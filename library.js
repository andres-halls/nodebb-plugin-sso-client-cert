(function(module) {
  'use strict';

  var user = module.parent.require('./user'),
      meta = module.parent.require('./meta'),
      db = module.parent.require('../src/database'),
      passport = module.parent.require('passport'),
      passportClientCert = require('passport-client-cert').Strategy,
      nconf = module.parent.require('nconf'),
      async = module.parent.require('async'),
      winston = module.parent.require('winston'),
      fs = require('fs'),
      openssl = require('openssl-wrapper');

  var constants = Object.freeze({
    'name': 'client-cert',
    'icon': 'icon-client-cert-auth'
  });

  // TODO: make a settings page in the Admin CP to configure these
  // and success/failure URLs.
  const CA_CNS = ['ESTEID-SK 2007', 'ESTEID-SK 2011'];
  const CERTS_TEMP_FOLDER = 'certs/temp/';
  const OCSP_URL = 'http://ocsp.sk.ee';
  const OCSP_INFO = {
    'ESTEID-SK 2007': {
      CA_CERT_FILE: 'certs/ESTEID-SK_2007.crt',
      OCSP_SERVER_CERT_FILE: 'certs/ESTEID-SK_2007_OCSP_RESPONDER_2010.crt'
    },
    'ESTEID-SK 2011': {
      CA_CERT_FILE: 'certs/ESTEID-SK_2011.crt',
      OCSP_SERVER_CERT_FILE: 'certs/SK_OCSP_RESPONDER_2011.crt'
    }
  };

  var ClientCert = {};

  function verify(req, cert, done) {
    var subject = cert.subject ? cert.subject : {CN: undefined, GN: undefined, SN: undefined};
    var subjectCommonName = subject.CN ? subject.CN : req.headers.ssl_client_s_dn_cn;

    var issuer = cert.issuer ? cert.issuer : {CN: undefined};
    var issuerCommonName = issuer.CN ? issuer.CN : req.headers.ssl_client_i_dn_cn;

    if (!subject) {
      winston.error('[sso-client-cert] Client Certificate Subject missing!');
      return done(null, false);
    } else if (!subjectCommonName) {
      winston.error('[sso-client-cert] Client Certificate Subject CN missing!');
      return done(null, false);
    }

    if (CA_CNS.indexOf(issuerCommonName) === -1) {
      winston.error('[sso-client-cert] Client Certificate Issuer CN invalid: ' + issuerCommonName +
          '. Subject CN: ' + subjectCommonName);

      return done(null, false);
    }

    OCSPCheck(cert, subjectCommonName, issuerCommonName, done, function() {
      if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
        // Save cert CN to the user
        user.setUserField(req.user.uid, 'certcn', subjectCommonName);
        db.setObjectField('certcn:uid', subjectCommonName, req.user.uid);
        return done(null, req.user);
      }

      var subjectGivenName = subject.GN ? subject.GN : req.headers.ssl_client_s_dn_g;
      var subjectSurname = subject.SN ? subject.SN : req.headers.ssl_client_s_dn_s;
      var firstName = subjectGivenName.charAt(0).toUpperCase() + subjectGivenName.slice(1).toLowerCase();
      var lastName = subjectSurname.charAt(0).toUpperCase() + subjectSurname.slice(1).toLowerCase();
      var userName = firstName + ' ' + lastName;
      var email = "";

      if (cert.subjectaltname) {
        email = cert.subjectaltname.split('email:')[1];
      }

      ClientCert.login(subjectCommonName, userName, email, function(err, user) {
        if (err) {
          return done(err);
        }

        done(null, user);
      });
    });
  }

  function OCSPCheck(cert, subjectCommonName, issuerCommonName, done, callback) {
    var certFile = CERTS_TEMP_FOLDER + subjectCommonName + '.crt';

    fs.writeFile(certFile, cert, function(err) {
      if (err) return done(err);

      openssl.exec('ocsp', {
        url: OCSP_URL,
        issuer: OCSP_INFO[issuerCommonName].CA_CERT_FILE,
        VAfile: OCSP_INFO[issuerCommonName].OCSP_SERVER_CERT_FILE,
        cert: certFile
      }, function(err, buffer) {
        fs.unlink(certFile);

        if (err.indexOf & err.indexOf('Response verify OK') === -1) {
          return done(err);
        }

        var response = buffer.toString();

        if (response.indexOf('good') === -1) {
          winston.error('[sso-client-cert] Client Certificate OCSP check failed! CN: ' + subjectCommonName);
          return done(null, false);
        } else {
          return callback();
        }
      });
    });
  }

  ClientCert.getStrategy = function(strategies, callback) {
    passport.use(constants.name, new passportClientCert({
      passReqToCallback: true,
      successReturnToOrRedirect: '/',
      failureRedirect: '/client-cert-auth-error'
    }, verify));

    strategies.push({
      name: 'client-cert',
      url: '/auth/client-cert',
      callbackURL: '/',
      icon: constants.icon
    });

    callback(null, strategies);
  };

  ClientCert.getAssociation = function(data, callback) {
    user.getUserField(data.uid, 'certcn', function(err, CN) {
      if (err) {
        return callback(err, data);
      }

      if (CN) {
        data.associations.push({
          associated: true,
          name: constants.name,
          icon: constants.icon
        });
      } else {
        data.associations.push({
          associated: false,
          url: nconf.get('url') + '/auth/client-cert',
          name: constants.name,
          icon: constants.icon
        });
      }

      callback(null, data);
    })
  };

  ClientCert.login = function(CN, userName, email, callback) {
    ClientCert.getUidByCertCN(CN, function(err, uid) {
      if(err) {
        return callback(err);
      }

      if (uid !== null) {
        // Existing User
        callback(null, {
          uid: uid
        });
      } else {
        // New User
        var success = function(uid) {
          // Save cert CN to the user
          user.setUserField(uid, 'certcn', CN);
          db.setObjectField('certcn:uid', CN, uid);
          user.setUserField(uid, 'email:confirmed', 0); // TODO: Add option to configure in Admin CP

          callback(null, {
            uid: uid
          });
        };

        user.getUidByEmail(email, function(err, uid) {
          if(err) {
            return callback(err);
          }

          if (!uid) {
            user.create({username: userName, email: email}, function(err, uid) {
              if(err) {
                return callback(err);
              }

              success(uid);
            });
          } else {
            success(uid); // Existing account -- merge
          }
        });
      }
    });
  };

  ClientCert.getUidByCertCN = function(CN, callback) {
    db.getObjectField('certcn:uid', CN, function(err, uid) {
      if (err) {
        return callback(err);
      }
      callback(null, uid);
    });
  };

  ClientCert.deleteUserData = function(data, callback) {
    var uid = data.uid;

    async.waterfall([
      async.apply(user.getUserField, uid, 'certcn'),
      function(CNToDelete, next) {
        db.deleteObjectField('certcn:uid', CNToDelete, next);
      }
    ], function(err) {
      if (err) {
        winston.error('[sso-client-cert] Could not remove cert CN for uid ' + uid + '. Error: ' + err);
        return callback(err);
      }
      callback(null, uid);
    });
  };

  module.exports = ClientCert;
}(module));