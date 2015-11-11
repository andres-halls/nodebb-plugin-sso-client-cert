(function(module) {
  'use strict';

  var user = module.parent.require('./user'),
    meta = module.parent.require('./meta'),
    db = module.parent.require('../src/database'),
    passport = module.parent.require('passport'),
    passportClientCert = require('passport-client-cert').Strategy,
    nconf = module.parent.require('nconf'),
    async = module.parent.require('async'),
    winston = module.parent.require('winston');

  var constants = Object.freeze({
    'name': 'client-cert',
    'icon': 'icon-client-cert-auth'
  });

  var CA_CNs = ['ESTEID-SK 2007', 'ESTEID-SK 2011'];
  // TODO: make a settings page in the Admin CP to configure these
  // and success/failure URLs.

  var ClientCert = {};

  ClientCert.getStrategy = function(strategies, callback) {
    passport.use(constants.name, new passportClientCert({
        passReqToCallback: true,
        successReturnToOrRedirect: '/',
        failureRedirect: '/client-cert-auth-error'
    }, function(req, cert, done) {
      var issuer = cert.issuer;

      if (CA_CNs.indexOf(issuer.CN) === -1) {
        winston.error('[sso-client-cert] Client Certificate Issuer CN invalid: ' + issuer.CN);
        return done(null, false);
      }

      var subject = cert.subject;

      if (!subject) {
        winston.error('[sso-client-cert] Client Certificate Subject missing!');
        return done(null, false);
      } else if (!subject.CN) {
        winston.error('[sso-client-cert] Client Certificate CN missing!');
        return done(null, false);
      }

      if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
        // Save cert CN to the user
        user.setUserField(req.user.uid, 'certcn', subject.CN);
        db.setObjectField('certcn:uid', subject.CN, req.user.uid);
        return done(null, req.user);
      }

      var firstName = subject.GN.charAt(0).toUpperCase() + subject.GN.slice(1).toLowerCase();
      var lastName = subject.SN.charAt(0).toUpperCase() + subject.SN.slice(1).toLowerCase();
      var userName = firstName + ' ' + lastName;
      var email = cert.subjectaltname.split('email:')[1];

      ClientCert.login(subject.CN, userName, email, function(err, user) {
        if (err) {
          return done(err);
        }

        done(null, user);
      });
    }));

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