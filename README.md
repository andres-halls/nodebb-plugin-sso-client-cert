# NodeBB Client Certificate SSO

NodeBB Plugin that allows users to login/register via a client certificate.

## Limitations

* Requires modifying NodeBB code a bit in order to work (one or two lines) if using Node for TLS termination.

## Installation

1. Install plugin and its dependencies with NPM.

  ```
  npm install github:andres-liiver/nodebb-plugin-sso-client-cert
  cd node_modules/nodebb-plugin-sso-client-cert
  npm install
  ```
2. Configure TLS termination (choose A or B).

  **(A)** Configure NodeBB for TLS termination.
    * Edit config.json.
        * Change `url` to https (no port).
        * Add the following (edit paths accordingly):
        ```
        "port": 443,
        "ssl": {
          "key": "ssl/server.key",
          "cert": "ssl/server.crt",
          "ca": [
            "ssl/ca/CA1.crt",
            "ssl/ca/CA2.crt"
          ]
        }
        ```
        You can add more CA certs and they will be concatenated in order.
    * Edit src/webserver.js.
        * Add the following after `cert: fs.readFileSync(nconf.get('ssl').cert)` where the https server is created.
        
          `ca: nconf.get('ssl').ca.map(function(n) { return fs.readFileSync(n); })`
        
  **(B)** Configure Apache for TLS termination (if not using Node for it).
3. Start NodeBB: `./nodebb start`
4. Go to your Admin Control Panel (note that forum is accessed now by https and no port).
5. Activate the plugin under Plugins -> Install Plugins.
6. Set an icon (or text or something) for the login button by going to Appearance -> Custom HTML & CSS. Here's an example:

  ```CSS
  .icon-client-cert-auth:after {
    content: '';
    display: block;
    width: 80px;
    height: 80px;
    background-image: url('/images/idLogo.png');
    background-size: contain;
    background-repeat: no-repeat;
  }
  ```
7. Use the [NodeBB Custom Pages plugin] (https://github.com/psychobunny/nodebb-plugin-custom-pages) to create an error page for the route `/client-cert-auth-error`
8. Reload the forum and test the new authentication.
