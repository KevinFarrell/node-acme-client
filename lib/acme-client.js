const jwa = require('jwa');
const rsaPemToJwk = require('rsa-pem-to-jwk');
const request = require('request');
const toBase64Url = require('./base64').toBase64Url;

const Account = require('./models/Account');
const Authorization = require('./models/Authorization');
const Challenge = require('./models/Challenge');
const Certificate = require('./models/Certificate');
const Identifier = require('./models/Identifier');

/** ACME Client */
class ACMEClient {
  constructor(configuration={}) {
    /* Initialize */
    this._acmeDirectoryUrl = configuration.acmeDirectoryUrl;
    this._privateKey = new Buffer(configuration.privateKey);
    this._publicJWK = rsaPemToJwk(this._privateKey, 'public');

    this._nonces = [];
    this._registrationUrl = null;
    this._account = null;
  }


  getDirectory(cb) {
    if(this._directory) {return cb(null, this._directory);}
    this._get(this._acmeDirectoryUrl, null, (error, response) => {
      if(error) {return cb(error);}
      if(!(response && response.payload && Object.keys(response.payload).length)) {
        return cb(new Error('Invalid directory object returned from ACME directory'));
      }
      this._directory = response.payload;
      return cb(null, this._directory);
    });
  }

  newRegistration(email, cb) {
    this.getDirectory((error, directory) => {
      if(error) {return cb(error);}
      let payload = {resource: 'new-reg'};
      if(email) {
        payload.contact = [`mailto:${email}`];
      }
      this._post(directory['new-reg'], payload, null, (error, response) => {
        if(error) {return cb(error);}
        if(response.statusCode === 409 && 'location' in response.headers) {
          this._registrationUrl = response.headers.location;
          return cb(null, this._registrationUrl);
        }
        if(response.statusCode !== 201) {return cb(new Error(`Unexpected response code from new-reg: ${response.statusCode}`));}
        this._account = this._createAccountFromResponse(response);
        return cb(null, this._account);
      });
    });
  }

  getRegistration(cb) {
    if(this._account) {return cb(null, this._account);}
    this.updateRegistration(null, cb);
  }

  updateRegistration(payload, cb) {
    this._getRegistrationUrl((error, registrationUrl) => {
      if(error) {return cb(error);}
      payload = payload || {};
      payload.resource = 'reg';
      this._post(registrationUrl, payload, null, (error, response) => {
        if(error) {return cb(error);}
        if(![200, 202].includes(response.statusCode)) {return cb(new Error(`Unexpected response code from reg: ${response.statusCode}`));}
        this._account = this._createAccountFromResponse(response);
        return cb(null, this._account);
      });
    });
  }

  newAuthorization(identifier, cb) {
    if(!(identifier instanceof Identifier)) {return cb(new Error('identifier must be an Identifier'));}

    this.getDirectory((error, directory) => {
      if(error) {return cb(error);}
      let payload = {
        resource   : 'new-authz',
        identifier : identifier.toJSON()
      };
      this._post(directory['new-authz'], payload, null, (error, response) => {
        if(error) {return cb(error);}
        if(response.statusCode !== 201) {return cb(new Error(`Unexpected response code from new-authz: ${response.statusCode}`));}
        return cb(null, this._createAuthorizationFromResponse(response));
      });
    });
  }

  getAuthorization(uri, cb) {
    this._get(uri, null, (error, response) => {
      if(error) {return cb(error);}
      if(response.statusCode !== 200) {return cb(new Error(`Unexpected response code from auth: ${response.statusCode}`));}
      if(!response.headers.location) {
        response.headers.location = uri;
      }
      return cb(null, this._createAuthorizationFromResponse(response));
    });
  }

  acceptChallenge(challenge, cb) {
    if(!(challenge instanceof Challenge)) {return cb(new Error('identifier must be an Challenge'));}

    this.getRegistration((error, account) => {
      if(error) {return cb(error);}
      let payload = {
        resource         : 'challenge',
        keyAuthorization : challenge.buildKeyAuthorization(account)
      };
      this._post(challenge.uri, payload, null, (error, response) => {
        if(error) {return cb(error);}
        if(response.statusCode !== 202) {return cb(new Error(`Unexpected response code from challenge: ${response.statusCode}`));}
        return cb(null, new Challenge(response.payload));
      });
    });
  }

  getChallenge(uri, cb) {
    this._get(uri, null, (error, response) => {
      if(error) {return cb(error);}
      if(response.statusCode !== 200) {return cb(new Error(`Unexpected response code from challenge: ${response.statusCode}`));}
      return cb(null, new Challenge(response.payload));
    });
  }

  newCertificate(csr, notBefore, notAfter, cb) {
    if(!(csr instanceof Buffer)) {return cb(new Error('csr must be a Buffer containing a CSR in DER format'));}
    if(!(notBefore instanceof Date)) {return cb(new Error('notBefore must be a Date'));}
    if(!(notAfter instanceof Date)) {return cb(new Error('notAfter must be a Date'));}
    if(notAfter - notBefore <= 0) {return cb(new Error('notAfter must be later than notBefore'));}

    this.getDirectory((error, directory) => {
      if(error) {return cb(error);}
      let payload = {
        resource  : 'new-cert',
        csr       : csr.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
        notBefore : notBefore.toISOString(),
        notAfter  : notAfter.toISOString()
      };
      this._post(directory['new-cert'], payload, null, (error, response) => {
        if(error) {return cb(error);}
        if(response.statusCode !== 201) {return cb(new Error(`Unexpected response code from new-cert: ${response.statusCode}`));}
        return cb(null, this._createCertificateFromResponse(response));
      });
    });
  }

  getCertificate(uri, cb) {
    this._get(uri, null, (error, response) => {
      if(error) {return cb(error);}
      if(response.statusCode !== 200) {return cb(new Error(`Unexpected response code from cert: ${response.statusCode}`));}
      return cb(null, this._createCertificateFromResponse(response));
    });
  }


  _get(uri, options, cb) {
    this._request('GET', uri, null, options, cb);
  }

  _post(uri, payload, options, cb) {
    console.log(`POST Request Payload ${JSON.stringify(payload)}`);
    this._getNonce(uri, (error, nonce) => {
      if(error) {return cb(error);}
      this._request('POST', uri, this._buildJWT(payload, nonce), options, cb);
    });
  }

  _request(method, uri, payload, options, cb) {
    //TODO: Validation

    let requestOptions = {method, uri};
    if(payload) {
      requestOptions.body = payload;
      requestOptions.encoding = null;
      requestOptions.headers = {
        'Content-Type'   : 'application/jose',
        'Content-Length' : payload.length
      };
    }

    console.log(`${method}ing ${uri}`);
    request(requestOptions, (error, response, body) => {
      if(error) {return cb(error);}
      console.log(`Response Code: ${response.statusCode}`);
      console.log(`Response Headers: ${JSON.stringify(response.headers)}`);
      if(body) {
        if(response.headers['content-type'].match(/^application\/.*json$/)) {
          try {
            response.payload = JSON.parse(body.toString('utf8'));
          }
          catch(error) {
            return cb(error);
          }
        }
        else {
          response.payload = body;
        }
      }
      if('replay-nonce' in response.headers) {
        this._nonces.push(response.headers['replay-nonce']);
      }
      console.log(`Response Body: ${JSON.stringify(response.payload)}`);
      return cb(null, response);
    });
  }

  _buildJWT(payload, nonce) {
    let header = {
      typ   : 'JWT',
      alg   : 'RS256',
      nonce : nonce,
      jwk   : this._publicJWK
    };
    let base64Header = toBase64Url(JSON.stringify(header));
    let base64Payload = toBase64Url(JSON.stringify(payload));

    return JSON.stringify({
      protected : base64Header,
      payload   : base64Payload,
      signature : jwa(header.alg).sign(`${base64Header}.${base64Payload}`, this._privateKey)
    });
  }

  _getNonce(uri, cb) {
    if(this._nonces && this._nonces.length) {return cb(null, this._nonces.shift());}
    this._request('HEAD', uri, null, null, (error, response) => {
      if(error) {return cb(error);}
      if(!(response && 'replay-nonce' in response.headers)) {return cb(new Error('Unable to fetch nonce'));}
      return cb(null, response.headers['replay-nonce']);
    });
  }

  _getRegistrationUrl(cb) {
    if(this._registrationUrl) {return cb(null, this._registrationUrl);}
    return this.newRegistration(null, cb);
  }

  _createAuthorizationFromResponse(response) {
    let authorization = response.payload;
    authorization.uri = response.headers.location;
    if(authorization.challenges && authorization.challenges.length) {
      authorization.challenges = authorization.challenges.map(c => new Challenge(c));
    }
    return new Authorization(authorization);
  }

  _createAccountFromResponse(response) {
    let account = response.payload;
    account.uri = response.headers.location;
    if('link' in response.headers) {
      let termsMatch = response.headers.link.match(/(<)([^>]+)(>;rel="terms-of-service")/);
      if(termsMatch) {
        account.termsUrl = termsMatch[2];
      }
    }
    return new Account(account);
  }

  _createCertificateFromResponse(response) {
    return new Certificate({
      uri         : response.headers.location,
      certificate : response.payload
    });
  }
}

module.exports = ACMEClient;
