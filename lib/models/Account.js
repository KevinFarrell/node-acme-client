const crypto = require('crypto');
const toBase64Url = require('../base64').toBase64Url;

class Account {
  constructor(values={}) {
    this.registrationUrl = values.registrationUrl;
    this.termsUrl = values.termsUrl;
    this.contact = values.contact;
    this.key = values.key;
  }

  getJWKDigest() {
    if(!this.key) {throw new Error('Missing key');}
    let jwk = new Buffer(JSON.stringify({
      // The order of these keys is important!
      e   : this.key.e,
      kty : this.key.kty,
      n   : this.key.n
    })).toString('utf8');
    return toBase64Url(crypto.createHash('sha256').update(jwk, 'utf8').digest());
  }
}

module.exports = Account;
