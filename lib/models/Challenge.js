
class Challenge {
  constructor(values={}) {
    this.type = values.type;
    this.uri = values.uri;
    this.status = values.status;
    this.token = values.token;
    this.keyAuthorization = values.keyAuthorization;
  }

  buildKeyAuthorization(account) {
    //TODO: Validation
    if(!this.keyAuthorization) {
      this.keyAuthorization = `${this.token}.${account.getJWKDigest()}`;
    }
    return this.keyAuthorization;
  }
}

module.exports = Challenge;
