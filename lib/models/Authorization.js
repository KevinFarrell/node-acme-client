
class Authorization {
  constructor(values={}) {
    this.uri = values.uri;
    this.identifier = values.identifier;
    this.status = values.status;
    this.expires = values.expires;
    this.challenges = values.challenges;
    this.combinations = values.combinations;
  }
}

module.exports = Authorization;
