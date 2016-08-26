
class Identifier {
  constructor(values={}) {
    //TODO: Validation
    this.type = values.type;
    this.value = values.value;
  }

  toJSON() {
    return {
      type: this.type,
      value: this.value
    };
  }
}

module.exports = Identifier;
