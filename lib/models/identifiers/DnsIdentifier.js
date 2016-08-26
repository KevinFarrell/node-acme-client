const Identifier = require('../Identifier');

class DnsIdentifier extends Identifier {
  constructor(values={}) {
    if(typeof values === 'string') {
      values = {
        type: 'dns',
        value: values
      };
    }
    else if(typeof values === 'object') {
      values.type = 'dns';
    }
    else {
      throw new Error('Invalid');
    }
    super(values);
  }
}

module.exports = DnsIdentifier;
