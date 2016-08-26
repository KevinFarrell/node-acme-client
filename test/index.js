const assert = require('chai').assert;
const ACMEClient = require('../lib/acme-client');
const DnsIdentifier = require('../lib/models/identifiers/DnsIdentifier');

const forge = require('node-forge');

const validACMEClientConfiguration = {
  acmeDirectoryUrl: 'https://acme-staging.api.letsencrypt.org/directory',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n'
};

describe('ACMEClient Instantiation', function() {
  describe('with no configuration', function() {
    it('should error');
  });

  describe('with valid configuration', function() {
    it('should return an ACMEClient instance', function() {
      let acmeClient = new ACMEClient(validACMEClientConfiguration);
      assert(acmeClient instanceof ACMEClient, 'acmeClient is not an ACMEClient instance');
      assert(typeof acmeClient._publicJWK === 'object');
    });
  });
});

describe('ACMEClient Instance Methods', function() {
  let acmeClient;
  before(function() {
    acmeClient = new ACMEClient(validACMEClientConfiguration);
  });

  describe('#getDirectory', function() {
    it('fetches ACME resource directory', function(done) {
      acmeClient.getDirectory(function(error, directory) {
        if(error) {return done(error);}
        assert(typeof directory === 'object', 'directory is not an object');
        return done();
      });
    });
  });

  describe('#newRegistration', function() {
    it('creates a new account on the ACME server', function(done) {
      acmeClient.newRegistration('test@example.com', function(error, registration) {
        if(error) {return done(error);}
        return done();
      });
    });
  });

  describe('#getRegistration', function() {
    it('fetches the account from the ACME server', function(done) {
      acmeClient.getRegistration(function(error, account) {
        if(error) {return done(error);}
        return done();
      });
    });
  });

  describe('#updateRegistration', function() {
    it('agrees to terms of service', function(done) {
      acmeClient.getRegistration(function(error, account) {
        if(error) {return done(error);}
        acmeClient.updateRegistration({agreement: acmeClient._termsURL}, function(error, account) {
          if(error) {return done(error);}
          return done();
        });
      });
    });
  });

  describe('#newAuthorization', function() {
    it('creates a new identifier authorization', function(done) {
      acmeClient.newAuthorization(new DnsIdentifier('foo.example.org'), function(error, authorization) {
        if(error) {return done(error);}
        let challenge = authorization.challenges.find(function(c) {return c.type === 'http-01';});
        if(!challenge) {return done(new Error('could not find http-01 challenge'));}
        acmeClient.getRegistration(function(error, account) {
          if(error) {return cb(error);}
          console.log(`Challenge Key Authorization: ${challenge.buildKeyAuthorization(account)}`);
          acmeClient.acceptChallenge(challenge, function(error, challenge) {
            if(error) {return done(error);}
            return done();
          });
        });
      });
    });
  });

  // describe('#newCertificate', function() {
  //   it('not sure yet', function(done) {
  //     let csr = generateCSR('foo.example.org');
  //     let notBefore = new Date();
  //     let notAfter = (new Date((+new Date()) + 1000 * 60 * 60 * 24 * 90)); // 90 days
  //     acmeClient.newCertificate(csr, notBefore, notAfter, function (error, certificate) {
  //       if(error) {return done(error);}
  //       return done();
  //     }.bind(this));
  //   });
  // });
});

function generateCSR(domain) {
  let keyPair = forge.pki.rsa.generateKeyPair(2048);
  let csr = forge.pki.createCertificationRequest();

  csr.publicKey = keyPair.publicKey;
  csr.setSubject([{name: 'commonName', value: domain}]);

  csr.sign(keyPair.privateKey, forge.md.sha256.create());
  return new Buffer(forge.util.bytesToHex(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr))), 'hex');
}
