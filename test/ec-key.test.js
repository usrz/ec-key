'use strict';

const ECKey = require('../src/ec-key');
const expect = require('chai').expect;
const fs = require('fs');

describe('EC Key', function() {

  var re = /-+BEGIN .* KEY-+([\s\S]+)-+END .* KEY-+/m;
  var names = [ 'prime256v1', 'secp384r1', 'secp521r1', 'secp256k1' ];
  var curves = {};

  before(function() {
    for (var i = 0; i < names.length; i ++) (function(name) {
      curves[name] = {
        // PEM FILES
        pkcs8: fs.readFileSync('./test/support/' + name + '.priv-pkcs8.pem', 'utf8'),
        priv: fs.readFileSync('./test/support/' + name + '.priv-openssl.pem', 'utf8'),
        pub: fs.readFileSync('./test/support/' + name + '.pub.pem', 'utf8'),
        // JWK FILES
        privJwk: JSON.parse(fs.readFileSync('./test/support/' + name + '.priv.json', 'utf8')),
        pubJwk: JSON.parse(fs.readFileSync('./test/support/' + name + '.pub.json', 'utf8'))
      };
    })(names[i]);
  });

  for (var i = 0; i < names.length; i ++) (function(name) {

    describe('Curve ' + name, function() {

      function testPublicKey(curve, key, name) {
        // Curve name
        expect(key.curve, "curve name").to.equal(name);

        // JWK representation
        expect(key.toJSON(), "jwk").to.eql(curve.pubJwk);

        // Buffer: spki
        expect(key.toBuffer('spki').toString('base64'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, ''));

        // Strings: spki normal and url safe
        expect(key.toString('spki'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, ''));
      }

      function testPrivateKey(curve, key, name) {
        // Curve name
        expect(key.curve, "curve name").to.equal(name);

        // JWK representation
        expect(key.toJSON(), "jwk").to.eql(curve.privJwk);

        // Buffers: pkcs8, openssl and spki (public)
        var pkcs8b64 = curve.pkcs8.match(re)[1].replace(/[\s-]/g, '')
        expect(key.toBuffer('pkcs8').toString('base64'))
          .to.equal(pkcs8b64);
        expect(key.toBuffer('rfc5915').toString('base64'))
          .to.equal(curve.priv.match(re)[1].replace(/[\s-]/g, ''));

        // Strings: pem, rfc5951 (openssl)
        expect(key.toString('pem')).to.equal(curve.pkcs8);
        expect(key.toString('rfc5915')).to.equal(curve.priv);

        // Strings: pkcs8 and spki (public) normal and url safe
        expect(key.toString('pkcs8'))
          .to.equal(curve.pkcs8.match(re)[1].replace(/[\s-]/g, ''));

        // Conversion to public key and test
        testPublicKey(curve, key.asPublicECKey(), name);
      }

      /* Run the tests per each source file */

      it('should parse a OpenSSL PEM private key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.priv);
        testPrivateKey(curve, key, name);
      });

      it('should parse a PKCS8 private key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.pkcs8);
        testPrivateKey(curve, key, name);
      });

      it('should parse a JWK private key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.privJwk);
        testPrivateKey(curve, key, name);
      });

      it('should parse a SPKI public key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.pub);
        testPublicKey(curve, key, name);
      });

      it('should parse a JWK public key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.pubJwk);
        testPublicKey(curve, key, name);
      });

    });
  })(names[i]);

  describe('Others', function() {

    it('should create a key with an OpenSSL curve name', function() {
      var key = ECKey.createECKey('secp521r1');
      expect(key.curve).to.equal('secp521r1');
      expect(key.d).to.be.instanceof(Buffer);
      expect(key.x).to.be.instanceof(Buffer);
      expect(key.y).to.be.instanceof(Buffer);
      expect(key.d.length).to.be.lt(67); // might be 65, 64, ...
      expect(key.x.length).to.be.equal(66);
      expect(key.y.length).to.be.equal(66);
    });

    it('should create a key with a JWK/NIST curve name', function() {
      var key = ECKey.createECKey('P-256');
      expect(key.curve).to.equal('prime256v1');
      expect(key.d).to.be.instanceof(Buffer);
      expect(key.x).to.be.instanceof(Buffer);
      expect(key.y).to.be.instanceof(Buffer);
      expect(key.d.length).to.be.lt(33);
      expect(key.x.length).to.be.equal(32);
      expect(key.y.length).to.be.equal(32);
    });

    it('should not create a key with an unknown curve name', function() {
      expect(function() { ECKey.createECKey('gonzo') }).to.throw('Invalid/unknown curve "gonzo"');
    });

    it('should create a couple of ECDH and negotiate a secret from existing keys', function() {
      var key1 = new ECKey(fs.readFileSync('./test/support/ecdh1.pem', 'utf8'));
      var key2 = new ECKey(fs.readFileSync('./test/support/ecdh1.pem', 'utf8'));
      var ecdh1 = key1.createECDH();
      var ecdh2 = key2.createECDH();
      // Use code points (we test keys below)
      var secret1 = ecdh1.computeSecret(key2.publicCodePoint);
      var secret2 = ecdh2.computeSecret(key1.publicCodePoint);
      // HEX to display errors in a sane way
      expect(secret1.toString('hex')).to.equal('620dee6f38472543ff87459fa37bc8cf9c04337aff5652327fe0ddfac88c715a');
      expect(secret2.toString('hex')).to.equal('620dee6f38472543ff87459fa37bc8cf9c04337aff5652327fe0ddfac88c715a');
    });

    it('should create a couple of ECDH and negotiate a secret from random keys', function() {
      var key1 = new ECKey.createECKey('P-521');
      var key2 = new ECKey.createECKey('P-521');
      var ecdh1 = key1.createECDH();
      var ecdh2 = key2.createECDH();
      // Use keys (we test code points above)
      var secret1 = ecdh1.computeSecret(key2);
      var secret2 = ecdh2.computeSecret(key1);
      // HEX to display errors in a sane way
      expect(secret1.toString('hex')).to.eql(secret2.toString('hex'));
      expect(secret1.length).to.equal(66);
    });

    it('should sign and verify a simple message', function() {
      var key = new ECKey.createECKey('P-521');
      var pub = key.asPublicECKey();

      var sign = key.createSign('SHA512');
      sign.write('The quick brown fox jumped over the lazy dog.', 'utf8');
      sign.end();

      var signature = sign.sign('base64');

      var verify1 = key.createVerify('SHA512');
      verify1.write('The quick brown fox jumped over the lazy dog.', 'utf8');
      verify1.end();

      expect(verify1.verify(signature, 'base64')).to.be.true;

      var verify2 = pub.createVerify('SHA512');
      verify2.write('The quick brown fox jumped over the lazy dog.', 'utf8');
      verify2.end();

      expect(verify2.verify(signature, 'base64')).to.be.true;

      var xverify1 = key.createVerify('SHA512');
      xverify1.write('The quick brown fox DID NOT jump over the lazy dog.', 'utf8');
      xverify1.end();

      expect(xverify1.verify(signature, 'base64')).to.be.false;

      var xverify2 = pub.createVerify('SHA512');
      xverify2.write('The quick brown fox DID NOT jump over the lazy dog.', 'utf8');
      xverify2.end();

      expect(xverify2.verify(signature, 'base64')).to.be.false;
    });

  });
});
