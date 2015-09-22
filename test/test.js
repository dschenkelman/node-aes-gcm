// Test module for node-aes-gcm
// Verifies against applicable test cases documented in:
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents
// /proposedmodes/gcm/gcm-revised-spec.pdf

var fs = require('fs');
var should = require('should');
var gcm = require('../build/Release/node_aes_gcm');


describe('node-aes-gcm', function () {
  var key, iv, plaintext, aad, ciphertext, auth_tag;
  var encrypted, decrypted, decryptedBadCiphertext,
      decryptedBadAad, decryptedBadAuthTag;
  var badCiphertext = new Buffer('Bad ciphertext'),
      badAad = new Buffer('Bad AAD'),
      badAuthTag = new Buffer('0000000000000000');

  function runEncryptDecryptTestCases(nist) {
    before(function () {
      encrypted = gcm.encrypt(key, iv, plaintext, aad);
      if (encrypted && encrypted.ciphertext && encrypted.auth_tag) {
        decrypted = gcm.decrypt(key, iv, encrypted.ciphertext,
                                aad, encrypted.auth_tag);
        decryptedBadCiphertext = gcm.decrypt(key, iv, badCiphertext,
                                aad, encrypted.auth_tag);
        decryptedBadAad = gcm.decrypt(key, iv, encrypted.ciphertext,
                                badAad, encrypted.auth_tag);
        decryptedBadAuthTag = gcm.decrypt(key, iv, encrypted.ciphertext,
                                aad, badAuthTag);
      } else {
        decrypted = null;
      }
    });

    if (nist) {
      it('should match the NIST ciphertext when encrypted', function () {
        encrypted.should.have.ownProperty('ciphertext');
        encrypted.ciphertext.should.be.a.Buffer;
        encrypted.ciphertext.equals(ciphertext).should.be.ok;
      });

      it('should match the NIST authentication tag when encrypted',
          function () {
        encrypted.should.have.ownProperty('auth_tag');
        encrypted.auth_tag.should.be.a.Buffer;
        encrypted.auth_tag.equals(auth_tag).should.be.ok;
      });
    }

    it('should decrypt back to the original plaintext', function () {
      decrypted.should.have.ownProperty('plaintext');
      decrypted.plaintext.should.be.a.Buffer;
      decrypted.plaintext.equals(plaintext).should.be.ok;
    });

    it('should report authentication ok when decrypted', function () {
      decrypted.should.have.ownProperty('auth_ok');
      decrypted.auth_ok.should.be.a.Boolean;
      decrypted.auth_ok.should.be.ok;
    });

    it('should fail authentication when decrypting bad ciphertext',
        function () {
      decryptedBadCiphertext.should.have.ownProperty('auth_ok');
      decryptedBadCiphertext.auth_ok.should.be.a.Boolean;
      decryptedBadCiphertext.auth_ok.should.not.be.ok;
    });

    it('should decrypt correctly even with bad AAD', function () {
      decryptedBadAad.should.have.ownProperty('plaintext');
      decryptedBadAad.plaintext.should.be.a.Buffer;
      decryptedBadAad.plaintext.equals(plaintext).should.be.ok;
    });

    it('should fail authentication when decrypting bad AAD',
        function () {
      decryptedBadAad.should.have.ownProperty('auth_ok');
      decryptedBadAad.auth_ok.should.be.a.Boolean;
      decryptedBadAad.auth_ok.should.not.be.ok;
    });

    it('should decrypt correctly even with bad authentication tag',
        function () {
      decryptedBadAuthTag.should.have.ownProperty('plaintext');
      decryptedBadAuthTag.plaintext.should.be.a.Buffer;
      decryptedBadAuthTag.plaintext.equals(plaintext).should.be.ok;
    });

    it('should fail authentication with a bad authentication tag',
        function () {
      decryptedBadAuthTag.should.have.ownProperty('auth_ok');
      decryptedBadAuthTag.auth_ok.should.be.a.Boolean;
      decryptedBadAuthTag.auth_ok.should.not.be.ok;
    });
  }

  describe('NIST Test Case 1', function () {
    before(function () {
      key = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
      iv = new Buffer('000000000000000000000000', 'hex');
      plaintext = new Buffer([]);
      aad = new Buffer([]);
      ciphertext = new Buffer([]);
      auth_tag = new Buffer('530f8afbc74536b9a963b4f1c4cb738b', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('NIST Test Case 2', function () {
    before(function () {
      key = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
      iv = new Buffer('000000000000000000000000', 'hex');
      plaintext = new Buffer('00000000000000000000000000000000', 'hex');
      aad = new Buffer([]);
      ciphertext = new Buffer('cea7403d4d606b6e074ec5d3baf39d18', 'hex');
      auth_tag = new Buffer('d0d1c8a799996bf0265b98b5d48ab919', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('NIST Test Case 3', function () {
    before(function () {
      key = new Buffer('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex');
      iv = new Buffer('cafebabefacedbaddecaf888', 'hex');
      plaintext = new Buffer('d9313225f88406e5a55909c5aff5269a' +
                             '86a7a9531534f7da2e4c303d8a318a72' +
                             '1c3c0c95956809532fcf0e2449a6b525' +
                             'b16aedf5aa0de657ba637b391aafd255', 'hex');
      aad = new Buffer([]);
      ciphertext = new Buffer('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad', 'hex');
      auth_tag = new Buffer('b094dac5d93471bdec1a502270e3cc6c', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('NIST Test Case 4', function () {
    before(function () {
      key = new Buffer('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex');
      iv = new Buffer('cafebabefacedbaddecaf888', 'hex');
      plaintext = new Buffer('d9313225f88406e5a55909c5aff5269a' +
                             '86a7a9531534f7da2e4c303d8a318a72' +
                             '1c3c0c95956809532fcf0e2449a6b525' +
                             'b16aedf5aa0de657ba637b39', 'hex');
      aad = new Buffer('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex');
      ciphertext = new Buffer('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662', 'hex');
      auth_tag = new Buffer('76fc6ece0f4e1768cddf8853bb2d551b', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('Its own binary module', function () {
    before(function (done) {
      key = new Buffer('88888888888888888888888888888888');
      iv = new Buffer('666666666666');
      fs.readFile('./build/Release/node_aes_gcm.node', function (err, data) {
        if (err) throw err;
        plaintext = data;
        done();
      });
      aad = new Buffer([]);
      ciphertext = null;
      auth_tag = null;
    });

    runEncryptDecryptTestCases(false);
  });
});
