'use strict';

var libsodiumJS = require('libsodium-wrappers-sumo');
var libsodiumNeon = require('../../lib');

var message = 'Hello';
var keyMaterial = new Uint8Array([5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246]);
var keyPairAlice, keyPairBob, curve25519SecretKeyAlice, curve25519SecretKeyBob, curve25519PublicKeyAlice, curve25519PublicKeyBob;

describe('Compliance', function() {
  it('crypto_sign_keypair', function() {
    keyPairAlice = libsodiumJS.crypto_sign_keypair();
    keyPairBob = libsodiumNeon.crypto_sign_keypair();

    expect(keyPairBob.publicKey.length).toBeGreaterThan(0);
    expect(keyPairAlice.publicKey.length).toEqual(keyPairBob.publicKey.length);
    expect(keyPairAlice.privateKey.length).toEqual(keyPairBob.privateKey.length);
  });

  it('crypto_auth_hmacsha256', function() {
    var auth = libsodiumJS.crypto_auth_hmacsha256(message, keyMaterial);
    var authNeon = libsodiumNeon.crypto_auth_hmacsha256(message, keyMaterial);
    expect(auth).toEqual(authNeon);
  });

  it('crypto_sign_detached', function() {
    var sign = libsodiumJS.crypto_sign_detached(message, keyPairAlice.privateKey);
    var signNeon = libsodiumNeon.crypto_sign_detached(message, keyPairAlice.privateKey);
    expect(sign).toEqual(signNeon);
  });

  it('crypto_sign_ed25519_sk_to_curve25519', function() {
    curve25519SecretKeyAlice = libsodiumJS.crypto_sign_ed25519_sk_to_curve25519(keyPairAlice.privateKey);
    var curve25519SecretKeyAliceNeon = libsodiumJS.crypto_sign_ed25519_sk_to_curve25519(keyPairAlice.privateKey);

    curve25519SecretKeyBob = libsodiumNeon.crypto_sign_ed25519_sk_to_curve25519(keyPairBob.privateKey);
    var curve25519SecretKeyBobNeon = libsodiumNeon.crypto_sign_ed25519_sk_to_curve25519(keyPairBob.privateKey);
    expect(curve25519SecretKeyAlice).toEqual(curve25519SecretKeyAliceNeon);
    expect(curve25519SecretKeyBob).toEqual(curve25519SecretKeyBobNeon);
  });

  it('crypto_sign_ed25519_pk_to_curve25519', function() {
    curve25519PublicKeyAlice = libsodiumJS.crypto_sign_ed25519_pk_to_curve25519(keyPairAlice.publicKey);
    var curve25519PublicKeyAliceNeon = libsodiumJS.crypto_sign_ed25519_pk_to_curve25519(keyPairAlice.publicKey);

    curve25519PublicKeyBob = libsodiumNeon.crypto_sign_ed25519_pk_to_curve25519(keyPairBob.publicKey);
    var curve25519PublicKeyBobNeon = libsodiumNeon.crypto_sign_ed25519_pk_to_curve25519(keyPairBob.publicKey);

    expect(curve25519PublicKeyAlice).toEqual(curve25519PublicKeyAliceNeon);
    expect(curve25519PublicKeyBob).toEqual(curve25519PublicKeyBobNeon);
  });

  it('crypto_scalarmult', function() {
    var scalar = libsodiumJS.crypto_scalarmult(curve25519SecretKeyAlice, curve25519PublicKeyBob);
    var scalarNeon = libsodiumNeon.crypto_scalarmult(curve25519SecretKeyAlice, curve25519PublicKeyBob);
    expect(scalar).toEqual(scalarNeon);
  });
});
