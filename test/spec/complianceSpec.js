'use strict';

var helpers = require('../helpers');
var libsodium = require('libsodium-wrappers-sumo');
var libsodium_neon = require('../../lib');

var keypair_alice, keypair_bob, curve25519_secret_key_alice, curve25519_secret_key_bob, curve25519_public_key_bob;

describe('libsodium-neon', function() {
  it('assert_is_not_zeros', function() {
    expect(helpers.assert_is_not_zeros([0, 0, 0, 0, 0])).toBe(false);
    expect(helpers.assert_is_not_zeros([0, 0, 0, 230, 0])).toBe(true);
    expect(helpers.assert_is_not_zeros([8, 51, 1, 103, 99])).toBe(true);
    expect(helpers.assert_is_not_zeros(helpers.key_material)).toBe(true);
  });

  it('crypto_sign_keypair', function() {
    keypair_alice = libsodium.crypto_sign_keypair();
    expect(helpers.assert_is_not_zeros(keypair_alice.publicKey)).toBe(true);
    expect(helpers.assert_is_not_zeros(keypair_alice.privateKey)).toBe(true);
  });
});

describe('Compliance', function() {
  it('crypto_sign_keypair', function() {
    keypair_alice = libsodium.crypto_sign_keypair();
    keypair_bob = libsodium_neon.crypto_sign_keypair();

    expect(keypair_bob.publicKey.length).toBeGreaterThan(0);
    expect(keypair_alice.publicKey.length).toEqual(keypair_bob.publicKey.length);
    expect(keypair_alice.privateKey.length).toEqual(keypair_bob.privateKey.length);
  });

  it('crypto_auth_hmacsha256', function() {
    var auth = libsodium.crypto_auth_hmacsha256(helpers.message, helpers.key_material);
    var authNeon = libsodium_neon.crypto_auth_hmacsha256(helpers.message, helpers.key_material);
    expect(auth).toEqual(authNeon);
  });

  it('crypto_sign_detached', function() {
    var sign = libsodium.crypto_sign_detached(helpers.message, keypair_alice.privateKey);
    var signNeon = libsodium_neon.crypto_sign_detached(helpers.message, keypair_alice.privateKey);
    expect(sign).toEqual(signNeon);
  });

  it('crypto_sign_ed25519_sk_to_curve25519', function() {
    curve25519_secret_key_alice = libsodium.crypto_sign_ed25519_sk_to_curve25519(keypair_alice.privateKey);
    var curve25519_secret_key_alice_neon = libsodium.crypto_sign_ed25519_sk_to_curve25519(keypair_alice.privateKey);

    curve25519_secret_key_bob = libsodium_neon.crypto_sign_ed25519_sk_to_curve25519(keypair_bob.privateKey);
    var curve25519_secret_key_bob_neon = libsodium_neon.crypto_sign_ed25519_sk_to_curve25519(keypair_bob.privateKey);
    expect(curve25519_secret_key_alice).toEqual(curve25519_secret_key_alice_neon);
    expect(curve25519_secret_key_bob).toEqual(curve25519_secret_key_bob_neon);
  });

  it('crypto_sign_ed25519_pk_to_curve25519', function() {
    var curve25519_public_key_alice = libsodium.crypto_sign_ed25519_pk_to_curve25519(keypair_alice.publicKey);
    var curve25519_public_key_alice_neon = libsodium.crypto_sign_ed25519_pk_to_curve25519(keypair_alice.publicKey);

    curve25519_public_key_bob = libsodium_neon.crypto_sign_ed25519_pk_to_curve25519(keypair_bob.publicKey);
    var curve25519_public_key_bob_neon = libsodium_neon.crypto_sign_ed25519_pk_to_curve25519(keypair_bob.publicKey);

    expect(curve25519_public_key_alice).toEqual(curve25519_public_key_alice_neon);
    expect(curve25519_public_key_bob).toEqual(curve25519_public_key_bob_neon);
  });

  it('crypto_scalarmult', function() {
    var scalar = libsodium.crypto_scalarmult(curve25519_secret_key_alice, curve25519_public_key_bob);
    var scalar_neon = libsodium_neon.crypto_scalarmult(curve25519_secret_key_alice, curve25519_public_key_bob);
    expect(scalar).toEqual(scalar_neon);
  });
});
