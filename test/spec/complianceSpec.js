/*
 * Wire
 * Copyright (C) 2017 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

/* eslint no-magic-numbers: "off" */

const path = require('path');

const _sodium = require('libsodium-wrappers-sumo');
const helpers = require(path.resolve(__dirname, '..', 'helpers'));
const libsodium_neon = require(path.resolve(__dirname, '..', '..', 'lib'));

let curve25519_public_key_bob;
let curve25519_secret_key_alice;
let curve25519_secret_key_bob;
let keypair_alice;
let keypair_bob;

describe('libsodium-neon', () => {
  it('assert_is_not_zeros', () => {
    expect(helpers.assert_is_not_zeros([0, 0, 0, 0, 0])).toBe(false);
    expect(helpers.assert_is_not_zeros([0, 0, 0, 230, 0])).toBe(true);
    expect(helpers.assert_is_not_zeros([8, 51, 1, 103, 99])).toBe(true);
    expect(helpers.assert_is_not_zeros(helpers.key_material)).toBe(true);
  });

  it('crypto_sign_keypair', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    keypair_alice = libsodium.crypto_sign_keypair();
    expect(helpers.assert_is_not_zeros(keypair_alice.publicKey)).toBe(true);
    expect(helpers.assert_is_not_zeros(keypair_alice.privateKey)).toBe(true);
  });
});

describe('Compliance', () => {
  it('crypto_sign_keypair', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    keypair_alice = libsodium.crypto_sign_keypair();
    keypair_bob = libsodium_neon.crypto_sign_keypair();

    expect(keypair_bob.publicKey.length).toBeGreaterThan(0);
    expect(keypair_alice.publicKey.length).toEqual(keypair_bob.publicKey.length);
    expect(keypair_alice.privateKey.length).toEqual(keypair_bob.privateKey.length);
  });

  it('crypto_auth_hmacsha256', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    const auth = libsodium.crypto_auth_hmacsha256(helpers.message, helpers.key_material);
    const authNeon = libsodium_neon.crypto_auth_hmacsha256(helpers.message, helpers.key_material);
    expect(auth).toEqual(authNeon);
  });

  it('crypto_sign_detached', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    const sign = libsodium.crypto_sign_detached(helpers.message, keypair_alice.privateKey);
    const signNeon = libsodium_neon.crypto_sign_detached(helpers.message, keypair_alice.privateKey);
    expect(sign).toEqual(signNeon);
  });

  it('crypto_sign_ed25519_sk_to_curve25519', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    curve25519_secret_key_alice = libsodium.crypto_sign_ed25519_sk_to_curve25519(keypair_alice.privateKey);
    const curve25519_secret_key_alice_neon = libsodium.crypto_sign_ed25519_sk_to_curve25519(keypair_alice.privateKey);

    curve25519_secret_key_bob = libsodium_neon.crypto_sign_ed25519_sk_to_curve25519(keypair_bob.privateKey);
    const curve25519_secret_key_bob_neon = libsodium_neon.crypto_sign_ed25519_sk_to_curve25519(keypair_bob.privateKey);
    expect(curve25519_secret_key_alice).toEqual(curve25519_secret_key_alice_neon);
    expect(curve25519_secret_key_bob).toEqual(curve25519_secret_key_bob_neon);
  });

  it('crypto_sign_ed25519_pk_to_curve25519', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    const curve25519_public_key_alice = libsodium.crypto_sign_ed25519_pk_to_curve25519(keypair_alice.publicKey);
    const curve25519_public_key_alice_neon = libsodium.crypto_sign_ed25519_pk_to_curve25519(keypair_alice.publicKey);

    curve25519_public_key_bob = libsodium_neon.crypto_sign_ed25519_pk_to_curve25519(keypair_bob.publicKey);
    const curve25519_public_key_bob_neon = libsodium_neon.crypto_sign_ed25519_pk_to_curve25519(keypair_bob.publicKey);

    expect(curve25519_public_key_alice).toEqual(curve25519_public_key_alice_neon);
    expect(curve25519_public_key_bob).toEqual(curve25519_public_key_bob_neon);
  });

  it('crypto_scalarmult', async () => {
    await _sodium.ready;
    const libsodium = _sodium;

    const scalar = libsodium.crypto_scalarmult(curve25519_secret_key_alice, curve25519_public_key_bob);
    const scalar_neon = libsodium_neon.crypto_scalarmult(curve25519_secret_key_alice, curve25519_public_key_bob);
    expect(scalar).toEqual(scalar_neon);
  });
});
