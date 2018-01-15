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

const path = require('path');
const sodiumneon = require(path.resolve(__dirname, '..', 'native'));

const obj_to_buffer = obj => {
  if (typeof Buffer.from === 'function') {
    return new Uint8Array(Buffer.from(obj));
  }
  return new Uint8Array(new Buffer(obj));
};

module.exports = {
  crypto_auth_BYTES: 32,
  crypto_auth_KEYBYTES: 32,
  crypto_auth_hmacsha256: (message, key) => {
    message = obj_to_buffer(message);
    key = obj_to_buffer(key);

    return new Uint8Array(sodiumneon.crypto_auth_hmacsha256(message, key));
  },
  crypto_auth_hmacsha256_BYTES: 32,
  crypto_auth_hmacsha256_KEYBYTES: 32,
  crypto_hash_BYTES: 64,
  crypto_scalarmult(secret_key, public_key) {
    secret_key = obj_to_buffer(secret_key);
    public_key = obj_to_buffer(public_key);

    return new Uint8Array(sodiumneon.crypto_scalarmult(secret_key, public_key));
  },
  crypto_scalarmult_BYTES: 32,
  crypto_scalarmult_SCALARBYTES: 32,
  crypto_sign_BYTES: 64,
  crypto_sign_PUBLICKEYBYTES: 32,
  crypto_sign_SECRETKEYBYTES: 64,
  crypto_sign_SEEDBYTES: 32,
  crypto_sign_detached: (message, secret_key) => {
    message = obj_to_buffer(message);
    secret_key = obj_to_buffer(secret_key);

    return new Uint8Array(sodiumneon.crypto_sign_detached(message, secret_key));
  },
  crypto_sign_ed25519_pk_to_curve25519: public_key => {
    public_key = obj_to_buffer(public_key);

    return new Uint8Array(sodiumneon.crypto_sign_ed25519_pk_to_curve25519(public_key));
  },
  crypto_sign_ed25519_sk_to_curve25519: secret_key => {
    secret_key = obj_to_buffer(secret_key);

    return new Uint8Array(sodiumneon.crypto_sign_ed25519_sk_to_curve25519(secret_key));
  },
  crypto_sign_keypair: () => {
    const key_pair = sodiumneon.crypto_sign_keypair();

    return {
      keyType: key_pair.key_type,
      privateKey: new Uint8Array(key_pair.private_key_buffer),
      publicKey: new Uint8Array(key_pair.public_key_buffer),
    };
  },
  crypto_sign_verify_detached: (signature, message, public_key) => {
    signature = obj_to_buffer(signature);
    message = obj_to_buffer(message);
    public_key = obj_to_buffer(public_key);

    return sodiumneon.crypto_sign_verify_detached(signature, message, public_key);
  },
};
