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

'use strict';

var sodiumneon = require('../native');

var objToBuffer = function(obj) {
  if (typeof Buffer.from === 'function') {
    return new Uint8Array(Buffer.from(obj));
  } else {
    return new Uint8Array(new Buffer(obj));
  }
};

module.exports = {
  crypto_auth_BYTES: 32,
  crypto_auth_hmacsha256: function(message, key) {
    message = objToBuffer(message);
    key = objToBuffer(key);

    return new Uint8Array(sodiumneon.crypto_auth_hmacsha256(message, key));
  },
  crypto_auth_hmacsha256_BYTES: 32,
  crypto_auth_hmacsha256_KEYBYTES: 32,
  crypto_auth_KEYBYTES: 32,
  crypto_hash_BYTES: 64,
  crypto_scalarmult (secretKey, publicKey) {
    secretKey = objToBuffer(secretKey);
    publicKey = objToBuffer(publicKey);

    return new Uint8Array(sodiumneon.crypto_scalarmult(secretKey, publicKey));
  },
  crypto_scalarmult_BYTES: 32,
  crypto_scalarmult_SCALARBYTES: 32,
  crypto_sign_BYTES: 64,
  crypto_sign_detached: function(message, secretKey) {
    message = objToBuffer(message);
    secretKey = objToBuffer(secretKey);

    return new Uint8Array(sodiumneon.crypto_sign_detached(message, secretKey));
  },
  crypto_sign_ed25519_pk_to_curve25519: function(publicKey) {
    publicKey = objToBuffer(publicKey);

    return new Uint8Array(sodiumneon.crypto_sign_ed25519_pk_to_curve25519(publicKey));
  },
  crypto_sign_ed25519_sk_to_curve25519: function(secretKey) {
    secretKey = objToBuffer(secretKey);

    return new Uint8Array(sodiumneon.crypto_sign_ed25519_sk_to_curve25519(secretKey));
  },
  crypto_sign_keypair: function() {
    var keyPair = sodiumneon.crypto_sign_keypair();

    return {
      publicKey: new Uint8Array(keyPair.publicKeyBuffer),
      privateKey: new Uint8Array(keyPair.privateKeyBuffer),
      keyType: keyPair.keyType
    };
  },
  crypto_sign_PUBLICKEYBYTES: 32,
  crypto_sign_SECRETKEYBYTES: 64,
  crypto_sign_SEEDBYTES: 32,
  crypto_sign_verify_detached: function(signature, message, publicKey) {
    signature = objToBuffer(signature);
    message = objToBuffer(message);
    publicKey = objToBuffer(publicKey);

    return sodiumneon.crypto_sign_verify_detached(signature, message, publicKey);
  }
};
