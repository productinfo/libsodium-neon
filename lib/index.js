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

const os = require('os');
let sodiumneon;

switch(os.type()) {
  case 'Darwin':
    sodiumneon = require('../dist/macos/x64');
    break;
  case 'Linux':
    sodiumneon = require('../dist/linux/x64');
    break;
  default:
    throw new Error(`Your operating system (${os.type()}) is not supported.`);
}

const strToUint8Array = (obj) => {
  if (obj instanceof Uint8Array) {
    return obj;
  } else if (typeof obj === 'string') {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder('utf-8').encode(obj);
    }
    obj = unescape(encodeURIComponent(obj));

    const arr = new Uint8Array(obj.length);
    for (let i = 0; i < obj.length; i++) {
      arr[i] = obj.charCodeAt(i);
    }
    return arr;
  }
};

module.exports = {
  crypto_auth_BYTES: 32,
  crypto_auth_hmacsha256 (message, key) {
    message = strToUint8Array(message);
    key = strToUint8Array(key);

    return Uint8Array.from(sodiumneon.crypto_auth_hmacsha256(message, key));
  },
  crypto_auth_hmacsha256_BYTES: 32,
  crypto_auth_hmacsha256_KEYBYTES: 32,
  crypto_auth_hmacsha256_verify (tag, message, key) {
    tag = strToUint8Array(tag);
    message = strToUint8Array(message);
    key = strToUint8Array(key);

    return sodiumneon.crypto_auth_hmacsha256_verify(tag, message, key);
  },
  crypto_auth_KEYBYTES: 32,
  crypto_hash_BYTES: 64,
  crypto_hash_sha256 (message) {
    message = strToUint8Array(message);

    return Uint8Array.from(sodiumneon.crypto_hash_sha256(message));
  },
  crypto_scalarmult (secretKey, publicKey) {
    secretKey = strToUint8Array(secretKey);
    publicKey = strToUint8Array(publicKey);

    return Uint8Array.from(sodiumneon.crypto_scalarmult(secretKey, publicKey));
  },
  crypto_scalarmult_BYTES: 32,
  crypto_scalarmult_SCALARBYTES: 32,
  crypto_sign_BYTES: 64,
  crypto_sign_detached (message, secretKey) {
    message = strToUint8Array(message);
    secretKey = strToUint8Array(secretKey);

    return Uint8Array.from(sodiumneon.crypto_sign_detached(message, secretKey));
  },
  crypto_sign_ed25519_pk_to_curve25519 (publicKey) {
    publicKey = strToUint8Array(publicKey);

    return Uint8Array.from(sodiumneon.crypto_sign_ed25519_pk_to_curve25519(publicKey));
  },
  crypto_sign_ed25519_sk_to_curve25519 (secretKey) {
    secretKey = strToUint8Array(secretKey);

    return Uint8Array.from(sodiumneon.crypto_sign_ed25519_sk_to_curve25519(secretKey));
  },
  crypto_sign_keypair () {
    const { publicKeyBuffer, privateKeyBuffer, keyType } = sodiumneon.crypto_sign_keypair();

    return {
      publicKey: Uint8Array.from(publicKeyBuffer),
      privateKey: Uint8Array.from(privateKeyBuffer),
      keyType
    };
  },
  crypto_sign_PUBLICKEYBYTES: 32,
  crypto_sign_SECRETKEYBYTES: 64,
  crypto_sign_SEEDBYTES: 32,
  crypto_sign_verify_detached (signature, message, publicKey) {
    signature = strToUint8Array(signature);
    message = strToUint8Array(message);
    publicKey = strToUint8Array(publicKey);

    return sodiumneon.crypto_sign_verify_detached(signature, message, publicKey);
  },
  crypto_stream_chacha20_KEYBYTES: 32,
  crypto_stream_chacha20_NONCEBYTES: 8,
  crypto_stream_chacha20_xor (message, nonce, key, outputFormat) {
    message = strToUint8Array(message);
    nonce = strToUint8Array(nonce);
    key = strToUint8Array(key);

    const stream = sodiumneon.crypto_stream_chacha20_xor(message, nonce, key);

    if (outputFormat === 'uint8array') {
      return Uint8Array.from(stream);
    }
    return stream;
  }
};
