//
// Wire
// Copyright (C) 2017 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//

use external;
use internal::utils::*;
use neon::js::{JsBoolean, JsString, JsObject, Object};
use neon::js::binary::JsBuffer;
use neon::js::error::{JsError, Kind};
use neon::vm::{Call, JsResult, Lock};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::SecretKey;

pub fn crypto_sign_detached(mut call: Call) -> JsResult<JsBuffer> {
  let mut message_buf = call.check_argument::<JsBuffer>(0)?;
  let mut sk_buf = call.check_argument::<JsBuffer>(1)?;

  let message = message_buf.grab(|contents| contents.as_slice());
  let sk = sk_buf.grab(|contents| contents.as_slice());
  let result = sign::sign_detached(message, &SecretKey::from_slice(sk).unwrap());

  let mut result_buf = JsBuffer::new(call.scope, result.as_ref().len() as u32)?;
  buf_copy_from_slice(result.as_ref(), &mut result_buf);

  Ok(result_buf)
}

pub fn crypto_sign_ed25519_pk_to_curve25519(mut call: Call) -> JsResult<JsBuffer> {
  let mut pk_buf = call.check_argument::<JsBuffer>(0)?;

  let pk = pk_buf.grab(|contents| contents.as_slice());

  unsafe {
    let curve25519_pk = &mut [0u8; 32];
    if external::crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.as_mut_ptr(), pk.as_ptr()) == 0 {

      let mut result_buf = JsBuffer::new(call.scope, 32)?;
      buf_copy_from_slice(curve25519_pk.as_ref(), &mut result_buf);

      Ok(result_buf)
    } else {
      JsError::throw(Kind::Error, "crypto_sign_ed25519_pk_to_curve25519() failed!")
    }
  }
}

pub fn crypto_sign_ed25519_sk_to_curve25519(mut call: Call) -> JsResult<JsBuffer> {
  let mut sk_buf = call.check_argument::<JsBuffer>(0)?;
  let sk = sk_buf.grab(|contents| contents.as_slice());

  unsafe {
    let curve25519_sk = &mut [0u8; 32];
    if external::crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.as_mut_ptr(), sk.as_ptr()) == 0 {

      let mut result_buf = JsBuffer::new(call.scope, 32)?;
      buf_copy_from_slice(curve25519_sk.as_ref(), &mut result_buf);

      Ok(result_buf)
    } else {
      JsError::throw(Kind::Error, "crypto_sign_ed25519_sk_to_curve25519() failed!")
    }
  }
}

pub fn crypto_sign_keypair(call: Call) -> JsResult<JsObject> {
  let scope = call.scope;
  let (kp_public, kp_secret) = sign::gen_keypair();

  let mut kp_public_buf = JsBuffer::new(scope, kp_public.0.as_ref().len() as u32)?;
  buf_copy_from_slice(&kp_public.0, &mut kp_public_buf);

  let mut kp_secret_buf = JsBuffer::new(scope, kp_secret.0.as_ref().len() as u32)?;
  buf_copy_from_slice(&kp_secret.0, &mut kp_secret_buf);

  let js_object = JsObject::new(scope);
  js_object.set("keyType", JsString::new(scope, "ed25519").unwrap())?;
  js_object.set("publicKeyBuffer", kp_public_buf)?;
  js_object.set("privateKeyBuffer", kp_secret_buf)?;

  Ok(js_object)
}

pub fn crypto_sign_verify_detached(mut call: Call) -> JsResult<JsBoolean> {
  let mut sig_buf = call.check_argument::<JsBuffer>(0)?;
  let mut message_buf = call.check_argument::<JsBuffer>(1)?;
  let mut pk_buf = call.check_argument::<JsBuffer>(2)?;

  let sig = sig_buf.grab(|contents| contents.as_slice());
  let message = message_buf.grab(|contents| contents.as_slice());

  let pk = pk_buf.grab(|contents| contents.as_slice());

  if pk.is_empty() {
    return JsError::throw(Kind::TypeError, "unsupported input type for secret key");
  }

  let result = sign::verify_detached(&sign::Signature::from_slice(sig).unwrap(), message, &sign::PublicKey::from_slice(pk).unwrap());

  Ok(JsBoolean::new(call.scope, result))
}
