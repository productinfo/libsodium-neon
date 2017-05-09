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

use internal::utils::*;
use neon::js::error::{JsError, Kind};
use neon::vm::{Call, JsResult, Lock};
use neon::js::binary::JsBuffer;
use rust_sodium::crypto::scalarmult as ecdh;
use rust_sodium::crypto::scalarmult::{GroupElement, Scalar};

pub fn crypto_scalarmult(mut call: Call) -> JsResult<JsBuffer> {
  let mut sk_buf = call.check_argument::<JsBuffer>(0)?;
  let mut pk_buf = call.check_argument::<JsBuffer>(1)?;

  let sk = sk_buf.grab(|contents| contents.as_slice());
  let pk = pk_buf.grab(|contents| contents.as_slice());

  let scalar = Scalar::from_slice(sk);
  if scalar.is_none() {
    return JsError::throw(Kind::TypeError, "unsupported input type for secret key");
  }

  let element = GroupElement::from_slice(pk);
  if element.is_none() {
    return JsError::throw(Kind::TypeError, "unsupported input type for public key");
  }

  let shared_secret = ecdh::scalarmult(&scalar.unwrap(), &element.unwrap())
            .map(|ge| ge.0);

  let mut result_buf = JsBuffer::new(call.scope, shared_secret.unwrap().len() as u32)?;
  buf_copy_from_slice(&shared_secret.unwrap(), &mut result_buf);

  Ok(result_buf)
}
