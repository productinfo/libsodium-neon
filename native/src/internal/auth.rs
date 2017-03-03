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
use neon::js::JsBoolean;
use neon::js::error::{JsError, Kind};
use neon::js::binary::JsBuffer;
use neon::vm::{Call, JsResult, Lock};
use sodiumoxide::crypto::auth::hmacsha256 as mac;
use sodiumoxide::crypto::auth::hmacsha256::{Key, Tag};

pub fn crypto_auth_hmacsha256(mut call: Call) -> JsResult<JsBuffer> {
  let mut message_buf = call.check_argument::<JsBuffer>(0)?;
  let mut key_buf = call.check_argument::<JsBuffer>(1)?;

  let message = message_buf.grab(|contents| contents.as_slice());
  let key = key_buf.grab(|contents| contents.as_slice());
  if key.is_empty() {
    return JsError::throw(Kind::TypeError, "unsupported input type for key");
  }

  let authenticator = mac::authenticate(message, &mac::Key::from_slice(key).unwrap());

  let mut result_buf = JsBuffer::new(call.scope, authenticator.as_ref().len() as u32)?;
  buf_copy_from_slice(authenticator.as_ref(), &mut result_buf);

  Ok(result_buf)
}

pub fn crypto_auth_hmacsha256_verify(mut call: Call) -> JsResult<JsBoolean> {
  let mut tag_buf = call.check_argument::<JsBuffer>(0)?;
  let mut message_buf = call.check_argument::<JsBuffer>(1)?;
  let mut key_buf = call.check_argument::<JsBuffer>(2)?;

  let tag = tag_buf.grab(|contents| contents.as_slice());
  let message = message_buf.grab(|contents| contents.as_slice());
  let key = key_buf.grab(|contents| contents.as_slice());

  let result = mac::verify(&Tag::from_slice(tag).unwrap(), message, &Key::from_slice(key).unwrap());

  Ok(JsBoolean::new(call.scope, result))
}
