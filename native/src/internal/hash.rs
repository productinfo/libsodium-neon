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
use neon::js::binary::JsBuffer;
use neon::vm::{Call, JsResult, Lock};
use sodiumoxide::crypto::hash::sha256;

pub fn crypto_hash_sha256(mut call: Call) -> JsResult<JsBuffer> {
  let mut message_buf = call.check_argument::<JsBuffer>(0)?;

  let message = message_buf.grab(|contents| contents.as_slice());
  let hash = sha256::hash(message);

  let mut result_buf = JsBuffer::new(call.scope, hash.as_ref().len() as u32)?;
  buf_copy_from_slice(hash.as_ref(), &mut result_buf);

  Ok(result_buf)
}
