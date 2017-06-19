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

#![feature(test)]

#[macro_use]
extern crate neon;
extern crate libc;
extern crate rust_sodium;

#[cfg(test)]
extern crate test;

mod external;
mod internal;

#[cfg(test)]
mod benchmarks;

use internal::auth;
use internal::scalarmult;
use internal::sign;

pub fn init() -> bool {
  rust_sodium::init()
}

register_module!(m, {
  m.export("crypto_auth_hmacsha256", auth::crypto_auth_hmacsha256)?;
  m.export("crypto_scalarmult", scalarmult::crypto_scalarmult)?;
  m.export("crypto_sign_detached", sign::crypto_sign_detached)?;
  m.export("crypto_sign_ed25519_pk_to_curve25519", sign::crypto_sign_ed25519_pk_to_curve25519)?;
  m.export("crypto_sign_ed25519_sk_to_curve25519", sign::crypto_sign_ed25519_sk_to_curve25519)?;
  m.export("crypto_sign_keypair", sign::crypto_sign_keypair)?;
  m.export("crypto_sign_verify_detached", sign::crypto_sign_verify_detached)?;
  Ok(())
});
