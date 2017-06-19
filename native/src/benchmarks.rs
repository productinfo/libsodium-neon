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

use test::Bencher;
use rust_sodium;
use rust_sodium::crypto::auth::hmacsha256 as mac;
use rust_sodium::crypto::scalarmult as ecdh;
use rust_sodium::crypto::sign;
use external;

pub fn from_ed25519_pk(k: &sign::PublicKey) -> Result<[u8; ecdh::GROUPELEMENTBYTES], ()> {
    let mut ep = [0u8; ecdh::GROUPELEMENTBYTES];
    unsafe {
        if external::crypto_sign_ed25519_pk_to_curve25519(ep.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
            Ok(ep)
        } else {
            Err(())
        }
    }
}

pub fn from_ed25519_sk(k: &sign::SecretKey) -> Result<[u8; ecdh::SCALARBYTES], ()> {
    let mut es = [0u8; ecdh::SCALARBYTES];
    unsafe {
        if external::crypto_sign_ed25519_sk_to_curve25519(es.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
            Ok(es)
        } else {
            Err(())
        }
    }
}

#[bench]
fn crypto_auth_hmacsha256(bencher: &mut Bencher) {
    rust_sodium::init();

    let message = "Hello".as_bytes();
    let key_material = &[5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
    let key = &mac::Key::from_slice(key_material).unwrap();

    bencher.iter(|| {
        mac::authenticate(message, key)
    });
}

#[bench]
fn crypto_sign_ed25519_sk_to_curve25519(bencher: &mut Bencher) {
    rust_sodium::init();

    let (_, alice_sk) = sign::gen_keypair();
    let (bob_pk, _) = sign::gen_keypair();

    unsafe {
        bencher.iter(|| {
            external::crypto_sign_ed25519_sk_to_curve25519((&alice_sk.0).as_ptr() as *mut u8, (&bob_pk.0).as_ptr());
        });
    }
}

#[bench]
fn crypto_sign_ed25519_pk_to_curve25519(bencher: &mut Bencher) {
    rust_sodium::init();

    let (_, alice_sk) = sign::gen_keypair();
    let (bob_pk, _) = sign::gen_keypair();

    unsafe {
        bencher.iter(|| {
            external::crypto_sign_ed25519_pk_to_curve25519((&bob_pk.0).as_ptr() as *mut u8, (&alice_sk.0).as_ptr());
        });
    }
}

#[bench]
fn crypto_auth_hmacsha256_verify(bencher: &mut Bencher) {
    rust_sodium::init();

    let message = "Hello".as_bytes();
    let key_material = &[5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
    let key = &mac::Key::from_slice(key_material).unwrap();
    let authenticator = mac::authenticate(message, key);

    bencher.iter(|| {
        mac::verify(&authenticator, message, key)
    });
}

#[bench]
fn crypto_sign_detached(bencher: &mut Bencher) {
    rust_sodium::init();

    let message = "Hello".as_bytes();
    let (_, alice_sk) = sign::gen_keypair();

    bencher.iter(|| {
        sign::sign_detached(message, &alice_sk)
    });
}

#[bench]
fn crypto_sign_keypair(bencher: &mut Bencher) {
    rust_sodium::init();

    bencher.iter(|| {
        sign::gen_keypair()
    });
}

#[bench]
fn crypto_scalarmult(bencher: &mut Bencher) {
    rust_sodium::init();

    let (public_key, secret_key) = sign::gen_keypair();
    let sec_curve = from_ed25519_sk(&secret_key).map(ecdh::Scalar).unwrap();
    let pub_curve = from_ed25519_pk(&public_key).map(ecdh::GroupElement).unwrap();

    bencher.iter(|| {
        ecdh::scalarmult(&sec_curve, &pub_curve).map(|ge| ge.0)
    });
}
