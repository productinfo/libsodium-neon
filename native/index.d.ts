/// <reference types="node" />
export as namespace sodium_native;

export interface KeyPair {
  key_type: 'curve25519' | 'ed25519' | 'x25519';
  private_key_buffer: Buffer;
  public_key_buffer: Buffer;
}

export function crypto_auth_hmacsha256(message: Uint8Array, key: Uint8Array): Buffer;
export function crypto_scalarmult(secret_key: Uint8Array, public_key: Uint8Array): Buffer;
export function crypto_sign_detached(message: Uint8Array, secret_key: Uint8Array): Buffer;
export function crypto_sign_ed25519_pk_to_curve25519(public_key: Uint8Array): Buffer;
export function crypto_sign_ed25519_sk_to_curve25519(secret_key: Uint8Array): Buffer;
export function crypto_sign_keypair(): KeyPair;
export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: Uint8Array,
  public_key: Uint8Array
): boolean;
