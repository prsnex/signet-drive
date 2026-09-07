// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// ML-KEM-1024 for the human surface (PQR Spec §7) — the TypeScript boundary
// over the committed wasm pkg (`./mlkem-wasm/`, built from `crypto-wasm/` by
// `crypto-wasm/build-web-pkg.sh`; ci.yml byte-compares it against source on
// every touching PR). One implementation, two compile targets: the wasm is the
// SAME RustCrypto `ml-kem` crate the CLI's Secure-Enclave differential tests
// validate, so the §11.3 cross-target goldens pin this exact code.
//
// This module supplies the ML-KEM primitive operations only — the hybrid
// combiner (KeyCombine + FixedInfo + AES-KW) lives in hybrid_wrap.ts, exactly
// as it lives in crypto/src/hybrid_wrap.rs on the PRSN side. Custody (§7): the
// caller stores only the 64-byte (d,z) seed (PRF-blob v2); the decapsulation
// key regenerates from it inside the wasm on every op (FIPS 203 KeyGen
// determinism) and never crosses the JS boundary.
//
// Initialization: the first operation lazily initializes the wasm module. In
// the browser the glue's default `new URL('…_bg.wasm', import.meta.url)`
// resolves to the vite-emitted, content-hashed asset (same-origin fetch;
// script-src 'wasm-unsafe-eval' permits the compile). Tests (vitest, node)
// call initMlkem(bytes) up front with the .wasm read from disk.

import type { Bytes } from './bytes';
import { InvalidInputError } from './errors';
import init, {
  mlkem1024_decapsulate,
  mlkem1024_ek_from_seed,
  mlkem1024_encapsulate,
  mlkem1024_keygen,
} from './mlkem-wasm/signet_crypto_wasm';

/** FIPS 203 ML-KEM-1024 sizes (PQR Spec §2), mirroring crypto-wasm/src/lib.rs. */
export const MLKEM_EK_LEN = 1568;
export const MLKEM_CT_LEN = 1568;
export const MLKEM_SS_LEN = 32;
/** The stored secret: the (d,z) seed — 2 × 32 bytes (spec §7). */
export const MLKEM_SEED_LEN = 64;

let ready: Promise<void> | undefined;

/** Initialize the wasm module (idempotent — first caller wins). Browser code
 *  never needs to call this (ops init lazily from the bundled asset URL);
 *  tests call it with the .wasm bytes read from disk before the first op. */
export function initMlkem(wasm?: BufferSource): Promise<void> {
  ready ??= init(wasm === undefined ? undefined : { module_or_path: wasm }).then(() => undefined);
  return ready;
}

/** Copy a wasm-returned array into a fresh ArrayBuffer-backed `Bytes` (the
 *  WebCrypto-safe type the rest of the crypto modules thread). */
function toBytes(a: Uint8Array): Bytes {
  const out = new Uint8Array(a.length);
  out.set(a);
  return out;
}

/** Generate a fresh ML-KEM-1024 identity (spec §7 keygen): the 64-byte (d,z)
 *  seed (goes into the PRF-wrapped blob, layout v2) + the 1568-byte
 *  encapsulation key (published to the directory at enrollment). */
export async function mlkemKeygen(): Promise<{ seed: Bytes; ek: Bytes }> {
  await initMlkem();
  const out = mlkem1024_keygen();
  return {
    seed: toBytes(out.subarray(0, MLKEM_SEED_LEN)),
    ek: toBytes(out.subarray(MLKEM_SEED_LEN)),
  };
}

/** Recompute the encapsulation key from a stored seed — the sign-in self-check
 *  that the unwrapped seed matches the published directory ek (spec §7). */
export async function mlkemEkFromSeed(seed: Bytes): Promise<Bytes> {
  if (seed.length !== MLKEM_SEED_LEN) throw new InvalidInputError('ml-kem seed must be 64 bytes');
  await initMlkem();
  return toBytes(mlkem1024_ek_from_seed(seed));
}

/** Encapsulate to a recipient's ek (the writer side of the hybrid wrap, spec
 *  §4.1): the 1568-byte ciphertext `ek`-field bytes + the 32-byte Z_mlkem. */
export async function mlkemEncapsulate(recipientEk: Bytes): Promise<{ ct: Bytes; ss: Bytes }> {
  if (recipientEk.length !== MLKEM_EK_LEN) {
    throw new InvalidInputError('ml-kem encapsulation key must be 1568 bytes');
  }
  await initMlkem();
  const out = mlkem1024_encapsulate(recipientEk);
  return { ct: toBytes(out.subarray(0, MLKEM_CT_LEN)), ss: toBytes(out.subarray(MLKEM_CT_LEN)) };
}

/** Decapsulate a ciphertext with the seed-regenerated key → the 32-byte
 *  Z_mlkem. Per FIPS 203 implicit rejection (spec §10) a tampered ciphertext
 *  does NOT error here — it yields a pseudorandom secret, and the failure
 *  surfaces downstream at AES-KW integrity (assert on unwrap outcomes, never
 *  on a decap error that never comes). */
export async function mlkemDecapsulate(seed: Bytes, ct: Bytes): Promise<Bytes> {
  if (seed.length !== MLKEM_SEED_LEN) throw new InvalidInputError('ml-kem seed must be 64 bytes');
  if (ct.length !== MLKEM_CT_LEN) {
    throw new InvalidInputError('ml-kem ciphertext must be 1568 bytes');
  }
  await initMlkem();
  return toBytes(mlkem1024_decapsulate(seed, ct));
}
