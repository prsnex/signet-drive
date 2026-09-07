// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { hexEncode, type Bytes } from './bytes';
import {
  initMlkem,
  mlkemDecapsulate,
  mlkemEkFromSeed,
  mlkemEncapsulate,
  mlkemKeygen,
  MLKEM_CT_LEN,
  MLKEM_EK_LEN,
  MLKEM_SEED_LEN,
  MLKEM_SS_LEN,
} from './mlkem';

// The TS boundary over the COMMITTED wasm pkg — the third context the §11.3
// cross-target KAT runs in (native cargo test · wasm-bindgen-test node ·
// this: the committed artifact through the boundary the web client actually
// imports). The pinned digest matching here proves the committed .wasm is the
// same code the other two contexts validated, end of chain.

const wasmBytes = readFileSync(
  fileURLToPath(new URL('./mlkem-wasm/signet_crypto_wasm_bg.wasm', import.meta.url)),
);

beforeAll(async () => {
  await initMlkem(wasmBytes);
});

async function sha256Hex(b: Bytes): Promise<string> {
  return hexEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', b)));
}

describe('mlkem boundary (committed wasm pkg)', () => {
  it('§11.3 cross-target KAT: fixed seed → the pinned ek digest', async () => {
    // The same pin as crypto-wasm/src/lib.rs KAT_EK_SHA256 (native + wasm legs).
    const seed = new Uint8Array(MLKEM_SEED_LEN).fill(0x42);
    const ek = await mlkemEkFromSeed(seed);
    expect(ek.length).toBe(MLKEM_EK_LEN);
    expect(await sha256Hex(ek)).toBe(
      'dd2e8fe4ffe00e224daab15f6d5f90516754ef13aa25cea525f5d55f520d0137',
    );
  });

  it('keygen → encaps → decaps round-trip; implicit rejection on tamper (§10)', async () => {
    const { seed, ek } = await mlkemKeygen();
    expect(seed.length).toBe(MLKEM_SEED_LEN);
    expect(ek.length).toBe(MLKEM_EK_LEN);
    // The seed regenerates the same ek (FIPS 203 KeyGen determinism — the §7
    // custody model the PRF-blob v2 relies on).
    expect(hexEncode(await mlkemEkFromSeed(seed))).toBe(hexEncode(ek));

    const { ct, ss } = await mlkemEncapsulate(ek);
    expect(ct.length).toBe(MLKEM_CT_LEN);
    expect(ss.length).toBe(MLKEM_SS_LEN);
    expect(hexEncode(await mlkemDecapsulate(seed, ct))).toBe(hexEncode(ss));

    // Implicit rejection: a tampered ct decapsulates WITHOUT error to a
    // different secret — the failure belongs to AES-KW downstream.
    const bad = new Uint8Array(ct);
    bad[0] ^= 0x01;
    expect(hexEncode(await mlkemDecapsulate(seed, bad))).not.toBe(hexEncode(ss));
  });

  it('validates lengths at the seam', async () => {
    await expect(mlkemEkFromSeed(new Uint8Array(63))).rejects.toThrow();
    await expect(mlkemEncapsulate(new Uint8Array(1567))).rejects.toThrow();
    await expect(mlkemDecapsulate(new Uint8Array(64), new Uint8Array(1569))).rejects.toThrow();
  });
});
