// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The transparency log's v3 account index for the human surface
// (Transparency-Log Epoch-2 design §2, §10.6): the TypeScript boundary over the
// committed wasm pkg's `vrf_r255_verify`, ECVRF-RISTRETTO255-SHA512 through the
// same pinned `vrf-r255` crate the server proves with and the CLI verifies with
// (crypto-wasm's native test pins its framing to signet_crypto's). Verify only:
// the browser never holds a VRF secret. The module is the ML-KEM one, so it
// initializes through `initMlkem`.

import type { Bytes } from './bytes';
import { IntegrityError } from './errors';
import { initMlkem } from './mlkem';
import { vrf_r255_verify } from './mlkem-wasm/signet_crypto_wasm';

/** The 64-byte index `proof` (80 bytes) proves for an account (a UUID's 16 raw
 *  bytes) under an epoch's VRF public key (32 bytes). A malformed key or proof,
 *  or a proof that does not verify, is an IntegrityError: a binding that cannot
 *  be proved is a substitution, never a pass. */
export async function vrfVerify(publicKey: Bytes, accountId: Bytes, proof: Bytes): Promise<Bytes> {
  await initMlkem();
  let index: Uint8Array;
  try {
    index = vrf_r255_verify(publicKey, accountId, proof);
  } catch (e) {
    throw new IntegrityError(`VRF proof does not verify (${e instanceof Error ? e.message : e})`);
  }
  const out = new Uint8Array(index.length);
  out.set(index);
  return out;
}
