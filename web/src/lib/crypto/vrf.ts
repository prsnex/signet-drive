// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The transparency log's v3 account index for the human surface
// (Transparency-Log Epoch-2 design §2, §10.6): the TypeScript boundary over the
// committed VRF wasm pkg's `vrf_r255_verify`, ECVRF-RISTRETTO255-SHA512 through
// the same pinned `vrf-r255` crate the server proves with and the CLI verifies
// with (crypto-wasm's native test pins its framing to signet_crypto's). Verify
// only: the browser never holds a VRF secret.
//
// Its own module, loaded on first use (Launch Punch-List §1-67): built from
// crypto-wasm's `vrf` feature into `./vrf-wasm/`, apart from the ML-KEM asset
// every session loads, so a session that never shares never downloads it. Only
// recipient_verify.ts reaches it. In the browser the glue's default
// `new URL('…_bg.wasm', import.meta.url)` resolves to the vite-emitted,
// content-hashed asset; tests call initVrf(bytes) with the .wasm read from disk.

import type { Bytes } from './bytes';
import { IntegrityError, ModuleLoadError } from './errors';
import init, { vrf_r255_verify } from './vrf-wasm/signet_vrf_wasm';

let ready: Promise<void> | undefined;

/** Initialize the VRF module (idempotent once it has loaded). A failed load is a
 *  {@link ModuleLoadError} and is NOT kept: the next call fetches again, so a share
 *  after a dropped connection or a deploy can succeed without a page reload (Bob,
 *  §1-67). Browser code never needs to call this; tests pass the .wasm bytes. */
export function initVrf(wasm?: BufferSource): Promise<void> {
  if (!ready) {
    const loading: Promise<void> = init(
      wasm === undefined ? undefined : { module_or_path: wasm },
    ).then(
      () => undefined,
      (e: unknown) => {
        if (ready === loading) ready = undefined;
        throw new ModuleLoadError('VRF verifier', e);
      },
    );
    ready = loading;
  }
  return ready;
}

/** The 64-byte index `proof` (80 bytes) proves for an account (a UUID's 16 raw
 *  bytes) under an epoch's VRF public key (32 bytes). A malformed key or proof,
 *  or a proof that does not verify, is an IntegrityError: a binding that cannot
 *  be proved is a substitution, never a pass. A module that cannot be loaded is a
 *  ModuleLoadError, which says nothing about the proof. */
export async function vrfVerify(publicKey: Bytes, accountId: Bytes, proof: Bytes): Promise<Bytes> {
  await initVrf();
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
