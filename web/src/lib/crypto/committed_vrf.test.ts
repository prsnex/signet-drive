// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The committed VRF module, the bytes a share fetches, held to the server-proved
// account-index golden (docs/design/test-vectors/golden/vrf-account-index.json, from
// crypto/examples/gen_vrf_golden.rs; crypto-wasm/tests/vrf_golden.rs re-proves it with
// signet_crypto::vrf): every case verifies to its index and every refusal to none (Bob
// and Gus, v1.1.1; until now the shipped module was checked by one known answer).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { hexDecode, hexEncode } from './bytes';
import { IntegrityError } from './errors';
import { initVrf, vrfVerify } from './vrf';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)));
const json = (rel: string) => JSON.parse(read(rel).toString('utf8'));
const VECTORS = '../../../../docs/design/test-vectors';

beforeAll(async () => {
  await initVrf(read('./vrf-wasm/signet_vrf_wasm_bg.wasm'));
});

type VrfCase = { public_key: string; account_id: string; proof: string; index: string };
type VrfRefusal = { why: string; public_key: string; account_id: string; proof: string };

describe('the committed VRF module: the server-proved account-index golden', () => {
  const golden: { cases: VrfCase[]; refusals: VrfRefusal[] } = json(
    `${VECTORS}/golden/vrf-account-index.json`,
  );

  it('carries 25 cases and 8 refusals', () => {
    expect([golden.cases.length, golden.refusals.length]).toEqual([25, 8]);
  });

  it('every case verifies to its index', async () => {
    for (const c of golden.cases) {
      const index = await vrfVerify(
        hexDecode(c.public_key),
        hexDecode(c.account_id),
        hexDecode(c.proof),
      );
      expect(hexEncode(index), `account ${c.account_id}`).toBe(c.index);
    }
  });

  it('every refusal yields no index, as an IntegrityError', async () => {
    for (const r of golden.refusals) {
      await expect(
        vrfVerify(hexDecode(r.public_key), hexDecode(r.account_id), hexDecode(r.proof)),
        r.why,
      ).rejects.toBeInstanceOf(IntegrityError);
    }
  });
});
