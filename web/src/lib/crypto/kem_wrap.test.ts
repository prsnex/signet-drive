// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { b64uDecode, hexDecode, hexEncode } from './bytes';
import {
  deriveWrapKey,
  prfSalt,
  unwrapKemPrivkey,
  wrapKemPrivkey,
  type KemPrivkeyWrap,
} from './kem_wrap';

// Differential harness vs the committed Node-WebCrypto golden (also consumed by
// crypto/tests/kem_wrap.rs). The chain is deterministic given the fixed PRF
// output + IV, so every step is pinned byte-for-byte: derive_wrap_key reproduces
// W, wrap reproduces the exact ct + tag, and unwrap recovers the PKCS#8 key.

interface KemGolden {
  kem_privkey_wrap: {
    prf_output_hex: string;
    expected_w_hex: string;
    pkcs8_hex: string;
    iv_b64u: string;
    expected_ct_b64u: string;
    expected_tag_b64u: string;
  };
}

const golden: KemGolden = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL('../../../../docs/design/test-vectors/golden/kem-wrap.json', import.meta.url),
    ),
    'utf8',
  ),
);
const v = golden.kem_privkey_wrap;

function goldenEnvelope(): KemPrivkeyWrap {
  return { v: 1, alg: 'A256GCM', iv: v.iv_b64u, ct: v.expected_ct_b64u, tag: v.expected_tag_b64u };
}

describe('KEM-key wrap chain (§8) — differential vs committed Node-WebCrypto golden', () => {
  it('derive_wrap_key: HKDF-SHA-256(prf_output) reproduces W', async () => {
    const w = await deriveWrapKey(hexDecode(v.prf_output_hex));
    expect(hexEncode(w)).toBe(v.expected_w_hex);
  });

  it('wrap_kem_privkey: reproduces the golden ct + tag (fixed W + IV)', async () => {
    const env = await wrapKemPrivkey(
      hexDecode(v.expected_w_hex),
      hexDecode(v.pkcs8_hex),
      b64uDecode(v.iv_b64u),
    );
    expect(env.alg).toBe('A256GCM');
    expect(env.iv).toBe(v.iv_b64u);
    expect(env.ct).toBe(v.expected_ct_b64u);
    expect(env.tag).toBe(v.expected_tag_b64u);
  });

  it('unwrap_kem_privkey: recovers the PKCS#8 key', async () => {
    const pkcs8 = await unwrapKemPrivkey(hexDecode(v.expected_w_hex), goldenEnvelope());
    expect(hexEncode(pkcs8)).toBe(v.pkcs8_hex);
  });

  it('full chain: derive W -> wrap -> unwrap round-trips the PKCS#8', async () => {
    const w = await deriveWrapKey(hexDecode(v.prf_output_hex));
    const env = await wrapKemPrivkey(w, hexDecode(v.pkcs8_hex), b64uDecode(v.iv_b64u));
    expect(hexEncode(await unwrapKemPrivkey(w, env))).toBe(v.pkcs8_hex);
  });

  it('unwrap under a wrong W is rejected', async () => {
    const wrongW = hexDecode('ff' + '00'.repeat(31));
    await expect(unwrapKemPrivkey(wrongW, goldenEnvelope())).rejects.toThrow();
  });
});

describe('prfSalt (INV-7)', () => {
  it('is SHA-256("signet-drive-kem-wrap-v1") — must match the server constant', async () => {
    expect(hexEncode(await prfSalt())).toBe(
      'e93d48bd9013c08e0bac7555f09312a3dd27c8e8a6d557fb325929d9a5cdf637',
    );
  });
});
