// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { hexDecode, hexEncode, type Bytes } from './bytes';
import { generateEphemeralKeypair } from './ecdh';
import { IntegrityError, InvalidInputError } from './errors';
import {
  buildFixedInfo,
  contentWrapKek,
  hybridRfp,
  hybridUnwrapDek,
  hybridUnwrapFromSecrets,
  hybridUnwrapMetadataKey,
  hybridWrapDek,
  hybridWrapFromSecrets,
  hybridWrapMetadataKey,
  parseHybridWrapEnvelope,
  type HybridWrapEnvelope,
} from './hybrid_wrap';
import { aesKwWrap } from './keywrap';
import { initMlkem, mlkemKeygen } from './mlkem';

// The web half of the hybrid content-wrap suite, mirroring
// crypto/tests/hybrid_wrap.rs. The load-bearing test is the KeyCombine KAT:
// the SAME A3-co-signed byte-pinned vectors the Rust suite pins (generated
// independently by Hlin and Gus from the spec text and byte-matched, S104) —
// a green KAT here means the TS combiner is byte-identical to the co-signed
// construction AND to the Rust reference. The committed cross-surface
// crossover goldens live in hybrid.crossover.test.ts.

beforeAll(async () => {
  await initMlkem(
    readFileSync(
      fileURLToPath(new URL('./mlkem-wasm/signet_crypto_wasm_bg.wasm', import.meta.url)),
    ),
  );
});

/** A fresh real P-256 point (the seams validate on-curve, so fixtures use
 *  real points; synthetic byte-fill appears only where the pure encoder is
 *  pinned, in the KAT). */
async function realPoint(): Promise<Bytes> {
  const pair = await generateEphemeralKeypair();
  return new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
}

/** The P-256 generator point (fixed, well-known) in X9.63 uncompressed form —
 *  for pinned vectors. */
function generatorX963(): Bytes {
  return hexDecode(
    '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' +
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  );
}

function filled(len: number, byte: number): Bytes {
  return new Uint8Array(len).fill(byte);
}

interface Sample {
  env: HybridWrapEnvelope;
  zEcdh: Bytes;
  zMlkem: Bytes;
  rkEc: Bytes;
  rkPq: Bytes;
  dek: Bytes;
}

async function sample(partyV: Bytes): Promise<Sample> {
  const epk = await realPoint();
  const zEcdh = filled(32, 0x11);
  const zMlkem = filled(32, 0x22);
  const rkEc = await realPoint();
  const rkPq = filled(1568, 0x44);
  const dek = filled(32, 0x66);
  const ek = filled(1568, 0x55);
  const env = await hybridWrapFromSecrets(zEcdh, zMlkem, epk, ek, rkEc, rkPq, dek, partyV);
  return { env, zEcdh, zMlkem, rkEc, rkPq, dek };
}

describe('KeyCombine KAT (PQR §11.5 — the A3 byte-matched vectors)', () => {
  it('VEC-1 (party_v empty) and VEC-2 (party_v = 16×0xF0) pin FixedInfo/KEK/wk', async () => {
    // Inputs per the merged spec: Z_ecdh = 0x00..0x1F, Z_mlkem = 0x20..0x3F,
    // alg fixed, epk=65×E1, ek=1568×E2, rk_ec=65×E3, rk_pq=1568×E4, L=256,
    // DEK=32×0x42 — the same bytes crypto/tests/hybrid_wrap.rs pins.
    const zEcdh = new Uint8Array(32).map((_, i) => i) as Bytes;
    const zMlkem = new Uint8Array(32).map((_, i) => i + 0x20) as Bytes;
    const epk = filled(65, 0xe1);
    const ek = filled(1568, 0xe2);
    const rkEc = filled(65, 0xe3);
    const rkPq = filled(1568, 0xe4);
    const dek = filled(32, 0x42);

    const fi1 = buildFixedInfo(epk, ek, rkEc, rkPq, new Uint8Array(0));
    expect(fi1.length).toBe(3324);
    const kek1 = await contentWrapKek(zEcdh, zMlkem, fi1);
    expect(hexEncode(kek1)).toBe(
      '5796f7961352b3b74e130dff668703a68611e64cc271351af22fa6b5a8b50363',
    );
    expect(hexEncode(await aesKwWrap(kek1, dek))).toBe(
      '538726e2887539c6810d8aa1f0e5891abc8d472ec4722c6d59446c8cb36a747d9b775df7171fed80',
    );

    const fi2 = buildFixedInfo(epk, ek, rkEc, rkPq, filled(16, 0xf0));
    expect(fi2.length).toBe(3340);
    const kek2 = await contentWrapKek(zEcdh, zMlkem, fi2);
    expect(hexEncode(kek2)).toBe(
      '4a0660ef7afe242e900f8bf8325aa9de4baba28b8384cebcd36323df160ef3ce',
    );
    expect(hexEncode(await aesKwWrap(kek2, dek))).toBe(
      '20ec7c1ec86a3290c5a17462fb2bdc70bf21eb59f5236a818f9f47fde7e65e513b1e16139eeee6f2',
    );
  });
});

describe('hybrid round-trips (from-secrets seams)', () => {
  it('DEK wrap round-trips; envelope carries both epk and ek + wk', async () => {
    const s = await sample(new Uint8Array(0));
    const got = await hybridUnwrapFromSecrets(
      s.zEcdh,
      s.zMlkem,
      s.env,
      s.rkEc,
      s.rkPq,
      new Uint8Array(0),
    );
    expect(hexEncode(got)).toBe(hexEncode(s.dek));
    expect(s.env.alg).toBe('ECDH-ES+ML-KEM-1024+A256KW');
    expect(s.env.v).toBe(1);
  });

  it('metadata-key wrap round-trips under its folder', async () => {
    const folder = filled(16, 0xab);
    const s = await sample(folder);
    const got = await hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, s.env, s.rkEc, s.rkPq, folder);
    expect(hexEncode(got)).toBe(hexEncode(s.dek));
  });
});

describe('downgrade / tamper inventory (PQR §9.4, web layer)', () => {
  it('N1/N2 shape: strict parse rejects a stripped or reshaped envelope', async () => {
    const s = await sample(new Uint8Array(0));
    // Round-trip through JSON (the API path) parses clean.
    const clean = JSON.parse(JSON.stringify(s.env)) as unknown;
    expect(parseHybridWrapEnvelope(clean)).toEqual(s.env);
    // ek stripped → not a valid hybrid block.
    const stripped = JSON.parse(JSON.stringify(s.env)) as Record<string, unknown>;
    delete stripped.ek;
    expect(() => parseHybridWrapEnvelope(stripped)).toThrow(InvalidInputError);
    // A smuggled extra field → reject (deny_unknown_fields mirror).
    const smuggled = JSON.parse(JSON.stringify(s.env)) as Record<string, unknown>;
    smuggled.ct = 'AAAAAAAA';
    expect(() => parseHybridWrapEnvelope(smuggled)).toThrow(InvalidInputError);
  });

  it('N2 dispatch: a non-hybrid alg is rejected from alg ALONE', async () => {
    const s = await sample(new Uint8Array(0));
    const e = { ...s.env, alg: 'ECDH-ES+A256KW' };
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, e, s.rkEc, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(InvalidInputError);
    // The reserved pure endpoint (v3 horizon) is rejected the same way — a
    // future activation must be a deliberate, test-visible act.
    const pure = { ...s.env, alg: 'ML-KEM-1024+A256KW' };
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, pure, s.rkEc, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(InvalidInputError);
  });

  it('N3: a swapped (valid-length) ek fails at AES-KW integrity, not before', async () => {
    const s = await sample(new Uint8Array(0));
    const tampered = { ...s.env, ek: hexToB64u(filled(1568, 0x77)) };
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, tampered, s.rkEc, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(IntegrityError);
  });

  it('N4: recipient-key binding — a transplanted block fails under other keys', async () => {
    const s = await sample(new Uint8Array(0));
    const wrongEc = await realPoint();
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, s.env, wrongEc, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(IntegrityError);
    await expect(
      hybridUnwrapFromSecrets(
        s.zEcdh,
        s.zMlkem,
        s.env,
        s.rkEc,
        filled(1568, 0x88),
        new Uint8Array(0),
      ),
    ).rejects.toThrow(IntegrityError);
  });

  it('N7: a metadata wrap does not unwrap as a DEK or under another folder', async () => {
    const folder = filled(16, 0xab);
    const s = await sample(folder);
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, s.env, s.rkEc, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(IntegrityError);
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, s.env, s.rkEc, s.rkPq, filled(16, 0xcd)),
    ).rejects.toThrow(IntegrityError);
  });
});

describe('rfp (§8.5 pair-commitment)', () => {
  it('commits to BOTH keys; matches the pinned cross-lineage vector', async () => {
    const p1 = await realPoint();
    const a = await hybridRfp(p1, filled(1568, 0x44));
    const b = await hybridRfp(p1, filled(1568, 0x45));
    expect(a).not.toBe(b);
    expect(a.length).toBe(64);
    // The pinned §8.5 vector (generator point + 1568×0xE4) — the same value
    // crypto/tests/hybrid_wrap.rs pins, independently derived in Python at
    // the S105 review (three lineages on the commitment encoding).
    expect(await hybridRfp(generatorX963(), filled(1568, 0xe4))).toBe(
      'bd2fd90ff413e4eed8fbc07b81e50f52d336f0e4e27932d3022c34c54700581d',
    );
  });
});

describe('seam validation', () => {
  it('rejects wrong-length ek at wrap and unwrap', async () => {
    const rkEc = await realPoint();
    const epk = await realPoint();
    await expect(
      hybridWrapFromSecrets(
        filled(32, 0x11),
        filled(32, 0x22),
        epk,
        filled(1567, 0x55),
        rkEc,
        filled(1568, 0x44),
        filled(32, 0x66),
        new Uint8Array(0),
      ),
    ).rejects.toThrow(InvalidInputError);
    const s = await sample(new Uint8Array(0));
    const short = { ...s.env, ek: hexToB64u(filled(1567, 0x55)) };
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, short, s.rkEc, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(InvalidInputError);
  });

  it('rejects non-canonical recipient keys (length, off-curve, rk_pq length)', async () => {
    const s = await sample(new Uint8Array(0));
    await expect(
      hybridUnwrapFromSecrets(
        s.zEcdh,
        s.zMlkem,
        s.env,
        filled(33, 0x02),
        s.rkPq,
        new Uint8Array(0),
      ),
    ).rejects.toThrow(InvalidInputError);
    const offCurve = filled(65, 0xaa);
    offCurve[0] = 0x04;
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, s.env, offCurve, s.rkPq, new Uint8Array(0)),
    ).rejects.toThrow(InvalidInputError);
    await expect(
      hybridUnwrapFromSecrets(
        s.zEcdh,
        s.zMlkem,
        s.env,
        s.rkEc,
        filled(1567, 0x44),
        new Uint8Array(0),
      ),
    ).rejects.toThrow(InvalidInputError);
    await expect(hybridRfp(filled(65, 0x99), filled(1568, 0x44))).rejects.toThrow(
      InvalidInputError,
    );
  });

  it('rejects malformed party_v both directions', async () => {
    const s = await sample(new Uint8Array(0));
    await expect(
      hybridUnwrapFromSecrets(s.zEcdh, s.zMlkem, s.env, s.rkEc, s.rkPq, filled(5, 0xab)),
    ).rejects.toThrow(InvalidInputError);
    const rkEc = await realPoint();
    const epk = await realPoint();
    await expect(
      hybridWrapFromSecrets(
        filled(32, 0x11),
        filled(32, 0x22),
        epk,
        filled(1568, 0x55),
        rkEc,
        filled(1568, 0x44),
        filled(32, 0x66),
        filled(5, 0xab),
      ),
    ).rejects.toThrow(InvalidInputError);
  });
});

describe('full flows (real WebCrypto ECDH + wasm ML-KEM)', () => {
  it('hybridWrapDek → hybridUnwrapDek round-trips with a real recipient', async () => {
    // A real hybrid recipient: WebCrypto P-256 pair + wasm ML-KEM identity.
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
      'deriveBits',
    ]);
    const rkEc = new Uint8Array(
      await crypto.subtle.exportKey('raw', (pair as CryptoKeyPair).publicKey),
    );
    const { seed, ek: rkPq } = await mlkemKeygen();
    const dek = crypto.getRandomValues(new Uint8Array(32)) as Bytes;

    const env = await hybridWrapDek(rkEc, rkPq, dek);
    const got = await hybridUnwrapDek((pair as CryptoKeyPair).privateKey, seed, env, rkEc, rkPq);
    expect(hexEncode(got)).toBe(hexEncode(dek));

    // §10 implicit rejection, end-to-end: a tampered ek surfaces as AES-KW
    // integrity failure at unwrap — never a decap error.
    const ekBytes = filled(1568, 0x00);
    const tampered = { ...env, ek: hexToB64u(ekBytes) };
    await expect(
      hybridUnwrapDek((pair as CryptoKeyPair).privateKey, seed, tampered, rkEc, rkPq),
    ).rejects.toThrow(IntegrityError);
  });

  it('hybridWrapMetadataKey binds the folder end-to-end', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
      'deriveBits',
    ])) as CryptoKeyPair;
    const rkEc = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const { seed, ek: rkPq } = await mlkemKeygen();
    const mk = crypto.getRandomValues(new Uint8Array(32)) as Bytes;
    const folder = filled(16, 0x0a);

    const env = await hybridWrapMetadataKey(rkEc, rkPq, mk, folder);
    const got = await hybridUnwrapMetadataKey(pair.privateKey, seed, env, rkEc, rkPq, folder);
    expect(hexEncode(got)).toBe(hexEncode(mk));
    await expect(
      hybridUnwrapMetadataKey(pair.privateKey, seed, env, rkEc, rkPq, filled(16, 0x0b)),
    ).rejects.toThrow(IntegrityError);
  });
});

/** base64url a byte-fill (test helper: envelopes carry b64u fields). */
function hexToB64u(bytes: Bytes): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
