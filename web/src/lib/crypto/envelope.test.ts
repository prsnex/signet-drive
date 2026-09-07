// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { aesGcmSeal } from './aead';
import { concatBytes, hexDecode, hexEncode, u32be, utf8Encode } from './bytes';
import { FILE_MAGIC_SINGLE_PUT, openChunk, openFile, sealChunk, sealFile } from './envelope';
import { hkdfSha256 } from './kdf';

// Differential harness vs the committed file-envelope golden (file_envelope_cat02,
// also consumed by crypto/tests/golden_vectors.rs). Deterministic given the fixed
// DEK + IV, so seal_file is pinned byte-for-byte to envelope_hex.

interface FileGolden {
  file_envelope_cat02: {
    dek_hex: string;
    iv_hex: string;
    file_id_hex: string;
    plaintext_utf8: string;
    envelope_hex: string;
  };
}

const golden: FileGolden = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL('../../../../docs/design/test-vectors/golden/wrap-chain.json', import.meta.url),
    ),
    'utf8',
  ),
);
const v = golden.file_envelope_cat02;
const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe('file envelope (single-PUT, §4.1) — differential vs committed golden', () => {
  it('seal_file produces the golden envelope bytes (fixed DEK + IV)', async () => {
    const envelope = await sealFile(
      hexDecode(v.dek_hex),
      hexDecode(v.iv_hex),
      hexDecode(v.file_id_hex),
      utf8Encode(v.plaintext_utf8),
    );
    expect(hexEncode(envelope)).toBe(v.envelope_hex);
  });

  it('open_file recovers the plaintext', async () => {
    const plaintext = await openFile(
      hexDecode(v.dek_hex),
      hexDecode(v.file_id_hex),
      hexDecode(v.envelope_hex),
    );
    expect(text(plaintext)).toBe(v.plaintext_utf8);
  });

  it('open_file rejects a wrong file_id (AAD binding)', async () => {
    const wrongFileId = hexDecode('ffffffff000040008000000000000111');
    await expect(
      openFile(hexDecode(v.dek_hex), wrongFileId, hexDecode(v.envelope_hex)),
    ).rejects.toThrow();
  });

  it('open_file rejects a malformed envelope (bad magic, too short)', async () => {
    await expect(
      openFile(hexDecode(v.dek_hex), hexDecode(v.file_id_hex), hexDecode('00'.repeat(30))),
    ).rejects.toThrow();
    await expect(
      openFile(hexDecode(v.dek_hex), hexDecode(v.file_id_hex), hexDecode('0101')),
    ).rejects.toThrow();
  });

  it('round-trips a fresh random file', async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const fileId = crypto.getRandomValues(new Uint8Array(16));
    const envelope = await sealFile(dek, iv, fileId, utf8Encode('the quick brown fox'));
    expect(text(await openFile(dek, fileId, envelope))).toBe('the quick brown fox');
  });
});

// Cross-implementation parity: CHUNK_GOLDEN is a committed, generated reference
// (gen/chunk_envelope_gen.mjs — Node WebCrypto / OpenSSL). The web (browser
// WebCrypto) and Rust (RustCrypto, crypto/tests/envelope.rs) must each produce
// envelope_hex byte-for-byte, so three independent crypto stacks agree on the §4.2
// chunk format. Regenerate (never hand-edit): `cd docs/design/test-vectors/gen &&
// npm run gen:chunk`.
const CHUNK_GOLDEN: {
  dek_hex: string;
  file_id_hex: string;
  chunk_index: number;
  chunk_count: number;
  plaintext_utf8: string;
  envelope_hex: string;
} = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL('../../../../docs/design/test-vectors/golden/chunk-envelope.json', import.meta.url),
    ),
    'utf8',
  ),
);

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe('multipart chunk envelope (§4.2)', () => {
  it('sealChunk produces signet-crypto bytes byte-for-byte (cross-impl parity)', async () => {
    const env = await sealChunk(
      hexDecode(CHUNK_GOLDEN.dek_hex),
      hexDecode(CHUNK_GOLDEN.file_id_hex),
      CHUNK_GOLDEN.chunk_index,
      CHUNK_GOLDEN.chunk_count,
      utf8Encode(CHUNK_GOLDEN.plaintext_utf8),
    );
    expect(hexEncode(env)).toBe(CHUNK_GOLDEN.envelope_hex);
  });

  it('sealChunk matches an independent WebCrypto reconstruction', async () => {
    // Rebuild from the spec'd primitives: IV = HKDF(DEK, empty salt,
    // "signet-drive-multipart-iv-v1" || idx_be, 12); AAD = file_id || idx_be ||
    // is_last; body = AES-256-GCM(DEK, IV, plaintext, AAD).
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const idx = 12345;
    const count = 20000; // idx not terminal → is_last = 0
    const pt = utf8Encode('reconstruct me');
    const info = concatBytes(utf8Encode('signet-drive-multipart-iv-v1'), u32be(idx));
    const iv = await hkdfSha256(dek, new Uint8Array(0), info, 12);
    const aad = concatBytes(fileId, u32be(idx), new Uint8Array([0]));
    const body = await aesGcmSeal(dek, iv, pt, aad);
    const expected = concatBytes(new Uint8Array([0x02, 0x01]), u32be(idx), iv, body);
    expect(hexEncode(await sealChunk(dek, fileId, idx, count, pt))).toBe(hexEncode(expected));
  });

  it('round-trips chunks (including an empty final chunk)', async () => {
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const count = 10000;
    const cases: [number, string][] = [
      [0, 'first chunk'],
      [9999, ''], // the terminal chunk (idx 9999 of 10000), empty
      [42, 'a later chunk'],
    ];
    for (const [idx, msg] of cases) {
      const env = await sealChunk(dek, fileId, idx, count, utf8Encode(msg));
      expect(text(await openChunk(dek, fileId, idx, count, env))).toBe(msg);
    }
  });

  it('rejects a reordered chunk via the stored-index check', async () => {
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const env = await sealChunk(dek, fileId, 2, 6, utf8Encode('position two'));
    await expect(openChunk(dek, fileId, 5, 6, env)).rejects.toThrow();
  });

  it('rejects a forged position via the AAD (the real binding)', async () => {
    // Defeat the structural index check by rewriting the stored index to the
    // target position — the AAD still fails, so a chunk cannot be silently moved.
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const env = await sealChunk(dek, fileId, 2, 6, utf8Encode('position two'));
    env.set(u32be(5), 2); // forge stored index 2 -> 5
    await expect(openChunk(dek, fileId, 5, 6, env)).rejects.toThrow();
  });

  it('detects whole-chunk truncation via the is_last flag', async () => {
    // A 3-chunk file: dropping the terminal chunk and lowering the count to 2 makes
    // the reader open chunk 1 expecting is_last=true, but it was sealed is_last=false.
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const c0 = await sealChunk(dek, fileId, 0, 3, utf8Encode('chunk zero'));
    const c1 = await sealChunk(dek, fileId, 1, 3, utf8Encode('chunk one'));

    // Honest read (true count) verifies; truncated read (lowered count) is rejected.
    expect(text(await openChunk(dek, fileId, 1, 3, c1))).toBe('chunk one');
    await expect(openChunk(dek, fileId, 1, 2, c1)).rejects.toThrow();
    // A non-boundary chunk still opens under the lowered count — detection is at the
    // forged boundary.
    expect(text(await openChunk(dek, fileId, 0, 2, c0))).toBe('chunk zero');
  });

  it('rejects chunk_index out of range for chunk_count', async () => {
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    await expect(sealChunk(dek, fileId, 5, 3, utf8Encode('x'))).rejects.toThrow();
    await expect(sealChunk(dek, fileId, 0, 0, utf8Encode('x'))).rejects.toThrow();
    const env = await sealChunk(dek, fileId, 0, 1, utf8Encode('x'));
    await expect(openChunk(dek, fileId, 3, 3, env)).rejects.toThrow();
  });

  it('rejects cross-file substitution, wrong DEK, and tamper', async () => {
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const env = await sealChunk(dek, fileId, 0, 1, utf8Encode('chunk contents'));

    const otherFile = fileId.slice();
    otherFile[0] ^= 0xff;
    await expect(openChunk(dek, otherFile, 0, 1, env)).rejects.toThrow();

    const wrongDek = dek.slice();
    wrongDek[0] ^= 0xff;
    await expect(openChunk(wrongDek, fileId, 0, 1, env)).rejects.toThrow();

    const tampered = env.slice();
    tampered[tampered.length - 1] ^= 1;
    await expect(openChunk(dek, fileId, 0, 1, tampered)).rejects.toThrow();
  });

  it('rejects wrong magic/alg and a too-short envelope', async () => {
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const env = await sealChunk(dek, fileId, 0, 1, utf8Encode('x'));

    const badMagic = env.slice();
    badMagic[0] = FILE_MAGIC_SINGLE_PUT;
    await expect(openChunk(dek, fileId, 0, 1, badMagic)).rejects.toThrow();

    const badAlg = env.slice();
    badAlg[1] = 0x02;
    await expect(openChunk(dek, fileId, 0, 1, badAlg)).rejects.toThrow();

    await expect(openChunk(dek, fileId, 0, 1, hexDecode('00'.repeat(20)))).rejects.toThrow();
  });

  it('single-PUT and multipart envelopes do not cross-open', async () => {
    const dek = randomBytes(32);
    const fileId = randomBytes(16);
    const single = await sealFile(dek, randomBytes(12), fileId, utf8Encode('x'));
    await expect(openChunk(dek, fileId, 0, 1, single)).rejects.toThrow();
    const chunk = await sealChunk(dek, fileId, 0, 1, utf8Encode('x'));
    await expect(openFile(dek, fileId, chunk)).rejects.toThrow();
  });
});
