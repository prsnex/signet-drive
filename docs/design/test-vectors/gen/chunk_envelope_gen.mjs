// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//
// Generates the §4.2 multipart chunk-envelope golden (../golden/chunk-envelope.json)
// from an INDEPENDENT lineage — Node's built-in WebCrypto (OpenSSL-backed HKDF +
// AES-256-GCM) — distinct from both Rust RustCrypto (crypto/tests/envelope.rs) and
// the browser WebCrypto the web client ships (web/src/lib/crypto/envelope.ts). All
// three must produce these exact bytes, so the committed golden is a genuine
// cross-impl reference, not a self-consistency check.
//
// Supersedes the prior hand-paste flow (an #[ignore]d Rust emitter whose hex was
// copied into the web test) — the file the web test comment named as a follow-on.
//
// Run:  cd docs/design/test-vectors/gen && npm run gen:chunk
// (no npm deps — built-in WebCrypto only, like gen:kem.)

const { subtle } = globalThis.crypto;

const hex = (u8) => Buffer.from(u8).toString('hex');
const u32be = (n) => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

// §4.2 framing constants (Envelope Format §4.2; mirrors crypto/src/envelope.rs).
const FILE_MAGIC_MULTIPART = 0x02;
const FILE_ALG_A256GCM = 0x01;
const IV_LABEL = new TextEncoder().encode('signet-drive-multipart-iv-v1');

// Golden inputs — IDENTICAL to crypto/tests/envelope.rs (GOLDEN_CHUNK_*): a
// non-terminal chunk (idx 7 of 10 → is_last = false).
const DEK = new Uint8Array(32).fill(0x42);
const FILE_ID = Uint8Array.from(Buffer.from('00000000000040008000000000000111', 'hex'));
const CHUNK_INDEX = 7;
const CHUNK_COUNT = 10;
const PLAINTEXT_UTF8 = 'chunk seven payload';

const plaintext = new TextEncoder().encode(PLAINTEXT_UTF8);
const isLast = CHUNK_INDEX === CHUNK_COUNT - 1;
const idxBe = u32be(CHUNK_INDEX);

// IV = HKDF-SHA-256(ikm=DEK, salt=<empty>, info="signet-drive-multipart-iv-v1"||idx_be, L=12).
const hkdfKey = await subtle.importKey('raw', DEK, 'HKDF', false, ['deriveBits']);
const ivBits = await subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: concat(IV_LABEL, idxBe) },
  hkdfKey,
  12 * 8,
);
const iv = new Uint8Array(ivBits);

// AAD = file_id || idx_be || is_last(1).  body = AES-256-GCM(DEK, IV, plaintext, AAD) = ct||tag.
const aad = concat(FILE_ID, idxBe, Uint8Array.of(isLast ? 1 : 0));
const aesKey = await subtle.importKey('raw', DEK, 'AES-GCM', false, ['encrypt']);
const body = new Uint8Array(
  await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, aesKey, plaintext),
);

// Envelope = [0x02][0x01][idx_be(4)][iv(12)][ct||tag].
const envelope = concat(Uint8Array.of(FILE_MAGIC_MULTIPART, FILE_ALG_A256GCM), idxBe, iv, body);

process.stdout.write(
  `${JSON.stringify(
    {
      _comment:
        'GENERATED — do not hand-edit. Run `cd docs/design/test-vectors/gen && npm run gen:chunk`. §4.2 multipart chunk envelope via Node WebCrypto (HKDF-SHA-256 IV + AES-256-GCM). Consumed by crypto/tests/envelope.rs + web/src/lib/crypto/envelope.test.ts — a cross-impl reference (Rust + browser WebCrypto must match these bytes).',
      dek_hex: hex(DEK),
      file_id_hex: hex(FILE_ID),
      chunk_index: CHUNK_INDEX,
      chunk_count: CHUNK_COUNT,
      is_last: isLast,
      plaintext_utf8: PLAINTEXT_UTF8,
      iv_hex: hex(iv),
      envelope_hex: hex(envelope),
    },
    null,
    2,
  )}\n`,
);
