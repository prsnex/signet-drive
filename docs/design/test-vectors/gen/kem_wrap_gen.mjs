// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//
// Generates the committed golden vector for the human-side KEM-key wrap chain
// (Envelope Format v09 §8 / WebAuthn-PRF v07 §"The cryptographic chain"). This
// is the reference producer for Test Vector Category 01 (TC01-02) + the §8.3
// wrap envelope. It is run ONCE; its output is committed to
// ../golden/kem-wrap.json and consumed by `crypto/tests/kem_wrap.rs`. It is
// NEVER a CI runtime dependency (Chris's S017 call: committed golden vectors,
// not a live subprocess).
//
//   cd gen && npm run gen:kem
//
// Why Node WebCrypto is the right oracle here: the SvelteKit web client
// (Phase 3) runs this exact chain in-browser via `crypto.subtle` —
// HKDF-SHA-256 then AES-256-GCM. Byte-for-byte agreement between WebCrypto and
// our RustCrypto reference impl is what proves real sign-up / sign-in will
// recover the same wrap key and decrypt the stored blob. (Independent of the
// RustCrypto family under test; same standards, different implementation.)
//
// Fully DETERMINISTIC — fixed PRF output + fixed PKCS#8 key + fixed IV — so the
// vector is reproducible and reviewable.

import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;
const utf8 = new TextEncoder();
const hex = (buf) => Buffer.from(buf).toString('hex');
const b64u = (buf) => Buffer.from(buf).toString('base64url');

// The version-tagged label (WebAuthn-PRF INV-7/8/9). PRF salt = SHA-256(LABEL);
// HKDF info = LABEL; AES-GCM AAD = LABEL.
const LABEL = 'signet-drive-kem-wrap-v1';

// Designated reference PRF output: the 32 bytes 0x00..0x1f. This is NOT captured
// from a real credential — the chain being pinned is HKDF -> W -> AES-256-GCM
// wrap; the PRF output is its (synthetic, obviously-a-fixture) input. A real
// authenticator's PRF output is opaque + per-credential; the deterministic
// property (TC01-03) is a WebAuthn guarantee, not a SigDrive construction.
const prfOutput = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) prfOutput[i] = i;

// W = HKDF-SHA-256(ikm = PRF output, salt = empty, info = utf8(LABEL), 32 bytes)
// — Envelope §8.2.
const ikm = await subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
const wBits = await subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode(LABEL) },
  ikm,
  256,
);
const w = new Uint8Array(wBits);

// The wrapped plaintext is the user's ECDH P-256 private key in PKCS#8 form (what
// `crypto.subtle.exportKey("pkcs8", ...)` yields, ~120 bytes). Imported from the
// published RFC 7518 Appendix C "Bob" P-256 key (fixed d/x/y) so the PKCS#8 bytes
// are deterministic.
const bobJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
  y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
  d: 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
  ext: true,
};
const ecdhPriv = await subtle.importKey(
  'jwk',
  bobJwk,
  { name: 'ECDH', namedCurve: 'P-256' },
  true,
  ['deriveBits'],
);
const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', ecdhPriv));

// Wrap: AES-256-GCM(key = W, iv, plaintext = PKCS#8, aad = utf8(LABEL)) —
// Envelope §8.3. WebCrypto returns ciphertext||tag; split for the {ct,tag} shape.
const iv = Buffer.from('0102030405060708090a0b0c', 'hex');
const wKey = await subtle.importKey('raw', w, 'AES-GCM', false, ['encrypt']);
const ctTag = new Uint8Array(
  await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8.encode(LABEL), tagLength: 128 },
    wKey,
    pkcs8,
  ),
);
const ct = ctTag.slice(0, -16);
const tag = ctTag.slice(-16);

process.stdout.write(
  `${JSON.stringify(
    {
      _comment:
        'GENERATED — do not hand-edit. Run `cd gen && npm run gen:kem`. Human-side KEM-key wrap chain (Envelope §8 / WebAuthn-PRF v07) via Node WebCrypto HKDF-SHA-256 + AES-256-GCM. Consumed by crypto/tests/kem_wrap.rs + Test Vector Category 01.',
      label: LABEL,
      kem_privkey_wrap: {
        description:
          'PRF output -> HKDF-SHA-256 W -> AES-256-GCM wrap of a PKCS#8 ECDH P-256 key (Envelope §8.2/§8.3). derive_wrap_key(prf_output)==W; wrap_kem_privkey(W, pkcs8, iv) produces {iv,ct,tag}; unwrap recovers pkcs8.',
        prf_output_hex: hex(prfOutput),
        expected_w_hex: hex(w),
        pkcs8_hex: hex(pkcs8),
        iv_b64u: b64u(iv),
        expected_ct_b64u: b64u(ct),
        expected_tag_b64u: b64u(tag),
      },
    },
    null,
    2,
  )}\n`,
);
