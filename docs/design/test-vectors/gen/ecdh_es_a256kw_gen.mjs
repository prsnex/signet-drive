// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//
// Generates the committed golden vectors for the B1 wrap chain. This is the
// tier-3 (independent JOSE library) + tier-4 (our novel bytes) reference
// producer. It is run ONCE; its output is committed to ../golden/wrap-chain.json
// and consumed by `crypto/tests/golden_vectors.rs`. It is NEVER a CI runtime
// dependency (Chris's S017 call: committed golden vectors, not a live subprocess).
//
//   cd gen && npm install && npm run gen
//
// Independence: panva/jose (pure-JS, Node WebCrypto lineage) implements the full
// ECDH-ES+A256KW JOSE composition — a different codebase + language from the
// RustCrypto impl under test, so agreement is genuine conformance evidence. The
// file-envelope reference uses Node WebCrypto AES-256-GCM directly.

import * as jose from 'jose';
import { webcrypto } from 'node:crypto';

const utf8 = new TextEncoder();
const hex = (buf) => Buffer.from(buf).toString('hex');

// RFC 7518 Appendix C consumer ("Bob") P-256 key — a published, recognizable
// recipient keypair (including the private scalar `d`).
const recipientJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
  y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
  d: 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
};
const recipientPub = await jose.importJWK(
  { kty: recipientJwk.kty, crv: recipientJwk.crv, x: recipientJwk.x, y: recipientJwk.y },
  'ECDH-ES+A256KW',
);

// Wrap `payload` to the recipient with ECDH-ES+A256KW (random ephemeral, as JOSE
// does it). `apv` (a Uint8Array) binds the P-015 folder context. Returns the
// flattened JWE: { protected, encrypted_key, iv, ciphertext, tag }. The CEK that
// JOSE generated is recoverable only by unwrapping `encrypted_key` — which is
// exactly what the Rust test does, then it AES-GCM-opens the payload to prove it
// recovered the right CEK.
async function joseWrap(payload, apv) {
  const e = new jose.FlattenedEncrypt(utf8.encode(payload)).setProtectedHeader({
    alg: 'ECDH-ES+A256KW',
    enc: 'A256GCM',
  });
  if (apv) e.setKeyManagementParameters({ apv });
  return e.encrypt(recipientPub);
}

const dekPayload = 'signet-drive ECDH-ES+A256KW DEK conformance vector';
const ecdh_es_a256kw_dek = {
  description:
    'DEK wrap (no apv). Rust unwrap_dek(recipient.d, {epk, ct=encrypted_key}) must recover the CEK that AES-256-GCM-decrypts the JWE payload.',
  recipient_jwk: recipientJwk,
  payload_utf8: dekPayload,
  jwe: await joseWrap(dekPayload, undefined),
};

// P-015: apv = root_folder_id (16-byte UUID). panva/jose folds apv into the
// Concat-KDF PartyVInfo, exactly as our wrap_metadata_key does.
const rootFolderId = Buffer.from('aaaaaaaa00004000800000000000000a', 'hex');
const metaPayload = 'signet-drive metadata-key (P-015 apv) conformance vector';
const ecdh_es_a256kw_metadata = {
  description:
    'Metadata-key wrap with apv=root_folder_id (P-015). Rust unwrap_metadata_key(recipient.d, jwe, root_folder_id) must recover the CEK.',
  recipient_jwk: recipientJwk,
  root_folder_id_hex: hex(rootFolderId),
  payload_utf8: metaPayload,
  jwe: await joseWrap(metaPayload, rootFolderId),
};

// Tier-4: the single-PUT file envelope (Cat 02 TC02-01). AES-256-GCM via Node
// WebCrypto (independent of RustCrypto); we assemble the [magic][alg][IV] frame.
const sha256 = async (b) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', b));
const dek = await sha256(utf8.encode('test-dek-tc02-01'));
const iv = Buffer.from('0102030405060708090a0b0c', 'hex');
const fileId = Buffer.from('00000000000040008000000000000111', 'hex');
const plaintext = 'hello signet';
const aesKey = await webcrypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['encrypt']);
const ctTag = new Uint8Array(
  await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: fileId, tagLength: 128 },
    aesKey,
    utf8.encode(plaintext),
  ),
);
const envelope = Buffer.concat([Buffer.from([0x01, 0x01]), iv, Buffer.from(ctTag)]);
const file_envelope_cat02 = {
  description:
    'Single-PUT file envelope (Cat 02 TC02-01): [0x01 magic][0x01 alg][12 IV][ct][16 tag], AAD=file_id. seal_file(..) must produce envelope_hex byte-for-byte.',
  dek_hex: hex(dek),
  iv_hex: hex(iv),
  file_id_hex: hex(fileId),
  plaintext_utf8: plaintext,
  envelope_hex: hex(envelope),
};

process.stdout.write(
  JSON.stringify(
    {
      _comment:
        'GENERATED — do not hand-edit. Run `cd gen && npm install && npm run gen`. tier-3 (ECDH-ES+A256KW) via panva/jose; tier-4 (file envelope) via Node WebCrypto AES-GCM. Consumed by crypto/tests/golden_vectors.rs.',
      jose_lib: 'panva/jose',
      ecdh_es_a256kw_dek,
      ecdh_es_a256kw_metadata,
      file_envelope_cat02,
    },
    null,
    2,
  ) + '\n',
);
