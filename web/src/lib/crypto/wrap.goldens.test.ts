// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { aesGcmOpen } from './aead';
import { b64uDecode, concatBytes, hexDecode, hexEncode, utf8Encode } from './bytes';
import { importEcdhPrivateJwk } from './ecdh';
import { unwrapDek, unwrapMetadataKey, type WrapEnvelope } from './wrap';

// The differential harness. It loads the SAME committed golden the Rust tests
// load (crypto/tests/golden_vectors.rs) — vectors produced by panva/jose, an
// independent JOSE implementation. Mirroring golden_vectors.rs's tier-3 trick:
// panva/jose's CEK is internal, so we prove our unwrap recovered the EXACT CEK
// by AES-256-GCM-decrypting the JWE payload with it — only the right CEK yields
// the known plaintext. This validates the whole composition (ECDH P-256 →
// Concat-KDF-SHA-256 with the A256KW constants → AES-KW), not self-consistency.

const text = (b: Uint8Array) => new TextDecoder().decode(b);

interface Jwe {
  ciphertext: string;
  iv: string;
  tag: string;
  encrypted_key: string;
  protected: string;
}
interface RecipientJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d: string;
}
interface Golden {
  ecdh_es_a256kw_dek: { recipient_jwk: RecipientJwk; payload_utf8: string; jwe: Jwe };
  ecdh_es_a256kw_metadata: {
    recipient_jwk: RecipientJwk;
    payload_utf8: string;
    root_folder_id_hex: string;
    jwe: Jwe;
  };
}

const golden: Golden = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL('../../../../docs/design/test-vectors/golden/wrap-chain.json', import.meta.url),
    ),
    'utf8',
  ),
);

interface ProtectedHeader {
  alg: string;
  epk: { kty: string; crv: string; x: string; y: string };
  apv?: string;
}

/** Decompose a committed JWE into our WrapEnvelope plus the content-layer pieces
 *  needed to confirm the recovered CEK (mirrors golden_vectors.rs::jwe_pieces). */
function jwePieces(jwe: Jwe) {
  const header = JSON.parse(text(b64uDecode(jwe.protected))) as ProtectedHeader;
  const envelope: WrapEnvelope = {
    v: 1,
    alg: header.alg,
    epk: { kty: header.epk.kty, crv: header.epk.crv, x: header.epk.x, y: header.epk.y },
    ct: jwe.encrypted_key,
    rfp: '',
  };
  return {
    envelope,
    apv: header.apv === undefined ? undefined : b64uDecode(header.apv),
    iv: b64uDecode(jwe.iv),
    ctAndTag: concatBytes(b64uDecode(jwe.ciphertext), b64uDecode(jwe.tag)),
    // RFC 7516 §5.1: the JWE content AAD is the ASCII of the base64url protected header.
    aad: utf8Encode(jwe.protected),
  };
}

describe('ECDH-ES+A256KW unwrap — differential vs committed panva/jose golden', () => {
  it('DEK wrap (no apv): unwrap recovers the CEK that decrypts the JWE payload', async () => {
    const v = golden.ecdh_es_a256kw_dek;
    const p = jwePieces(v.jwe);
    expect(p.apv).toBeUndefined();
    const priv = await importEcdhPrivateJwk(v.recipient_jwk);
    const cek = await unwrapDek(priv, p.envelope);
    const plaintext = await aesGcmOpen(cek, p.iv, p.ctAndTag, p.aad);
    expect(text(plaintext)).toBe(v.payload_utf8);
  });

  it('metadata wrap (apv = root_folder_id, P-015): unwrap recovers the CEK', async () => {
    const v = golden.ecdh_es_a256kw_metadata;
    const p = jwePieces(v.jwe);
    const apv = p.apv;
    if (apv === undefined) throw new Error('metadata golden is missing apv');
    expect(hexEncode(apv)).toBe(v.root_folder_id_hex);
    const priv = await importEcdhPrivateJwk(v.recipient_jwk);
    const cek = await unwrapMetadataKey(priv, p.envelope, hexDecode(v.root_folder_id_hex));
    const plaintext = await aesGcmOpen(cek, p.iv, p.ctAndTag, p.aad);
    expect(text(plaintext)).toBe(v.payload_utf8);
  });

  it('P-015: unwrapping the metadata wrap under a wrong root_folder_id is rejected', async () => {
    const v = golden.ecdh_es_a256kw_metadata;
    const p = jwePieces(v.jwe);
    const priv = await importEcdhPrivateJwk(v.recipient_jwk);
    const wrongFolder = hexDecode('ffffffff00004000800000000000000a');
    await expect(unwrapMetadataKey(priv, p.envelope, wrongFolder)).rejects.toThrow();
  });
});
