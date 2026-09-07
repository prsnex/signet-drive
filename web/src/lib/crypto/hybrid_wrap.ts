// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Hybrid content-wrap — `ECDH-ES+ML-KEM-1024+A256KW` (PQR Crypto Spec §3–§5).
//
// Wraps a 32-byte key (a file DEK, or a per-folder metadata key) to a
// recipient's HYBRID KEM public keys — `rk_ec` (P-256, X9.63) + `rk_pq`
// (ML-KEM-1024 encapsulation key) — via the NIST SP 800-227 §4.6 two-step
// HKDF KDM:
//
//   IKM = Z_ecdh ‖ Z_mlkem                    (the SP 800-56A secret first, §4.2)
//   PRK = HKDF-Extract(salt = zero-length, IKM)
//   KEK = HKDF-Expand(PRK, FixedInfo, 32)     (FixedInfo per §4.3)
//   wk  = AES-256-KW(KEK, key)                (RFC 3394, 40 bytes)
//
// This module byte-matches crypto/src/hybrid_wrap.rs (the Rust reference) —
// the two-step choice is exactly WHY hybrid runs on native crypto here too:
// WebCrypto has native HKDF (kdf.ts) where Concat-KDF is library-JS (§4.2).
// The tests pin the same A3-co-signed KeyCombine KAT vectors the Rust suite
// pins, plus the committed cross-surface goldens (hybrid-crossover.json).
//
// What is bound, and why (§4.4): FixedInfo binds the alg-ID, the ML-KEM
// ciphertext `ek`, the ephemeral `epk`, and BOTH recipient public keys.
// Binding the ciphertexts is not downgrade-hygiene alone — per SP 800-227
// §4.6.3 a secrets-only combiner does not preserve IND-CCA security, so
// `ek ∈ FixedInfo` is what makes the composite generically IND-CCA. Binding
// the recipient keys defeats cross-recipient block-swapping (N4). The alg-ID
// in FixedInfo + per-alg field validation is the downgrade defense (N1/N2).
// There is NO `enc` field (§4.3, decided S104).
//
// Like the Rust module, the *-FromSecrets seams take the two shared secrets as
// inputs (the KAT-pinnable correctness core: pure HKDF + AES-KW + byte
// assembly); the full wrap/unwrap flows below them drive WebCrypto ECDH +
// the wasm ML-KEM (mlkem.ts) and hand the secrets in.

import {
  b64uDecode,
  b64uEncode,
  concatBytes,
  hexEncode,
  u32be,
  utf8Encode,
  type Bytes,
} from './bytes';
import { deriveZ, generateEphemeralKeypair, importEcdhPublicX963 } from './ecdh';
import { InvalidInputError } from './errors';
import { hkdfSha256 } from './kdf';
import { aesKwUnwrap, aesKwWrap } from './keywrap';
import { mlkemDecapsulate, mlkemEncapsulate, MLKEM_CT_LEN, MLKEM_EK_LEN } from './mlkem';
import type { EpkJwk } from './wrap';

export const ECDH_ES_MLKEM1024_A256KW = 'ECDH-ES+ML-KEM-1024+A256KW';

/** The derived KEK length in bits, bound into FixedInfo's `L` field (§4.3). */
const KEYDATALEN_BITS = 256;

const EMPTY = new Uint8Array(0);

/** A hybrid wrapped-key envelope (PQR Spec §5.2). Distinct shape from the
 *  classical WrapEnvelope: it carries BOTH `epk` (the classical ephemeral
 *  public key) and `ek` (the ML-KEM ciphertext), plus `wk` (the AES-KW output
 *  — a disambiguated name, never a bare `ct` in an object that also holds a
 *  KEM ciphertext). Stored opaquely server-side; the server never parses it. */
export interface HybridWrapEnvelope {
  v: number;
  alg: string;
  epk: EpkJwk;
  /** base64url(no-pad) of the 1568-byte ML-KEM-1024 ciphertext. */
  ek: string;
  /** base64url(no-pad) of the 40-byte AES-KW output. */
  wk: string;
  /** Recipient HYBRID KEM pair-fingerprint (§8.5), lowercase hex. */
  rfp: string;
}

/** Append one length-prefixed field: big-endian u32 length ‖ bytes (§4.3 —
 *  the same JOSE-Datum encoding the classical Concat-KDF uses, so FixedInfo
 *  has no field-boundary ambiguity). */
function lengthPrefixed(data: Bytes): Bytes {
  return concatBytes(u32be(data.length), data);
}

/** Build the SP 800-227 §4.6 FixedInfo (§4.3), length-prefixed fields in this
 *  exact order: alg ‖ epk ‖ ek ‖ rk_ec ‖ rk_pq ‖ L(=256) ‖ party_v.
 *  `party_v` is empty for a file-DEK wrap, or the 16-byte root_folder_id for
 *  a metadata-key wrap (the P-015 folder binding; N7). Pure encoder — the
 *  wrap/unwrap seams own validation (the KAT pins this over synthetic bytes). */
export function buildFixedInfo(
  epkX963: Bytes,
  ek: Bytes,
  rkEcX963: Bytes,
  rkPq: Bytes,
  partyV: Bytes,
): Bytes {
  return concatBytes(
    lengthPrefixed(utf8Encode(ECDH_ES_MLKEM1024_A256KW)),
    lengthPrefixed(epkX963),
    lengthPrefixed(ek),
    lengthPrefixed(rkEcX963),
    lengthPrefixed(rkPq),
    lengthPrefixed(u32be(KEYDATALEN_BITS)),
    lengthPrefixed(partyV),
  );
}

/** The SP 800-227 §4.6.2 KDM (§4.2): IKM = Z_ecdh ‖ Z_mlkem (the SP 800-56A
 *  secret FIRST, normative), zero-length HKDF-Extract salt (RFC 5869 §2.2 →
 *  32 zero bytes), FixedInfo as the Expand info, L = 32. Both shared secrets
 *  enter Extract as IKM; neither appears in the salt or FixedInfo.
 *  Zeroization is best-effort across WebCrypto (the §4.6 web posture). */
export async function contentWrapKek(
  zEcdh: Bytes,
  zMlkem: Bytes,
  fixedInfo: Bytes,
): Promise<Bytes> {
  if (zEcdh.length !== 32 || zMlkem.length !== 32) {
    throw new InvalidInputError('shared secrets must be 32 bytes');
  }
  const ikm = concatBytes(zEcdh, zMlkem);
  try {
    return await hkdfSha256(ikm, EMPTY, fixedInfo, 32);
  } finally {
    ikm.fill(0);
  }
}

/** The recipient HYBRID KEM pair-fingerprint (§8.5): ONE lowercase-hex SHA-256
 *  committing to BOTH recipient KEM public keys — SHA-256(lp(rk_ec)‖lp(rk_pq)).
 *  Because it commits to both keys, a PQ-stripped directory bundle changes it
 *  (the transparency-layer detection property). Inputs are validated to the
 *  canonical §4.3 encodings — a non-canonical encoding would silently produce
 *  a fingerprint no other party derives. */
export async function hybridRfp(rkEcX963: Bytes, rkPq: Bytes): Promise<string> {
  await validateRecipientKeys(rkEcX963, rkPq);
  const lp = concatBytes(lengthPrefixed(rkEcX963), lengthPrefixed(rkPq));
  return hexEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', lp)));
}

/** Validate the recipient's hybrid KEM public keys are the exact §4.3
 *  canonical encodings: rk_ec a 65-byte X9.63 UNCOMPRESSED on-curve P-256
 *  point; rk_pq a 1568-byte ML-KEM-1024 encapsulation key. (WebCrypto's raw
 *  import is the on-curve check.) */
async function validateRecipientKeys(rkEcX963: Bytes, rkPq: Bytes): Promise<void> {
  if (rkEcX963.length !== 65 || rkEcX963[0] !== 0x04) {
    throw new InvalidInputError('rk_ec must be a 65-byte uncompressed x9.63 point');
  }
  try {
    await importEcdhPublicX963(rkEcX963);
  } catch {
    throw new InvalidInputError('rk_ec not on curve');
  }
  if (rkPq.length !== MLKEM_EK_LEN) {
    throw new InvalidInputError('rk_pq must be a 1568-byte ml-kem-1024 encapsulation key');
  }
}

/** party_v is exactly one of the two legal §4.3 values: empty (a file-DEK
 *  wrap) or 16 bytes (a metadata-key wrap's root_folder_id). */
function validatePartyV(partyV: Bytes): void {
  if (partyV.length !== 0 && partyV.length !== 16) {
    throw new InvalidInputError('party_v must be empty or a 16-byte root_folder_id');
  }
}

function epkToX963(epk: EpkJwk): Bytes {
  if (epk.kty !== 'EC' || epk.crv !== 'P-256') {
    throw new InvalidInputError('epk must be EC P-256');
  }
  const x = b64uDecode(epk.x);
  const y = b64uDecode(epk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new InvalidInputError('epk coordinates must be 32 bytes');
  }
  return concatBytes(new Uint8Array([0x04]) as Bytes, x, y);
}

function epkFromX963(x963: Bytes): EpkJwk {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: b64uEncode(x963.slice(1, 33) as Bytes),
    y: b64uEncode(x963.slice(33, 65) as Bytes),
  };
}

/** Canonicalize a caller-supplied ephemeral public key to the uncompressed
 *  X9.63 bytes both sides bind (§4.3): import (the on-curve check) and
 *  re-export raw. */
async function canonicalEpk(epkX963: Bytes): Promise<Bytes> {
  let key: CryptoKey;
  try {
    key = await importEcdhPublicX963(epkX963);
  } catch {
    throw new InvalidInputError('epk not on curve');
  }
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

/** Strictly parse an unknown value as a §5.2 hybrid recipient block: the
 *  exact field set, no extras (the deny_unknown_fields mirror — N1/N2/N5
 *  shape defense), with `epk` itself field-exact. The alg VALUE is checked at
 *  unwrap (the code path is selected from `alg` alone, never field presence). */
export function parseHybridWrapEnvelope(value: unknown): HybridWrapEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new InvalidInputError('hybrid envelope must be an object');
  }
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v).sort();
  if (keys.join(',') !== 'alg,ek,epk,rfp,v,wk') {
    throw new InvalidInputError('hybrid envelope must have exactly v/alg/epk/ek/wk/rfp');
  }
  if (typeof v.v !== 'number' || typeof v.alg !== 'string' || typeof v.ek !== 'string') {
    throw new InvalidInputError('hybrid envelope field types');
  }
  if (typeof v.wk !== 'string' || typeof v.rfp !== 'string') {
    throw new InvalidInputError('hybrid envelope field types');
  }
  const epk = v.epk;
  if (typeof epk !== 'object' || epk === null || Array.isArray(epk)) {
    throw new InvalidInputError('hybrid envelope epk');
  }
  const e = epk as Record<string, unknown>;
  if (Object.keys(e).sort().join(',') !== 'crv,kty,x,y') {
    throw new InvalidInputError('hybrid envelope epk must have exactly kty/crv/x/y');
  }
  if (
    typeof e.kty !== 'string' ||
    typeof e.crv !== 'string' ||
    typeof e.x !== 'string' ||
    typeof e.y !== 'string'
  ) {
    throw new InvalidInputError('hybrid envelope epk field types');
  }
  return {
    v: v.v,
    alg: v.alg,
    epk: { kty: e.kty, crv: e.crv, x: e.x, y: e.y },
    ek: v.ek,
    wk: v.wk,
    rfp: v.rfp,
  };
}

// --- the from-secrets seams (the KAT-pinnable core, mirroring the Rust API) ---

/** Assemble a hybrid recipient block from already-computed shared secrets and
 *  wrap inputs (§4.5 wrap). The caller computes Z_ecdh (ephemeral-static
 *  ECDH) and (Z_mlkem, ek) (ML-KEM-1024 encaps); this runs the combiner +
 *  AES-KW and serializes the envelope. */
export async function hybridWrapFromSecrets(
  zEcdh: Bytes,
  zMlkem: Bytes,
  epkX963: Bytes,
  ek: Bytes,
  rkEcX963: Bytes,
  rkPq: Bytes,
  key: Bytes,
  partyV: Bytes,
): Promise<HybridWrapEnvelope> {
  await validateRecipientKeys(rkEcX963, rkPq);
  validatePartyV(partyV);
  if (ek.length !== MLKEM_CT_LEN) throw new InvalidInputError('ml-kem ciphertext length');
  if (key.length !== 32) throw new InvalidInputError('wrapped key must be 32 bytes');
  const epkCanon = await canonicalEpk(epkX963);
  const fixedInfo = buildFixedInfo(epkCanon, ek, rkEcX963, rkPq, partyV);
  const kek = await contentWrapKek(zEcdh, zMlkem, fixedInfo);
  const wk = await aesKwWrap(kek, key);
  kek.fill(0);
  return {
    v: 1,
    alg: ECDH_ES_MLKEM1024_A256KW,
    epk: epkFromX963(epkCanon),
    ek: b64uEncode(ek),
    wk: b64uEncode(wk),
    rfp: await hybridRfp(rkEcX963, rkPq),
  };
}

/** Unwrap a hybrid recipient block given the two shared secrets (§5.3). The
 *  recipient supplies their own static KEM public keys to reconstruct the
 *  FixedInfo — the recipient binding (N4). `party_v` MUST match the wrap-time
 *  value or AES-KW's integrity check rejects (N7). The code path is selected
 *  from `alg` ALONE (§5.2): any alg but the hybrid one is rejected before any
 *  key material is derived. AES-KW integrity failure is the sole tamper
 *  signal (§10) — a tampered `ek` decapsulates to a pseudorandom secret and
 *  fails HERE, never at decap. */
export async function hybridUnwrapFromSecrets(
  zEcdh: Bytes,
  zMlkem: Bytes,
  envelope: HybridWrapEnvelope,
  rkEcX963: Bytes,
  rkPq: Bytes,
  partyV: Bytes,
): Promise<Bytes> {
  if (envelope.alg !== ECDH_ES_MLKEM1024_A256KW) {
    throw new InvalidInputError('unknown wrap alg');
  }
  await validateRecipientKeys(rkEcX963, rkPq);
  validatePartyV(partyV);
  const epkX963 = epkToX963(envelope.epk);
  const ek = b64uDecode(envelope.ek);
  if (ek.length !== MLKEM_CT_LEN) throw new InvalidInputError('ml-kem ciphertext length');
  const fixedInfo = buildFixedInfo(epkX963, ek, rkEcX963, rkPq, partyV);
  const kek = await contentWrapKek(zEcdh, zMlkem, fixedInfo);
  try {
    const key = await aesKwUnwrap(kek, b64uDecode(envelope.wk));
    if (key.length !== 32) throw new InvalidInputError('unwrapped key is not 32 bytes');
    return key;
  } finally {
    kek.fill(0);
  }
}

// --- the full flows (WebCrypto ECDH + wasm ML-KEM, §4.5/§5.3) ---

/** Wrap a 32-byte key to a recipient's hybrid KEM public keys: fresh
 *  ephemeral P-256 + ML-KEM-1024 encaps, then the from-secrets seam. */
async function hybridWrapTo(
  rkEcX963: Bytes,
  rkPq: Bytes,
  key: Bytes,
  partyV: Bytes,
): Promise<HybridWrapEnvelope> {
  await validateRecipientKeys(rkEcX963, rkPq);
  const recipientPub = await importEcdhPublicX963(rkEcX963);
  const ephemeral = await generateEphemeralKeypair();
  const zEcdh = await deriveZ(ephemeral.privateKey, recipientPub);
  const { ct: ek, ss: zMlkem } = await mlkemEncapsulate(rkPq);
  const epkX963 = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  try {
    return await hybridWrapFromSecrets(zEcdh, zMlkem, epkX963, ek, rkEcX963, rkPq, key, partyV);
  } finally {
    zEcdh.fill(0);
    zMlkem.fill(0);
  }
}

/** Wrap a 32-byte DEK to a recipient's hybrid KEM public keys (§5.2; no
 *  folder binding — the file envelope binds content to file_id via AAD). */
export function hybridWrapDek(
  rkEcX963: Bytes,
  rkPq: Bytes,
  dek: Bytes,
): Promise<HybridWrapEnvelope> {
  return hybridWrapTo(rkEcX963, rkPq, dek, EMPTY);
}

/** Wrap a 32-byte metadata key, bound to rootFolderId (P-015 / N7). */
export function hybridWrapMetadataKey(
  rkEcX963: Bytes,
  rkPq: Bytes,
  metadataKey: Bytes,
  rootFolderId: Bytes,
): Promise<HybridWrapEnvelope> {
  if (rootFolderId.length !== 16) throw new InvalidInputError('root_folder_id must be 16 bytes');
  return hybridWrapTo(rkEcX963, rkPq, metadataKey, rootFolderId);
}

/** Recipient-side unwrap: Z_ecdh from the session's non-extractable ECDH
 *  private key (WebCrypto), Z_mlkem from the session's ML-KEM seed (wasm
 *  decap — the §7 custody model), then the from-secrets seam. */
async function hybridUnwrapWith(
  recipientEcdhKey: CryptoKey,
  mlkemSeed: Bytes,
  envelope: HybridWrapEnvelope,
  rkEcX963: Bytes,
  rkPq: Bytes,
  partyV: Bytes,
): Promise<Bytes> {
  if (envelope.alg !== ECDH_ES_MLKEM1024_A256KW) {
    throw new InvalidInputError('unknown wrap alg');
  }
  const ephemeralPub = await importEcdhPublicX963(epkToX963(envelope.epk));
  const zEcdh = await deriveZ(recipientEcdhKey, ephemeralPub);
  const ek = b64uDecode(envelope.ek);
  if (ek.length !== MLKEM_CT_LEN) throw new InvalidInputError('ml-kem ciphertext length');
  const zMlkem = await mlkemDecapsulate(mlkemSeed, ek);
  try {
    return await hybridUnwrapFromSecrets(zEcdh, zMlkem, envelope, rkEcX963, rkPq, partyV);
  } finally {
    zEcdh.fill(0);
    zMlkem.fill(0);
  }
}

/** Unwrap a hybrid DEK wrap (§5.3). */
export function hybridUnwrapDek(
  recipientEcdhKey: CryptoKey,
  mlkemSeed: Bytes,
  envelope: HybridWrapEnvelope,
  rkEcX963: Bytes,
  rkPq: Bytes,
): Promise<Bytes> {
  return hybridUnwrapWith(recipientEcdhKey, mlkemSeed, envelope, rkEcX963, rkPq, EMPTY);
}

/** Unwrap a hybrid metadata-key wrap. rootFolderId MUST match the folder the
 *  wrap was created for (P-015 / N7). */
export function hybridUnwrapMetadataKey(
  recipientEcdhKey: CryptoKey,
  mlkemSeed: Bytes,
  envelope: HybridWrapEnvelope,
  rkEcX963: Bytes,
  rkPq: Bytes,
  rootFolderId: Bytes,
): Promise<Bytes> {
  if (rootFolderId.length !== 16) throw new InvalidInputError('root_folder_id must be 16 bytes');
  return hybridUnwrapWith(recipientEcdhKey, mlkemSeed, envelope, rkEcX963, rkPq, rootFolderId);
}
