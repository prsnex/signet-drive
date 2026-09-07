// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// ECDH-ES+A256KW key wrapping (Envelope §5 DEK wrap + §7.2 metadata-key wrap).
// The composition step: a fresh ephemeral-static ECDH → Concat-KDF-SHA-256 (with
// the P-015 party_v binding) → AES-256 Key Wrap, serialized as the JOSE-shaped
// WrapEnvelope. Mirrors signet-crypto's wrap.rs; it reuses the validated
// ecdh / concatkdf / keywrap primitives and adds only the glue and the
// on-the-wire shape — no new cryptography.
//
// The DEK wrap and the metadata-key wrap are the SAME construction; they differ
// only in party_v: empty for a DEK, the 16-byte root_folder_id for a metadata
// key (P-015). The folder binding means a metadata-key blob moved to another
// folder derives a different KEK and fails AES-KW's integrity check.

import { b64uDecode, b64uEncode, concatBytes, type Bytes } from './bytes';
import { ecdhEsA256kwKek } from './concatkdf';
import { deriveZ, generateEphemeralKeypair, importEcdhPublicX963 } from './ecdh';
import { InvalidInputError } from './errors';
import { aesKwUnwrap, aesKwWrap } from './keywrap';
import { fingerprint } from './pubkey';

export const ECDH_ES_A256KW = 'ECDH-ES+A256KW';

/** The ephemeral public key in JWK form (RFC 7517 §3), as it appears in the
 *  wrap envelope's `epk` field. */
export interface EpkJwk {
  kty: string;
  crv: string;
  /** base64url(no-pad) of the 32-byte X coordinate. */
  x: string;
  /** base64url(no-pad) of the 32-byte Y coordinate. */
  y: string;
}

/** A wrapped-key envelope (Envelope §5 for a DEK, §7.2 for a metadata key —
 *  identical shape). Stored opaquely server-side; the server never parses it. */
export interface WrapEnvelope {
  v: number;
  alg: string;
  epk: EpkJwk;
  /** base64url(no-pad) of the 40-byte AES-KW output. */
  ct: string;
  /** Recipient KEM pubkey fingerprint, lowercase hex (routing only). */
  rfp: string;
}

const EMPTY = new Uint8Array(0);

/** Strictly parse an unknown value as a CLASSICAL wrap envelope: the exact
 *  field set — `ek` or any other extra field is rejected (the §5.2 symmetric
 *  validation / N5: no field-smuggling across algs; the deny_unknown_fields
 *  mirror of the Rust WrapEnvelope). The alg VALUE is checked at unwrap. */
export function parseWrapEnvelope(value: unknown): WrapEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new InvalidInputError('wrap envelope must be an object');
  }
  const v = value as Record<string, unknown>;
  if (Object.keys(v).sort().join(',') !== 'alg,ct,epk,rfp,v') {
    throw new InvalidInputError('wrap envelope must have exactly v/alg/epk/ct/rfp');
  }
  if (
    typeof v.v !== 'number' ||
    typeof v.alg !== 'string' ||
    typeof v.ct !== 'string' ||
    typeof v.rfp !== 'string'
  ) {
    throw new InvalidInputError('wrap envelope field types');
  }
  const epk = v.epk;
  if (typeof epk !== 'object' || epk === null || Array.isArray(epk)) {
    throw new InvalidInputError('wrap envelope epk');
  }
  const e = epk as Record<string, unknown>;
  if (Object.keys(e).sort().join(',') !== 'crv,kty,x,y') {
    throw new InvalidInputError('wrap envelope epk must have exactly kty/crv/x/y');
  }
  if (
    typeof e.kty !== 'string' ||
    typeof e.crv !== 'string' ||
    typeof e.x !== 'string' ||
    typeof e.y !== 'string'
  ) {
    throw new InvalidInputError('wrap envelope epk field types');
  }
  return {
    v: v.v,
    alg: v.alg,
    epk: { kty: e.kty, crv: e.crv, x: e.x, y: e.y },
    ct: v.ct,
    rfp: v.rfp,
  };
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
  return concatBytes(new Uint8Array([0x04]), x, y);
}

function epkFromX963(x963: Bytes): EpkJwk {
  if (x963.length !== 65 || x963[0] !== 0x04) {
    throw new InvalidInputError('x9.63 uncompressed point');
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: b64uEncode(x963.slice(1, 33)),
    y: b64uEncode(x963.slice(33, 65)),
  };
}

// --- unwrap (download / decrypt path) ---

/** Unwrap a DEK wrap with the recipient's ECDH private key (Envelope §5). */
export function unwrapDek(recipientPrivateKey: CryptoKey, envelope: WrapEnvelope): Promise<Bytes> {
  return unwrapWith(recipientPrivateKey, envelope, EMPTY);
}

/** Unwrap a metadata-key wrap. rootFolderId MUST match the folder the wrap was
 *  created for; a mismatch derives a different KEK and AES-KW rejects it (P-015). */
export function unwrapMetadataKey(
  recipientPrivateKey: CryptoKey,
  envelope: WrapEnvelope,
  rootFolderId: Bytes,
): Promise<Bytes> {
  if (rootFolderId.length !== 16) throw new InvalidInputError('root_folder_id must be 16 bytes');
  return unwrapWith(recipientPrivateKey, envelope, rootFolderId);
}

async function unwrapWith(
  recipientPrivateKey: CryptoKey,
  envelope: WrapEnvelope,
  partyV: Bytes,
): Promise<Bytes> {
  if (envelope.alg !== ECDH_ES_A256KW) throw new InvalidInputError('unknown wrap alg');
  const ephemeralPub = await importEcdhPublicX963(epkToX963(envelope.epk));
  const z = await deriveZ(recipientPrivateKey, ephemeralPub);
  const kek = await ecdhEsA256kwKek(z, partyV);
  const key = await aesKwUnwrap(kek, b64uDecode(envelope.ct));
  if (key.length !== 32) throw new InvalidInputError('unwrapped key is not 32 bytes');
  return key;
}

// --- wrap (upload / encrypt path) ---

/** Wrap a 32-byte DEK to a recipient's KEM public key (Envelope §5). No folder
 *  binding (the §4.1 file envelope binds content to file_id via AAD). */
export function wrapDek(recipientPubX963: Bytes, dek: Bytes): Promise<WrapEnvelope> {
  return wrapTo(recipientPubX963, dek, EMPTY);
}

/** Wrap a 32-byte metadata key to a recipient, bound to rootFolderId (P-015). */
export function wrapMetadataKey(
  recipientPubX963: Bytes,
  metadataKey: Bytes,
  rootFolderId: Bytes,
): Promise<WrapEnvelope> {
  if (rootFolderId.length !== 16) throw new InvalidInputError('root_folder_id must be 16 bytes');
  return wrapTo(recipientPubX963, metadataKey, rootFolderId);
}

async function wrapTo(recipientPubX963: Bytes, key: Bytes, partyV: Bytes): Promise<WrapEnvelope> {
  if (key.length !== 32) throw new InvalidInputError('wrapped key must be 32 bytes');
  const recipientPub = await importEcdhPublicX963(recipientPubX963);
  const ephemeral = await generateEphemeralKeypair();
  const z = await deriveZ(ephemeral.privateKey, recipientPub);
  const kek = await ecdhEsA256kwKek(z, partyV);
  const wrapped = await aesKwWrap(kek, key);
  const ephemeralPubX963 = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeral.publicKey),
  );
  return {
    v: 1,
    alg: ECDH_ES_A256KW,
    epk: epkFromX963(ephemeralPubX963),
    ct: b64uEncode(wrapped),
    rfp: await fingerprint(recipientPubX963),
  };
}

// --- self-public-key verification (pre-launch crypto review #5) ---

/** Verify that a NON-extractable KEM private key is the counterpart of a claimed
 *  public key — without needing the private key to be extractable. Wraps a random
 *  probe to `publicX963` (ephemeral-static ECDH → Concat-KDF KEK → AES-KW) then
 *  unwraps it with `privateKey`: the round-trip recovers the probe iff the two are
 *  an ECDH pair, because a mismatched public key derives a different KEK and
 *  AES-KW's integrity check fails on unwrap.
 *
 *  This is the only local check available at sign-in, where the self KEM public
 *  key is server-supplied while the private key is recovered NON-extractable from
 *  the PRF-wrapped blob (so WebCrypto cannot re-derive its public key for a direct
 *  comparison). It defends the self-wrap path against a malicious server returning
 *  a substituted self-public-key (which would otherwise wrap the user's own new
 *  uploads to the attacker). Fails closed: any error (malformed key, KEK mismatch)
 *  returns false. */
export async function kemKeypairMatches(
  privateKey: CryptoKey,
  publicX963: Bytes,
): Promise<boolean> {
  const probe = crypto.getRandomValues(new Uint8Array(32)) as Bytes;
  try {
    const envelope = await wrapDek(publicX963, probe);
    const recovered = await unwrapDek(privateKey, envelope);
    return recovered.length === probe.length && recovered.every((b, i) => b === probe[i]);
  } catch {
    return false;
  }
}
