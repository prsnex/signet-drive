// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Human-side KEM-key wrap chain (Envelope §8 / WebAuthn-PRF v07): the chain that
// lets a human recover their ECDH KEM private key from a WebAuthn passkey. The
// passkey's 32-byte PRF output → HKDF-SHA-256 → 32-byte wrap key W (§8.2), which
// AES-256-GCM-wraps the PKCS#8 ECDH private key into {v,alg,iv,ct,tag} (§8.3).
//
// In production this runs entirely in the browser: the server never sees the PRF
// output, W, or the private key (INV-1..3, INV-13). Mirrors signet-crypto's
// kem_wrap.rs; composes the validated kdf (HKDF) + aead (AES-GCM) primitives and
// adds only the label constant + the on-the-wire shape — no new cryptography.
//
// The PRF eval salt (prf_salt = SHA-256(LABEL), INV-7) is a WebAuthn-ceremony
// input and lands with C1, not here.

import { aesGcmOpen, aesGcmSeal } from './aead';
import { b64uDecode, b64uEncode, concatBytes, utf8Encode, type Bytes } from './bytes';
import { InvalidInputError } from './errors';
import { hkdfSha256 } from './kdf';

const A256GCM = 'A256GCM';
const GCM_TAG_LEN = 16;
const EMPTY = new Uint8Array(0);

/** The version-tagged label scoping the wrap chain (WebAuthn-PRF INV-8/INV-9):
 *  both the HKDF `info` and the AES-256-GCM AAD. The `-v1` suffix is the
 *  migration hook — a future chain bumps to `-v2` and old blobs keep decrypting
 *  under `-v1` until a re-wrap runs. */
export const KEM_WRAP_LABEL = utf8Encode('signet-drive-kem-wrap-v1');

/** The fixed WebAuthn PRF eval salt: SHA-256(LABEL) (INV-7). The server sends it
 *  (base64url) as `prf.eval.first` for sign-in; the browser computes it for the
 *  signup-time PRF harvest. NOT the raw label — that is the INV-7 bug it prevents. */
export async function prfSalt(): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', KEM_WRAP_LABEL));
}

/** The human-side wrap blob (Envelope §8.3), stored opaquely server-side in
 *  `accounts.wrapped_kem_privkey_blob`. `ct` is the ciphertext WITHOUT the GCM
 *  tag (the tag is a sibling field); all three are base64url-no-pad. */
export interface KemPrivkeyWrap {
  v: number;
  alg: string;
  iv: string;
  ct: string;
  tag: string;
}

/** Derive the 32-byte wrap key W from a 32-byte WebAuthn PRF output (Envelope
 *  §8.2): HKDF-SHA-256(ikm = prfOutput, salt = empty, info = LABEL, 32). A
 *  non-32-byte PRF output is rejected rather than padded. */
export async function deriveWrapKey(prfOutput: Bytes): Promise<Bytes> {
  if (prfOutput.length !== 32) throw new InvalidInputError('prf output must be 32 bytes');
  return hkdfSha256(prfOutput, EMPTY, KEM_WRAP_LABEL, 32);
}

/** Wrap a PKCS#8-encoded ECDH private key under `wrapKey` with a caller-supplied
 *  12-byte `iv` (Envelope §8.3). AAD is the fixed LABEL. `iv` MUST be unique per
 *  `wrapKey` (fresh random per wrap event). */
export async function wrapKemPrivkey(
  wrapKey: Bytes,
  pkcs8: Bytes,
  iv: Bytes,
): Promise<KemPrivkeyWrap> {
  if (iv.length !== 12) throw new InvalidInputError('iv must be 12 bytes');
  const sealed = await aesGcmSeal(wrapKey, iv, pkcs8, KEM_WRAP_LABEL); // ct || tag
  const split = sealed.length - GCM_TAG_LEN;
  return {
    v: 1,
    alg: A256GCM,
    iv: b64uEncode(iv),
    ct: b64uEncode(sealed.slice(0, split)),
    tag: b64uEncode(sealed.slice(split)),
  };
}

/** Unwrap a {@link KemPrivkeyWrap} under `wrapKey`, recovering the PKCS#8 bytes
 *  (Envelope §8.5). Throws on a wrong key (wrong passkey/PRF output), tampered
 *  ciphertext, or AAD mismatch — the caller MUST NOT distinguish these. */
export async function unwrapKemPrivkey(wrapKey: Bytes, envelope: KemPrivkeyWrap): Promise<Bytes> {
  if (envelope.alg !== A256GCM) throw new InvalidInputError('unknown kem wrap alg');
  const iv = b64uDecode(envelope.iv);
  if (iv.length !== 12) throw new InvalidInputError('kem wrap iv must be 12 bytes');
  const tag = b64uDecode(envelope.tag);
  if (tag.length !== GCM_TAG_LEN) throw new InvalidInputError('kem wrap tag must be 16 bytes');
  const ctAndTag = concatBytes(b64uDecode(envelope.ct), tag);
  return aesGcmOpen(wrapKey, iv, ctAndTag, KEM_WRAP_LABEL);
}
