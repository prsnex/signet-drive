// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// P-256 public-key fingerprint: the lowercase-hex SHA-256 of the DER-encoded
// SubjectPublicKeyInfo — NOT the raw 65-byte X9.63 point. This matches
// signet-crypto's pubkey::fingerprint and the KEM-wrap routing field (`rfp`).
// WebCrypto's exportKey('spki') yields the same standard DER bytes.

import { hexEncode, type Bytes } from './bytes';
import { importEcdhPublicX963 } from './ecdh';

export async function fingerprint(pubX963: Bytes): Promise<string> {
  const key = await importEcdhPublicX963(pubX963);
  const spki = await crypto.subtle.exportKey('spki', key);
  const digest = await crypto.subtle.digest('SHA-256', spki);
  return hexEncode(new Uint8Array(digest));
}

/** The PQ-key fingerprint convention (PQR §8.5, signet-crypto's
 *  `fingerprint_raw`): lowercase-hex SHA-256 over the RAW FIPS 203/204 key
 *  bytes — ML-KEM/ML-DSA keys have no SPKI form in our stack, a deliberate,
 *  named split from the classical convention above. */
export async function fingerprintRaw(raw: Bytes): Promise<string> {
  return hexEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)));
}
