// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// KEM keypair lifecycle for the human-side wrap chain (WebAuthn-PRF v07 §7/§8,
// sign-in §7). At signup the ECDH P-256 keypair is generated extractable ONLY so
// the private key can be exported to PKCS#8 and wrapped under W (INV-12); the
// CryptoKey itself is discarded. On sign-in the recovered PKCS#8 is re-imported
// NON-extractable for session use — it can derive shared secrets (DEK unwrap) but
// can never be re-exported.

import type { Bytes } from './crypto/bytes';

const P256: EcKeyImportParams = { name: 'ECDH', namedCurve: 'P-256' };

export interface GeneratedKemKeypair {
  /** PKCS#8 of the ECDH private key — wrapped under W at signup, then discarded. */
  privatePkcs8: Bytes;
  /** X9.63 uncompressed public key (`0x04 ‖ X ‖ Y`, 65 bytes) — sent to the server. */
  publicX963: Bytes;
}

/** Generate a fresh ECDH P-256 KEM keypair and export both encodings. Extractable
 *  only to permit the PKCS#8 export for wrapping (INV-12); the private CryptoKey is
 *  not returned and falls out of scope after wrapping. */
export async function generateKemKeypair(): Promise<GeneratedKemKeypair> {
  const pair = await crypto.subtle.generateKey(P256, true, ['deriveBits']);
  const privatePkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const publicX963 = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { privatePkcs8, publicX963 };
}

/** Re-import a recovered PKCS#8 ECDH private key NON-extractable for session use
 *  (sign-in §7 / INV-12): usable for `deriveBits` (DEK unwrap), never re-exportable.
 *  This is the session's decryption capability that C2–C4 depend on. */
export function importKemPrivateNonExtractable(pkcs8: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', pkcs8, P256, false, ['deriveBits']);
}
