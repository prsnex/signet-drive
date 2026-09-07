// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// ECDH P-256 key agreement (Envelope §5). The shared secret Z is the 32-byte
// x-coordinate of the shared point — exactly what WebCrypto deriveBits returns,
// matching signet-crypto's ecdh_p256 (p256 raw_secret_bytes).

import type { Bytes } from './bytes';

const P256: EcKeyImportParams = { name: 'ECDH', namedCurve: 'P-256' };

/** Import a recipient/ephemeral public key from a 65-byte X9.63 uncompressed
 *  point (`0x04 ‖ X ‖ Y`). Extractable so it can be re-exported for SPKI
 *  fingerprinting; ECDH public keys carry no key usages. */
export function importEcdhPublicX963(pubX963: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', pubX963, P256, true, []);
}

export function importEcdhPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, P256, true, []);
}

/** Import a recipient private key from a JWK (`d` present). Non-extractable;
 *  usable only to derive the shared secret. */
export function importEcdhPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, P256, false, ['deriveBits']);
}

/** Z = ECDH(privateKey, peerPublic): the 32-byte shared-point x-coordinate. */
export async function deriveZ(privateKey: CryptoKey, peerPublic: CryptoKey): Promise<Bytes> {
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublic },
    privateKey,
    256,
  );
  return new Uint8Array(bits);
}

export function generateEphemeralKeypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(P256, true, ['deriveBits']);
}
