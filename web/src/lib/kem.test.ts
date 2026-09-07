// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { hexEncode } from './crypto/bytes';
import { deriveZ, generateEphemeralKeypair, importEcdhPublicX963 } from './crypto/ecdh';
import { generateKemKeypair, importKemPrivateNonExtractable } from './kem';

describe('KEM keypair lifecycle', () => {
  it('generates a 65-byte X9.63 public key and a PKCS#8 private key', async () => {
    const kp = await generateKemKeypair();
    expect(kp.publicX963.length).toBe(65);
    expect(kp.publicX963[0]).toBe(0x04);
    expect(kp.privatePkcs8.length).toBeGreaterThan(0);
  });

  it('the re-imported private key is the partner of the exported public key', async () => {
    // The keystone property: a private key exported to PKCS#8, then re-imported
    // (as it is after sign-in unwrap), still pairs with the published KEM public
    // key. Proven via ECDH symmetry: kem_priv·peer_pub == peer_priv·kem_pub.
    const kem = await generateKemKeypair();
    const recovered = await importKemPrivateNonExtractable(kem.privatePkcs8);
    const peer = await generateEphemeralKeypair();
    const kemPub = await importEcdhPublicX963(kem.publicX963);

    const zA = await deriveZ(recovered, peer.publicKey);
    const zB = await deriveZ(peer.privateKey, kemPub);
    expect(hexEncode(zA)).toBe(hexEncode(zB));
  });

  it('the re-imported private key is non-extractable', async () => {
    const kem = await generateKemKeypair();
    const recovered = await importKemPrivateNonExtractable(kem.privatePkcs8);
    await expect(crypto.subtle.exportKey('pkcs8', recovered)).rejects.toThrow();
  });
});
