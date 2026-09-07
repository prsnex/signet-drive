// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Concat-KDF-SHA-256 in the JOSE ECDH-ES OtherInfo format (RFC 7518 §4.6.2 /
// NIST SP 800-56A). The key-derivation step of ECDH-ES+A256KW: the ECDH shared
// secret Z becomes the 256-bit AES-KW KEK. This is NOT HKDF — JOSE specifies
// Concat-KDF for ECDH-ES; substituting HKDF would silently break interop.
//
// P-015 folder binding: the OtherInfo PartyVInfo slot (the JOSE `apv`) carries
// contextual data into the derived key. A metadata-key wrap sets
// party_v = root_folder_id (16 bytes); a blob unwrapped under a different folder
// derives a different KEK and AES-KW's integrity check rejects it.

import { concatBytes, u32be, utf8Encode, type Bytes } from './bytes';

const ECDH_ES_A256KW = 'ECDH-ES+A256KW';

/** One JOSE Datum: a big-endian uint32 length prefix followed by the data. */
function datum(data: Bytes): Bytes {
  return concatBytes(u32be(data.length), data);
}

/** JOSE OtherInfo: Datum(algorithmId) ‖ Datum(partyU) ‖ Datum(partyV) ‖ uint32_be(keydatalenBits).
 *  SuppPrivInfo is empty in v1. */
export function joseOtherInfo(
  algorithmId: Bytes,
  partyU: Bytes,
  partyV: Bytes,
  keydatalenBits: number,
): Bytes {
  return concatBytes(datum(algorithmId), datum(partyU), datum(partyV), u32be(keydatalenBits));
}

/** SP 800-56A single-step KDF with SHA-256. Round i (1-based) is
 *  SHA-256(uint32_be(i) ‖ Z ‖ otherInfo); rounds are concatenated, truncated to
 *  outLen. v1 only ever derives a 256-bit KEK (one round). */
export async function concatKdfSha256(z: Bytes, otherInfo: Bytes, outLen: number): Promise<Bytes> {
  const blocks: Bytes[] = [];
  let produced = 0;
  let counter = 1;
  while (produced < outLen) {
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', concatBytes(u32be(counter), z, otherInfo)),
    );
    blocks.push(digest);
    produced += digest.length;
    counter++;
  }
  return concatBytes(...blocks).slice(0, outLen);
}

/** The 256-bit ECDH-ES+A256KW key-wrapping KEK. party_v: empty for a DEK,
 *  root_folder_id (16 bytes) for a metadata key (P-015). party_u is empty. */
export function ecdhEsA256kwKek(z: Bytes, partyV: Bytes): Promise<Bytes> {
  const otherInfo = joseOtherInfo(utf8Encode(ECDH_ES_A256KW), new Uint8Array(0), partyV, 256);
  return concatKdfSha256(z, otherInfo, 32);
}
