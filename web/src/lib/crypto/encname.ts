// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Encrypted file/folder names (Envelope §7.3). A name is encrypted with its
// share folder's metadata key (a per-root-folder AES key, itself wrapped to each
// recipient via the §7.2 ECDH-ES+A256KW wrap). A256GCM; the AAD is
// root_folder_id ‖ target_id (the 16-byte UUIDs), so a name ciphertext is bound
// to its file/folder under its root — the server can't move an encrypted name to
// another target. JSON envelope with separate base64url-no-pad iv/ct/tag fields.
// Mirrors signet-crypto's encname.rs.

import { aesGcmOpen, aesGcmSeal } from './aead';
import { b64uDecode, b64uEncode, concatBytes, utf8Encode, type Bytes } from './bytes';
import { InvalidInputError } from './errors';

const A256GCM = 'A256GCM';
const GCM_TAG_LEN = 16;
const utf8Decode = (b: Bytes): string => new TextDecoder().decode(b);

/** The §7.3 encrypted-name envelope (JSON; base64url-no-pad fields). */
export interface NameEnvelope {
  v: number;
  alg: string;
  iv: string;
  ct: string;
  tag: string;
}

/** AAD binding a name to its folder + target: root_folder_id ‖ target_id. */
function nameAad(rootFolderId: Bytes, targetId: Bytes): Bytes {
  return concatBytes(rootFolderId, targetId);
}

function checkIds(rootFolderId: Bytes, targetId: Bytes): void {
  if (rootFolderId.length !== 16 || targetId.length !== 16) {
    throw new InvalidInputError('root_folder_id and target_id must be 16 bytes');
  }
}

/** Encrypt a UTF-8 `name` under a folder's `metadataKey` (Envelope §7.3). The IV
 *  is fresh random per call (the metadata key is reused across names). */
export async function encryptName(
  metadataKey: Bytes,
  rootFolderId: Bytes,
  targetId: Bytes,
  name: string,
): Promise<NameEnvelope> {
  checkIds(rootFolderId, targetId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await aesGcmSeal(
    metadataKey,
    iv,
    utf8Encode(name),
    nameAad(rootFolderId, targetId),
  );
  const split = sealed.length - GCM_TAG_LEN;
  return {
    v: 1,
    alg: A256GCM,
    iv: b64uEncode(iv),
    ct: b64uEncode(sealed.slice(0, split)),
    tag: b64uEncode(sealed.slice(split)),
  };
}

/** Decrypt a §7.3 name envelope; returns the UTF-8 name. `rootFolderId` +
 *  `targetId` MUST match the values it was encrypted under, or the GCM tag
 *  fails (IntegrityError). */
export async function decryptName(
  metadataKey: Bytes,
  rootFolderId: Bytes,
  targetId: Bytes,
  envelope: NameEnvelope,
): Promise<string> {
  if (envelope.alg !== A256GCM) throw new InvalidInputError('unknown name alg');
  checkIds(rootFolderId, targetId);
  const iv = b64uDecode(envelope.iv);
  if (iv.length !== 12) throw new InvalidInputError('name iv must be 12 bytes');
  const tag = b64uDecode(envelope.tag);
  const ciphertextAndTag = concatBytes(b64uDecode(envelope.ct), tag);
  const plain = await aesGcmOpen(
    metadataKey,
    iv,
    ciphertextAndTag,
    nameAad(rootFolderId, targetId),
  );
  return utf8Decode(plain);
}
