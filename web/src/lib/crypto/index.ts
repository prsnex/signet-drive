// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Signet Drive browser crypto client (Phase 3 C0). A WebCrypto reimplementation
// of signet-crypto's classical wrap chain, validated byte-for-byte against the
// committed golden vectors (docs/design/test-vectors/golden/).

export * from './bytes';
export { IntegrityError, InvalidInputError } from './errors';
export {
  deriveZ,
  generateEphemeralKeypair,
  importEcdhPrivateJwk,
  importEcdhPublicJwk,
  importEcdhPublicX963,
} from './ecdh';
export { concatKdfSha256, ecdhEsA256kwKek, joseOtherInfo } from './concatkdf';
export { hkdfSha256 } from './kdf';
export { aesKwUnwrap, aesKwWrap } from './keywrap';
export { aesGcmOpen, aesGcmSeal } from './aead';
export { fingerprint, fingerprintRaw } from './pubkey';
export {
  ECDH_ES_A256KW,
  parseWrapEnvelope,
  unwrapDek,
  unwrapMetadataKey,
  wrapDek,
  wrapMetadataKey,
} from './wrap';
export type { EpkJwk, WrapEnvelope } from './wrap';
export {
  ECDH_ES_MLKEM1024_A256KW,
  hybridRfp,
  hybridUnwrapDek,
  hybridUnwrapMetadataKey,
  hybridWrapDek,
  hybridWrapMetadataKey,
  parseHybridWrapEnvelope,
} from './hybrid_wrap';
export type { HybridWrapEnvelope } from './hybrid_wrap';
export {
  initMlkem,
  mlkemDecapsulate,
  mlkemEkFromSeed,
  mlkemEncapsulate,
  mlkemKeygen,
} from './mlkem';
export { decodeKeyBlobV2, encodeKeyBlobV2 } from './keyblob';
export {
  FILE_ALG_A256GCM,
  FILE_MAGIC_SINGLE_PUT,
  openChunk,
  openFile,
  sealChunk,
  sealFile,
} from './envelope';
export {
  KEM_WRAP_LABEL,
  deriveWrapKey,
  prfSalt,
  unwrapKemPrivkey,
  wrapKemPrivkey,
} from './kem_wrap';
export type { KemPrivkeyWrap } from './kem_wrap';
export { decryptName, encryptName } from './encname';
export type { NameEnvelope } from './encname';
