// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Mirrors signet-crypto's CryptoError distinction: an integrity failure (wrong
// key / tampered ciphertext) is NEVER conflated with malformed input. Callers
// must not branch on the difference in a way that leaks an oracle, but the two
// are genuinely different conditions and carry different types.

/** A cryptographic integrity/authentication failure: AES-KW or AES-GCM rejected
 *  the input (wrong key, wrong AAD, wrong P-015 folder, or tampering). */
export class IntegrityError extends Error {
  constructor(message = 'authentication failed') {
    super(message);
    this.name = 'IntegrityError';
  }
}

/** Malformed input — a structurally invalid length, encoding, or algorithm.
 *  Distinct from {@link IntegrityError}: this is a caller/data bug, not a
 *  cryptographic rejection. */
export class InvalidInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidInputError';
  }
}
