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

/** The passkey just created does not report the WebAuthn PRF extension, which key
 *  derivation requires. A designed refusal (the 1-Pager: "reject non-PRF authenticators
 *  at registration with a clear error"), not a defect. It has its own type so the UI
 *  can show calm copy instead of this message: before bug252 it was a plain
 *  InvalidInputError, and its developer string reached the sign-up page. */
export class PrfNotSupportedError extends InvalidInputError {
  constructor() {
    super('this authenticator does not support the required PRF extension');
    this.name = 'PrfNotSupportedError';
  }
}

/** The server's transparency-log epoch moved under an operation (design §10.4):
 *  a read refused the epoch the operation anchored (`refusal`), or a part it
 *  read names another one. `onceMoreOnEpochChange` re-reads once from a fresh
 *  `/v1/server-info`. A refusal met again reaches the user as "The service was
 *  updating. Please try again."; a part naming another epoch again becomes an
 *  IntegrityError, since it then contradicts a fresh read. */
export class EpochChangedError extends Error {
  constructor(
    message: string,
    readonly refusal: boolean,
  ) {
    super(message);
    this.name = 'EpochChangedError';
  }
}
