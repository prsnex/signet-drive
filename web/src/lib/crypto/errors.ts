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

/** A passkey prompt in a multi-gesture ceremony returned no credential (the gateway
 *  resolved null rather than rejecting): the user dismissed it, or the passkey manager
 *  ended it. Its own type so the UI shows calm try-again copy (bug262); as a plain
 *  InvalidInputError its developer string reached the rotate dialog. */
export class PasskeyPromptEndedError extends InvalidInputError {
  constructor(what: string) {
    super(`the ${what} was cancelled`);
    this.name = 'PasskeyPromptEndedError';
  }
}

/** A crypto module loaded on first use (the VRF verifier, Launch Punch-List §1-67)
 *  could not be fetched or compiled: a dropped connection, or a deploy between the
 *  page load and the share. Nothing was wrapped or sent, and nothing was verified, so
 *  it is NEVER an {@link IntegrityError} (that would tell a user their recipient's keys
 *  were substituted) and never a skipped binding (Bob, §1-67). The UI shows "The
 *  service was updating. Please try again."; the next attempt fetches the module again. */
export class ModuleLoadError extends Error {
  constructor(what: string, cause: unknown) {
    super(
      `the ${what} could not be loaded (${cause instanceof Error ? cause.message : String(cause)})`,
    );
    this.name = 'ModuleLoadError';
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
