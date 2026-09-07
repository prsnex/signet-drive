// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { SignetApiError } from './api';
import {
  friendlyAdminError,
  friendlyAuthError,
  friendlyCeremonyError,
  friendlyDriveError,
} from './errors';
import { StallError, TransferExhaustedError } from './transfer';

describe('friendlyAuthError', () => {
  it('maps known API error codes to friendly copy without leaking detail', () => {
    expect(
      friendlyAuthError(new SignetApiError(401, 'webauthn_authentication_failed', 'x')),
    ).toContain('sign you in');
    expect(friendlyAuthError(new SignetApiError(409, 'email_unavailable', 'x'))).toContain(
      'already exists',
    );
    expect(friendlyAuthError(new SignetApiError(409, 'handle_unavailable', 'x'))).toContain(
      'taken',
    );
    expect(friendlyAuthError(new SignetApiError(400, 'prf_not_supported', 'x'))).toContain(
      'passkey',
    );
  });

  it('falls back to the API message for an unmapped code', () => {
    expect(friendlyAuthError(new SignetApiError(400, 'some_future_code', 'the raw message'))).toBe(
      'the raw message',
    );
  });

  it('surfaces a plain Error message (e.g. a cancelled passkey prompt)', () => {
    expect(friendlyAuthError(new Error('sign-in was cancelled'))).toBe('sign-in was cancelled');
  });

  it('has a safe fallback for non-Error throws', () => {
    expect(friendlyAuthError('weird')).toContain('went wrong');
  });
});

describe('friendlyCeremonyError', () => {
  it('gives the in-flight-handle case its own actionable copy, distinct from the generic taken message (Bug040)', () => {
    const inFlight = friendlyCeremonyError(new SignetApiError(409, 'handle_in_flight', 'x'));
    const taken = friendlyCeremonyError(new SignetApiError(409, 'handle_unavailable', 'x'));
    // The in-flight copy points at the guardian's OWN pending enrollment (finish/cancel
    // + reuse the name) — NOT "choose another", which is the genuinely-taken case.
    expect(inFlight).toContain('in progress');
    expect(taken).toContain('choose another');
    expect(inFlight).not.toBe(taken);
  });

  it('surfaces the server message for invalid_request (already user-shaped)', () => {
    expect(
      friendlyCeremonyError(new SignetApiError(400, 'invalid_request', 'a fingerprint mismatch')),
    ).toBe('a fingerprint mismatch');
  });

  it('has a safe fallback for non-Error throws', () => {
    expect(friendlyCeremonyError('weird')).toContain('went wrong');
  });
});

describe('friendlyAdminError', () => {
  it('maps admin error codes to calm copy', () => {
    expect(friendlyAdminError(new SignetApiError(409, 'version_conflict', 'x'))).toContain(
      'already',
    );
    expect(friendlyAdminError(new SignetApiError(404, 'not_found', 'x'))).toContain('no longer');
    expect(friendlyAdminError(new SignetApiError(403, 'permission_denied', 'x'))).toContain(
      'permission',
    );
  });

  it('surfaces the server message for invalid_request (already user-shaped)', () => {
    expect(
      friendlyAdminError(
        new SignetApiError(400, 'invalid_request', 'duration_days must be at least 1'),
      ),
    ).toBe('duration_days must be at least 1');
  });

  it('has a safe fallback for non-Error throws', () => {
    expect(friendlyAdminError('weird')).toContain('went wrong');
  });
});

// bug060: failure notices are a product requirement (Chris, S126) — every
// failure must say what happened, that nothing was lost, and what to do next.
describe('friendlyDriveError — transfer failures (bug060)', () => {
  it('explains an exhausted UPLOAD honestly, never blames the server, and offers resume', () => {
    const msg = friendlyDriveError(
      new TransferExhaustedError('upload failed after 10 attempts', 10, null, 'upload'),
    );
    expect(msg).toMatch(/upload/i);
    expect(msg).not.toMatch(/on our end/i);
    // What to do next, and that the work already done survives (bug060's bar).
    expect(msg).toMatch(/again/i);
    expect(msg).toMatch(/saved/i);
  });

  // ⚠⚠ bug199 — THE DEFECT: a failed DOWNLOAD was reported as a failed UPLOAD,
  // and told the user to "start the same upload again": an operation they never
  // began and a recovery that does not exist for them. Seen live on v0.5.41, and
  // it cost real diagnostic time because it misled the two people best equipped
  // to read it.
  it('a failed DOWNLOAD says download and never says upload', () => {
    const msg = friendlyDriveError(
      new TransferExhaustedError('download failed after 10 attempts', 10, null, 'download'),
    );
    expect(msg).toMatch(/download/i);
    expect(msg).not.toMatch(/upload/i);
  });

  // ⚠ The negative control bug199 §4-3 asks for by name: the copy split must not
  // be a rename. If the upload arm ever stops naming upload or stops offering
  // resume, we have moved the defect rather than fixed it.
  it('the split is not a rename — upload keeps its own noun and its resume promise', () => {
    const up = friendlyDriveError(new TransferExhaustedError('x', 10, null, 'upload'));
    const down = friendlyDriveError(new TransferExhaustedError('x', 10, null, 'download'));
    expect(up).not.toEqual(down);
    expect(up).toMatch(/upload/i);
    expect(down).not.toMatch(/upload/i);
  });

  // ⭐ bug199 §4-2 + Gus's S180 ruling: NO CAUSE CLAIMS on either verb. The old
  // copy asserted "the connection to storage kept dropping" whatever had actually
  // happened — the measured truth in bug198 was four instant failures at the head
  // (7.0-7.7 ms, nothing sent), so the sentence sent a reader to inspect their own
  // network while the defect was in ours. Causes go to logs, never to users.
  it('claims no cause on either direction', () => {
    for (const direction of ['upload', 'download'] as const) {
      const msg = friendlyDriveError(new TransferExhaustedError('x', 10, null, direction));
      expect(msg).not.toMatch(/connection/i);
      expect(msg).not.toMatch(/dropping|dropped/i);
      expect(msg).not.toMatch(/network/i);
      expect(msg).not.toMatch(/storage/i);
    }
  });

  it('explains a stalled attempt without implying data loss', () => {
    const msg = friendlyDriveError(new StallError('stalled'));
    expect(msg).toMatch(/stopped responding/i);
    expect(msg).toMatch(/nothing was lost/i);
  });
});
