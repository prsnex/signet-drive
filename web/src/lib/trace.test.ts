// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

import { describe, expect, it } from 'vitest';
import { errorIdentity } from './trace';

// ⚠⚠ F1 (Gus, S180 review). The trace exists to be PASTED — into a bug file, a
// consult, a chat. Safari embeds the full URL in fetch TypeError messages, and a
// storage URL carries `X-Amz-Signature`. Without redaction the artifact built for
// sharing becomes a credential in a chat log, defeating this file's own header
// rule via the one field added for Safari's sake.
describe('errorIdentity redaction (bug206 instrument, F1)', () => {
  // The REAL message, verbatim from S180's Safari console.
  const safariCors =
    'Fetch API cannot load https://s3.bhs.io.cloud.ovh.net/signet-drive-storage-staging/' +
    'files/972fd86a-62bb-4d69-b31d-892ab860658c?x-id=GetObject&X-Amz-Algorithm=AWS4-HMAC-SHA256' +
    '&X-Amz-Credential=1590791e11cd4cf5a35bb8b4c8ec0e26%2F20260816%2Fbhs%2Fs3%2Faws4_request' +
    '&X-Amz-Signature=ccdd0663c96ff7ad5f7fdbe1d871fe6a8a39320288fefda5c0722a8fae8a1172 ' +
    'due to access control checks.';

  it('strips the signature — the credential never reaches the log', () => {
    const { message } = errorIdentity(new TypeError(safariCors)) as { message: string };
    expect(message).not.toMatch(/X-Amz-Signature/);
    expect(message).not.toMatch(/ccdd0663/);
    expect(message).not.toMatch(/https?:\/\//);
  });

  // ⭐ Redaction that also destroyed the diagnosis would be a worse instrument, not
  // a safer one: "access control checks" is the ONLY thing separating a CORS
  // refusal from a network drop, since both arrive as a bare TypeError.
  it('keeps what discriminates — the sentence, never the URL', () => {
    const { message, name } = errorIdentity(new TypeError(safariCors)) as {
      message: string;
      name: string;
    };
    expect(message).toMatch(/access control checks/);
    expect(message).toMatch(/<url>/);
    expect(name).toBe('TypeError');
  });

  it('flags OUR abort distinctly from the platform refusing', () => {
    const abort = new DOMException('The operation was aborted.', 'AbortError');
    expect(errorIdentity(abort)).toMatchObject({ name: 'AbortError', aborted: true });
    expect(errorIdentity(new TypeError(safariCors))).toMatchObject({ aborted: false });
  });

  it('truncates AFTER stripping, so a long URL cannot push the reason out of frame', () => {
    const longUrl = 'https://s3.example/' + 'a'.repeat(400) + '?X-Amz-Signature=deadbeef';
    const { message } = errorIdentity(
      new TypeError(`Fetch API cannot load ${longUrl} due to access control checks.`),
    ) as { message: string };
    expect(message).toMatch(/access control checks/);
    expect(message).not.toMatch(/deadbeef/);
    expect(message.length).toBeLessThanOrEqual(160);
  });
});
