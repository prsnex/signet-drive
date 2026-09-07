// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug219 — identifying a relay at-capacity response by its DECLARED CODE
// rather than by the shape of the URL it came from.
//
// ## Why this changed
//
// `putPart` used to recognise a relay response with `url.startsWith('/')`,
// because relay URLs were relative by construction and presigned storage URLs
// absolute (review F3). The h1 transport fix serves parts from a dedicated
// upload host, so relay URLs become ABSOLUTE and that test INVERTS.
//
// ⛔ Nothing would have thrown. A relay `503 relay_at_capacity` would simply
// stop matching, degrade to an ordinary retryable error, and start spending
// `multipart_part_retry_attempts` — the exact budget the v04 S2 review
// protected it from — while `waitingForCapacitySeconds` (bug075 row 18's
// server-busy UI) silently stopped working. A silent inversion, in a branch
// whose comment explained a premise that had just stopped being true.
//
// ## The property being bought
//
// A URL-shape test is a claim about the DEPLOYMENT TOPOLOGY. This is a claim
// about the RESPONSE. ⭐ The helper takes no URL at all — the independence is
// structural, not a rule someone has to remember.
//
// ## The asymmetry these cases are built around
//
// A false NEGATIVE is safe: the 503 stays an ordinary retryable error, which is
// exactly what it was before this branch existed. A false POSITIVE is not: it
// parks a storage 503 on a Retry-After wait that will never be satisfied. Every
// ambiguous input below is therefore asserted FALSE.

import { describe, it, expect } from 'vitest';
import { isRelayAtCapacityBody } from './api';

const relayEnvelope = JSON.stringify({
  error: { code: 'relay_at_capacity', message: 'relay at capacity' },
});

describe('bug219: isRelayAtCapacityBody', () => {
  it('recognises our at-capacity envelope', () => {
    expect(isRelayAtCapacityBody(relayEnvelope)).toBe(true);
  });

  it('recognises it with a details block present', () => {
    expect(
      isRelayAtCapacityBody(
        JSON.stringify({
          error: {
            code: 'relay_at_capacity',
            message: 'too many parts',
            details: { inFlight: 12 },
          },
        }),
      ),
    ).toBe(true);
  });

  // ── The one that matters most: storage must stay ordinary ────────────────
  it("does NOT match S3's XML 503 — the case the URL test used to exclude", () => {
    const s3SlowDown =
      '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>';
    expect(isRelayAtCapacityBody(s3SlowDown)).toBe(false);
  });

  it('does NOT match a DIFFERENT error code of ours', () => {
    // e.g. the bug220 stalled-part 408, which is retryable and must spend budget.
    expect(
      isRelayAtCapacityBody(
        JSON.stringify({ error: { code: 'part_transfer_stalled', message: 'stalled' } }),
      ),
    ).toBe(false);
  });

  it('does NOT match an envelope whose error carries no code', () => {
    expect(isRelayAtCapacityBody(JSON.stringify({ error: { message: 'something' } }))).toBe(false);
  });

  it('does NOT match the code at the WRONG nesting level', () => {
    // A flat `{code: …}` is not our envelope; matching it would mean the shape
    // check is doing no work.
    expect(isRelayAtCapacityBody(JSON.stringify({ code: 'relay_at_capacity' }))).toBe(false);
  });

  it('does NOT match a null error member', () => {
    expect(isRelayAtCapacityBody(JSON.stringify({ error: null }))).toBe(false);
  });

  it('does NOT match JSON scalars, arrays, or null', () => {
    for (const body of ['null', '"relay_at_capacity"', '12', '[{"error":{"code":"x"}}]']) {
      expect(isRelayAtCapacityBody(body)).toBe(false);
    }
  });

  it('does NOT match unparseable or absent bodies', () => {
    for (const body of ['', '   not json   ', '{oops', null, undefined]) {
      expect(isRelayAtCapacityBody(body)).toBe(false);
    }
  });

  // ── The structural property, asserted rather than assumed ────────────────
  it('takes no URL — the same body decides identically whatever host served it', () => {
    // ⭐ This is the whole point of the re-key. Under the OLD test, the verdict
    // depended on the URL; a relay body from an absolute upload-host URL would
    // have been MISSED. The helper's signature makes that impossible rather
    // than merely unlikely: there is no URL to get wrong.
    expect(isRelayAtCapacityBody.length).toBe(1);
    expect(isRelayAtCapacityBody(relayEnvelope)).toBe(true);
  });
});
