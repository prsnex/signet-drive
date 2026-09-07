// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';

import { prsnSectionVisible } from './prsn-section';

/* bug196 item 5: the derived default.
 *
 * The request as first made was "off by default". Taken literally that would
 * have HIDDEN THE SECTION FROM PEOPLE ACTIVELY USING IT — a Guardian with six
 * PRSNs signs in and their folders are gone from the sidebar. The correction was
 * to derive the default from the account instead, and these arms pin it, because
 * a rule that lives only in a comment is a rule that gets "simplified" later. */
describe('prsnSectionVisible: the default is DERIVED, never flatly off', () => {
  it('a newcomer with no PRSNs sees no section — the point of the request', () => {
    expect(prsnSectionVisible(null, 0)).toBe(false);
  });

  it('⚠ a Guardian WITH PRSNs still sees them by default — the harm we avoided', () => {
    expect(prsnSectionVisible(null, 1)).toBe(true);
    expect(prsnSectionVisible(null, 6)).toBe(true);
  });

  it('an explicit choice always wins, in BOTH directions', () => {
    // Turned off despite having PRSNs.
    expect(prsnSectionVisible(false, 6)).toBe(false);
    // Turned on before having any — a Guardian about to enrol their first.
    expect(prsnSectionVisible(true, 0)).toBe(true);
  });

  it('"never chosen" and "chose off" are distinguishable, or the default cannot exist', () => {
    // If null ever collapsed to false, this pair would be identical and the
    // derivation above would be unreachable.
    expect(prsnSectionVisible(null, 3)).not.toBe(prsnSectionVisible(false, 3));
  });
});
