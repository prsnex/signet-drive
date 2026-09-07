// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
/* bug196 items 5–7: whether the Dashboard's PRSN ACCOUNTS section is shown.
 *
 * Most Signet Drive users will never have a PRSN, and for them a whole sidebar
 * section they cannot use is noise. The toggle lives in Settings (which always
 * shows its PRSN card, so the control stays discoverable) and governs the
 * DASHBOARD sidebar only.
 *
 * ⚠⚠ THE DEFAULT IS DERIVED, NOT SIMPLY OFF — and the distinction is the whole
 * reason this is a module rather than a boolean. "Off by default", as first
 * proposed, would have made PRSN folders VANISH for people actively using them:
 * a Guardian with six PRSNs would sign in and find their section gone. Deriving
 * from the account's own PRSN count gives newcomers the clean surface AND leaves
 * existing users untouched.
 *
 * Persisted per-browser, like the file sort and the nav width. The gap that
 * leaves — a different browser does not know your explicit choice — is exactly
 * what the derived default covers: on a browser you have never used, having
 * PRSNs turns it on. Server-side persistence was considered and rejected as a
 * migration plus an API to fix a case the derivation already handles.
 */

const KEY = 'signet:show-prsn-section';

/** The user's EXPLICIT choice, or `null` when they have never made one.
 *  ⚠ `null` is not `false`: "never chosen" and "chose off" must stay
 *  distinguishable, or the derived default below cannot exist. */
export function loadPrsnSectionPref(): boolean | null {
  if (typeof localStorage === 'undefined') return null;
  const raw = localStorage.getItem(KEY);
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return null;
}

export function savePrsnSectionPref(show: boolean): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(KEY, show ? 'true' : 'false');
}

/** Should the Dashboard show the PRSN ACCOUNTS section?
 *
 *  An explicit choice always wins. Absent one, the account answers: a Guardian
 *  with PRSNs sees them, an account with none does not. */
export function prsnSectionVisible(pref: boolean | null, prsnCount: number): boolean {
  return pref ?? prsnCount > 0;
}
