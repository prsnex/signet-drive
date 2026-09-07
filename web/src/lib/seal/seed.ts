// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Identity → impression seed. Maps a key fingerprint (lowercase-hex SHA-256,
// PQR §8.5) to the six bytes the derivation consumes; callers fall back to a
// stable string (a handle, or a page path) that the component hashes when no
// fingerprint is on hand. The seal is decorative — this is which stable input
// each surface presses from, not a verification path.
//
// Own mark vs. others' marks:
//  - A signed-in user's OWN surfaces press from their key fingerprint, per the
//    pinned per-type regime in impression.ts — use `meSeed`.
//  - Other-PRSN surfaces a guardian sees (sidebar groups, PRSNs-in-care, the
//    guardian-context strip) press from the PRSN's HANDLE, because GuardedPrsn /
//    PrsnAttestationSummary carry no fingerprint field. This is a decided
//    adaptation (Gus carve review F3, S132), not drift: the press a guardian
//    sees for a PRSN differs from that PRSN's own-page press, and "new keys, new
//    press" does not hold on handle-seeded surfaces. Adding the signing fp to
//    the summary (post-launch) closes both — identitySeed's fallback chain
//    already handles its later presence.
//
// (Integration helper — Hlin. The derivation itself is Gus's impression.ts.)

import type { MeResponse } from '$lib/api';

/** The first 6 bytes of a hex fingerprint, or null if it is absent or too short. */
export function fpSeed(hex: string | null | undefined): Uint8Array | null {
  if (!hex || hex.length < 12) return null;
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    bytes[i] = byte;
  }
  return bytes;
}

/** An identity's impression seed: its fingerprint bytes when the client holds
 *  them (the user's own mark), else a stable string the component hashes (an
 *  in-context handle). `'signet'` is the last-resort constant so the mark is
 *  never random. */
export function identitySeed(
  fingerprint: string | null | undefined,
  fallback: string | null | undefined,
): Uint8Array | string {
  return fpSeed(fingerprint) ?? fallback ?? 'signet';
}

/** The signed-in user's OWN impression seed, per the pinned per-type regime
 *  (impression.ts): a PRSN presses from its SIGNING-key fingerprint (the
 *  identity anchor); a human presses from its classical KEM fingerprint (humans
 *  hold no client-side signing key). Falls back to the handle, then `'signet'`.
 *  Keeps the per-type rule in one place (Gus carve review F2, S132). */
export function meSeed(me: MeResponse | null | undefined): Uint8Array | string {
  const fingerprint =
    me?.account_type === 'prsn'
      ? me?.attestation?.signing_pubkey_fingerprint
      : me?.kem_pubkey_fingerprint;
  return identitySeed(fingerprint, me?.handle);
}
