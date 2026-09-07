// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug189 — `uploadFile` refuses a non-`Blob` source instead of silently
// producing a zero-byte file.
//
// ## The defect
//
// Passing a `Uint8Array` "succeeded": nothing threw, and the server recorded
// `size_bytes: 0, multipart_chunks: null` — because `source.size` is `undefined`
// on a typed array and `uploadPlan(undefined)` plans nothing. The failure then
// surfaced as an EMPTY DOWNLOAD, several steps from the mistake.
//
// ⚠ No shipped user path reached it — the web UI always hands `uploadFile` a
// real `File` from a picker. ⭐ But the UI was safe **by luck of its inputs, not
// by construction**, and the moment anything programmatic uploads (a bulk path,
// a harness, a test) it becomes reachable. It was found by an engineer making
// exactly that mistake while writing a concurrency test.
//
// ## The distinction these tests exist to protect (§3-3)
//
// ⛔ The refusal is about the wrong TYPE, never the zero SIZE. A genuinely empty
// `Blob` is a legitimate thing to store and MUST remain allowed. Conflating the
// two would break a real case to fix a synthetic one — so the empty-Blob case
// below is not a nicety, it is the guard against the obvious wrong fix.

import { describe, it, expect } from 'vitest';
import { Drive, describeSource } from './drive';
import { InvalidInputError } from './crypto';

/** A Drive whose api and session are inert.
 *
 *  ⭐ Sound precisely because the guard is `uploadFile`'s FIRST statement: it
 *  throws before `randomUUID`, before `uploadPlan`, before any quota reservation
 *  or network call — so nothing below it is ever reached and nothing needs to
 *  work. If a future edit moves the guard down, these stubs stop being enough
 *  and the test fails loudly rather than passing over a weakened check.
 *
 *  ⚠ The casts are honest here rather than lazy: bug189 is precisely about a
 *  caller who got past the TYPES, so the test must get past them too. */
function inertDrive(): Drive {
  const api = {} as unknown as ConstructorParameters<typeof Drive>[0];
  const session = {} as unknown as ConstructorParameters<typeof Drive>[1];
  return new Drive(api, session);
}

const target = { folderId: 'f', rootFolderId: 'r', shareFolder: false };

describe('bug189: describeSource — naming what actually arrived', () => {
  it('names the constructor, which is the useful word', () => {
    expect(describeSource(new Uint8Array(8))).toBe('Uint8Array');
    expect(describeSource(new ArrayBuffer(8))).toBe('ArrayBuffer');
    expect(describeSource('a string')).toBe('String');
    expect(describeSource(42)).toBe('Number');
  });

  it('handles null and undefined without throwing', () => {
    // ⚠ `null.constructor` throws; this is the case a naive implementation
    // crashes on, turning a helpful refusal into a confusing TypeError.
    expect(describeSource(null)).toBe('null');
    expect(describeSource(undefined)).toBe('undefined');
  });

  it('falls back to typeof for a null-prototype object', () => {
    expect(describeSource(Object.create(null))).toBe('object');
  });

  it('never interpolates the value itself', () => {
    // An upload source can be megabytes of user content. The description must
    // describe, not disclose.
    const secret = 'super-secret-file-contents';
    expect(describeSource(secret)).toBe('String');
    expect(describeSource(secret)).not.toContain(secret);
  });
});

describe('bug189: the type guard the refusal is built on', () => {
  // The guard in `uploadFile` is `!(source instanceof Blob)`. `uploadFile`
  // itself needs a constructed Drive, a session and a network layer, so these
  // pin the PREDICATE the guard uses — the part a future edit would get wrong.

  it('ACCEPTS a genuinely empty Blob — wrong type, not zero size (§3-3)', () => {
    // ⭐ The obvious wrong fix is `if (!source.size) throw`. It would pass every
    // other case here and silently break storing an empty file.
    const empty = new Blob([]);
    expect(empty.size).toBe(0);
    expect(empty instanceof Blob).toBe(true);
  });

  it('ACCEPTS a File, which is what the shipped UI actually passes', () => {
    const file = new File(['x'], 'a.txt', { type: 'text/plain' });
    expect(file instanceof Blob).toBe(true);
  });

  it('REJECTS the exact type that caused the defect', () => {
    expect(new Uint8Array(8) instanceof Blob).toBe(false);
  });

  it('REJECTS the other plausible near-misses a caller might reach for', () => {
    for (const wrong of [new ArrayBuffer(8), 'contents', 42, null, undefined, {}, []]) {
      expect(wrong instanceof Blob).toBe(false);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// bug189 §3-1 — the guard AS CALLED. The block above pins the predicate; these
// call `uploadFile` itself.
//
// ⚠⚠ Without these, the whole file is VACUOUS with respect to the actual fix:
// deleting the guard from `uploadFile` would leave every test above GREEN,
// because none of them call it. That is exactly the must-fail Gus asked for —
// "remove the type check ⇒ the new test goes red" — and it is only true of this
// block. §B-5.8: a control catches only the defects whose preconditions it
// reproduces.
// ─────────────────────────────────────────────────────────────────────────────

describe('bug189 §3-1: uploadFile refuses a non-Blob before any side effect', () => {
  it('THROWS OUR refusal on the Uint8Array that caused the defect', async () => {
    // ⚠⚠ Asserts the ERROR TYPE, not merely "something threw". A bare
    // `.rejects.toThrow()` here was NEARLY VACUOUS and I caught it by mutation:
    // with the guard disabled, `uploadFile` runs on and throws a TypeError
    // against the inert api anyway, so the bare form stayed GREEN over a deleted
    // guard while its three pattern-asserting siblings went red.
    // ⇒ On a path that throws for more than one reason, "it threw" is not a
    // result. Name which throw you meant.
    await expect(
      inertDrive().uploadFile(target, 'a.bin', new Uint8Array(8) as unknown as Blob),
    ).rejects.toBeInstanceOf(InvalidInputError);
  });

  it('names the PARAMETER and the EXPECTED TYPE, as the condition requires', async () => {
    // §3-1: "naming the parameter and the expected type". The whole cost of this
    // defect was diagnostic distance, so a bare "invalid input" would refuse in
    // the right place and still leave the caller hunting.
    await expect(
      inertDrive().uploadFile(target, 'a.bin', new Uint8Array(8) as unknown as Blob),
    ).rejects.toThrow(/source/);
    await expect(
      inertDrive().uploadFile(target, 'a.bin', new Uint8Array(8) as unknown as Blob),
    ).rejects.toThrow(/Blob/);
  });

  it('names what actually ARRIVED', async () => {
    await expect(
      inertDrive().uploadFile(target, 'a.bin', new Uint8Array(8) as unknown as Blob),
    ).rejects.toThrow(/Uint8Array/);
  });

  it('refuses BEFORE any side effect — the inert api is never touched', async () => {
    // ⭐ The proof of placement (§3-1: "before any network call, before any quota
    // reservation"). The stub api has NO methods at all, so if control reached
    // anything below the guard this would fail with a TypeError about a missing
    // function rather than our refusal. The error message IS the placement
    // evidence.
    await expect(
      inertDrive().uploadFile(target, 'a.bin', new Uint8Array(8) as unknown as Blob),
    ).rejects.toThrow(/must be a Blob/);
  });

  it('⛔ does NOT refuse an empty Blob — the wrong fix would (§3-3)', async () => {
    // An empty Blob must get PAST the guard. It will fail later against the
    // inert api, and that is the point: a DIFFERENT failure proves the guard let
    // it through. `if (!source.size) throw` would fail this test and pass every
    // other one in this file.
    await expect(inertDrive().uploadFile(target, 'empty.bin', new Blob([]))).rejects.not.toThrow(
      /must be a Blob/,
    );
  });
});
