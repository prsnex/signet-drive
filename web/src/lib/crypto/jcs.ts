// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

// JSON Canonicalization Scheme (RFC 8785 / JCS) — the TypeScript half of the
// single canonicalization chokepoint (`crypto/src/jcs.rs` is the Rust half;
// this file is a port against it, byte-for-byte cross-pinned by the committed
// golden in `docs/design/test-vectors/golden/jcs-cross-impl.json`). It produces
// the canonical bytes the server's B4 signatures are computed over: the §9
// attestation-verification response's `attestation` object and the §10a log
// receipt — what the web's verified-source recipient check (F-DOWNGRADE(b))
// verifies the ES256 half against.
//
// Domain constraint (load-bearing, ENFORCED, shared verbatim with the Rust
// side): every JSON object SigDrive signs uses plain ASCII keys — no control
// characters, no `"` or `\` — and integer numbers (unix seconds and
// counters). Within that domain this implementation is RFC-8785-exact:
//
// - RFC 8785 primitive serialization IS ECMAScript's `JSON.stringify` (the RFC
//   was specified around it — §3.2.2), so strings/booleans/null delegate to it
//   (short escapes + raw UTF-8, `/` unescaped) and integers format minimally.
// - Object keys sort by UTF-16 code units (§3.2.3) — `Array.prototype.sort`'s
//   default string order. The Rust side's serde_jcs orders keys by their
//   ESCAPED form, which diverges for any key containing an escape-class
//   character (found empirically by the S112 differential corpus) — so BOTH
//   sides refuse such keys outright: the divergent input is unrepresentable,
//   not documented-around.
// - Non-integer and unsafe-range numbers are REJECTED loudly rather than
//   float-formatted: the protocol never produces them, and a silent ryu-style
//   float path here would be an untested divergence surface.
//
// Keeping this the one chokepoint means a future swap to a full JCS library is
// a single-file change, exactly as on the Rust side.

import { InvalidInputError } from './errors';

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

/** Canonical RFC 8785 (JCS) bytes for `value` — see the module-level domain
 *  constraint (ASCII keys, integer numbers) under which this is RFC-8785-exact. */
export function toCanonicalBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(serialize(value));
}

/** The enforced key domain: plain ASCII, no control characters, no `"` or
 *  `\` — exactly the range where the Rust side's escaped-form key ordering
 *  agrees with RFC 8785's raw code-unit ordering (and with this port). */
function keyInDomain(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e || c === 0x22 /* " */ || c === 0x5c /* \ */) return false;
  }
  return true;
}

function serialize(value: JsonValue): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new InvalidInputError(
        'jcs: non-integer or unsafe-range number outside the SigDrive domain',
      );
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(serialize).join(',')}]`;
  }
  const keys = Object.keys(value);
  for (const key of keys) {
    if (!keyInDomain(key)) {
      throw new InvalidInputError(
        'jcs: object key outside the enforced domain (plain ASCII, no control ' +
          'chars, no quote/backslash)',
      );
    }
  }
  keys.sort();
  const members = keys.map((key) => `${JSON.stringify(key)}:${serialize(value[key])}`);
  return `{${members.join(',')}}`;
}
