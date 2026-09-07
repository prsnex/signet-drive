// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { execFileSync } from 'node:child_process';

// Playwright global setup for the local E2E. Raises the public-endpoint per-IP
// rate-limit caps in the isolated E2E database so the suite's serial signups +
// sign-ins from a single IP (127.0.0.1) don't trip the limiter (S046 #116). The
// caps are migration-seeded low for production (signup 10/hr, auth-begin per-min);
// the `enforce` layer reads them LIVE from system_config per request, so this
// UPDATE takes effect with no server restart. These are E2E-only values in
// signet_drive_e2e — production keeps the seeded defaults. The same direct-psql
// affordance helpers.ts uses (verificationToken / makeAdmin / activate).
function raiseCap(key: string, value: string): void {
  // ⛔ CLAMP TO THE DECLARED MAXIMUM. `config_int` (sharing.rs) refuses a value
  // above the row's own `max_value` and the endpoint 500s — so a cap "raised" past
  // the bound does not loosen the limiter, it BREAKS every route that reads it.
  // Signup returned 500 and the whole local suite died at `signUp` (found running
  // the bug241 repro, 2026-09-02: this wrote 1000000 against a max of 100000).
  // LEAST() against the column keeps this correct if the bound ever moves.
  const sql =
    `UPDATE system_config SET value = LEAST(${value}::bigint, max_value::bigint)::text ` +
    `WHERE key = '${key}'`;
  execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', 'signet_drive_e2e', '-tAc', sql],
    { encoding: 'utf8' },
  );
}

export default function globalSetup(): void {
  // Effectively unlimited for the test run; the limiter still functions (its own
  // unit tests gate the counting logic) — this only lifts the per-IP ceiling the
  // serial suite would otherwise hit.
  raiseCap('signup_rate_limit_per_ip_per_hour', '1000000');
  raiseCap('auth_begin_rate_limit_per_ip_per_minute', '1000000');
  // The enrollment-driven specs (4 of them) create a rendezvous each; repeated
  // local runs within an hour blow the seeded per-IP cap (20/hr) and fail with
  // "Too many attempts" on + Add PRSN (caught S061).
  raiseCap('prsn_enrollment_create_rate_limit_per_ip_per_hour', '1000000');
  // bug047: the upload-resilience specs exhaust a part's attempt budget with
  // fault-injected aborts; the seeded 10 attempts make that slow — 2 keeps it
  // fast (the specs assume ≥2). E2E-DB-only; production keeps the seed.
  raiseCap('multipart_part_retry_attempts', '2');
  // 3b (S175) — the COHERENT-KNOBS rule (bug173's trap): the retry budget above
  // is COUPLED to the transport-concurrency knobs; setting one without stating
  // the others runs the suite against a knob set no deployment will ever serve,
  // and it reports green on the wrong path. State the whole coupled set
  // explicitly, at the SEEDED production values, so the e2e exercises exactly
  // what staging serves: fan-out at 4, seal-ahead at 1.
  raiseCap('transfer_concurrency_upload', '4');
  raiseCap('transfer_concurrency_download', '4');
  raiseCap('transfer_upload_prepare_ahead', '1');
}
