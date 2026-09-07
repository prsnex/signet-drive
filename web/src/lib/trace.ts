// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The WEB transfer trace — the sibling of the CLI's `SIGNET_TRANSFER_TRACE=1`
// (`cli/src/commands.rs`, built for bug193's v03 §6-1 per-chunk instants).
//
// ⚠⚠ WHY THIS EXISTS, and it is a §B-3.5 gap rather than a new idea. The CLI got a
// transfer trace at bug193; the web never did. At S177 we could measure the CLI's
// download parallelism to 0.03×, and at S180 — nineteen partnered downloads, a
// measured ~42% failure rate on Safari — we could not see WHY a single one of them
// failed. One decision, two surfaces, diverged; care was not the mitigation.
//
// WHAT S180 COULD NOT ANSWER FROM OUTSIDE THE BUNDLE, and why each needs to be in it:
//   1. **Did the retry run?** `transferWithRetry` gets 3 attempts per chunk
//      (`drive.ts` `downloadKnobs`). Failing downloads showed exactly ONE console
//      error, the same as passing ones — so either the retries did not happen, or
//      they died in a way that logs nothing. From outside, indistinguishable.
//   2. **What actually kills it?** A Safari CORS refusal and OUR OWN abort (the
//      first-byte timer, the backstop) are both a rejected promise at the call
//      site. Only the thrower knows which.
//   3. **What is the ~3 s?** Two failures died at ~3 s with ZERO chunk requests on
//      the wire. `READY_TIMEOUT_MS` (3000) was the obvious suspect and was
//      ELIMINATED — the `dl-ready`→`dl-consumed` marks measured ~6 ms on the
//      failing run. Nothing else in the path is 3 s (`FIRST_BYTE` 60 s, gap 20 s,
//      backstop ~18 min for a 16 MiB chunk).
//
// ⛔ WHY EXTERNAL INSTRUMENTS CANNOT REPLACE IT — measured at S180, both mine, both
// wrong before the controls caught them:
//   • A console `window.fetch` hook sees NOTHING: `api.ts` binds `doFetch` at client
//     construction (`globalThis.fetch.bind(globalThis)`), so a hook installed later
//     is bypassed by construction.
//   • `performance.getEntriesByType('resource')` records SUCCESSES: a passing
//     download showed 7 entries while the console showed 7 successes AND 1 CORS
//     failure. It cannot count attempts, which is the whole question.
//
// GATING. Off unless the operator asks, per browser, no deploy to toggle:
//
//     localStorage.setItem('signet_transfer_trace', '1')   // on
//     localStorage.removeItem('signet_transfer_trace')     // off
//
// ⚠ NEVER LOG A URL. Storage URLs carry `X-Amz-Signature`; a presigned URL in a
// pasted console dump is a credential in a chat log. Ranges, sizes, error
// identities and timings only — everything the questions above need, and nothing
// that grants access.

/** Read the gate every time rather than caching it: an operator turns the trace on
 *  MID-INVESTIGATION, and a cached `false` from page load would silently produce an
 *  empty log that reads as "nothing happened" — which is precisely the false
 *  negative that cost two instruments at S180. */
function enabled(): boolean {
  try {
    return globalThis.localStorage?.getItem('signet_transfer_trace') === '1';
  } catch {
    // Private modes and blocked storage throw on access; a trace must never be
    // able to break a transfer.
    return false;
  }
}

/** Milliseconds since page load, one decimal — the axis every mark shares so
 *  `attempt-failed` can be placed against `trigger` and `consumed`. */
function at(): string {
  try {
    return `${performance.now().toFixed(1)}ms`;
  } catch {
    return '?';
  }
}

/** Emit one trace line. `event` is a stable kebab token (greppable in a pasted
 *  dump); `data` is small, flat, and free of URLs and ciphertext. */
export function trace(event: string, data?: Record<string, unknown>): void {
  if (!enabled()) return;
  try {
    // console.info, not debug: Safari's Web Inspector hides `debug` behind a
    // verbosity filter that is off by default — a trace nobody sees is worse than
    // no trace, because it reads as silence from the system.
    console.info(`[signet-trace] ${at()} ${event}`, data ?? '');
  } catch {
    /* never let instrumentation throw into a transfer */
  }
}

/** ⚠⚠ F1 (Gus, S180 review — MUST-FIX before this instrument ever ran). The
 *  message field exists because Safari's CORS refusal and a network drop are both a
 *  bare `TypeError` and only the message separates them. But **Safari embeds the
 *  FULL URL in that message** — *"Fetch API cannot load https://…X-Amz-Signature=…"*
 *  — so a 160-char slice preserves the signature rather than truncating it, and the
 *  artifact built to be pasted into a chat becomes a credential in a chat log.
 *
 *  ⭐ The header rule of this file, defeated by the one field added for Safari's
 *  sake. Strip URLs FIRST, then truncate: the CORS-vs-network distinction survives
 *  intact because it lives in the sentence, never in the URL. */
function redact(message: string): string {
  return message.replace(/https?:\/\/\S+/g, '<url>').slice(0, 160);
}

/** Identify a thrown value for the trace: the three-way split S180 needed and
 *  could not get from outside — OUR abort vs the platform's refusal vs an HTTP
 *  status. ⚠ Message included because Safari's CORS refusal and a network drop are
 *  both a bare `TypeError`, and only the message separates them. */
export function errorIdentity(error: unknown): Record<string, unknown> {
  if (error && typeof error === 'object') {
    const e = error as { name?: string; message?: string; status?: number };
    return {
      name: e.name ?? error.constructor?.name ?? 'unknown',
      message: redact(e.message ?? ''),
      ...(typeof e.status === 'number' ? { status: e.status } : {}),
      aborted: e.name === 'AbortError',
    };
  }
  return { name: typeof error, message: redact(String(error)) };
}
