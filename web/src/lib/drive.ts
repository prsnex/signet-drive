// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Signet Drive data-plane crypto orchestration (C2). Turns plaintext folder/file
// operations into encrypted API calls: each private folder mints a fresh metadata
// key (wrapped to the owner) that encrypts its names; each file mints a fresh DEK
// that seals its content (§4.1) and is wrapped to the uploader and — for a share
// folder — to every current recipient (S049). Built on C0's golden-validated
// primitives. All crypto runs in the browser; the server sees only ciphertext + wraps.

import type {
  AcceptInvitationResponse,
  AccountApi,
  CreateFolderBody,
  CreateInvitationBody,
  CreateInvitationResponse,
  CreateShareFolderBody,
  DriveApi,
  FileView,
  FolderView,
  InvitationPreview,
  ListFilesResponse,
  ListFoldersResponse,
  ListPrsnsResponse,
  MeResponse,
  PendingInvitationsResponse,
  QuotaResponse,
  RecipientKey,
  RecipientsResponse,
  ShareFolderView,
  SharedWithMeResponse,
} from './api';
import { fetchAllPages } from './paginate';
import type { Session } from './auth';
import {
  b64uDecode,
  decryptName,
  ECDH_ES_A256KW,
  ECDH_ES_MLKEM1024_A256KW,
  encryptName,
  hybridUnwrapDek,
  hybridUnwrapMetadataKey,
  hybridWrapDek,
  hybridWrapMetadataKey,
  IntegrityError,
  InvalidInputError,
  openChunk,
  parseHybridWrapEnvelope,
  parseWrapEnvelope,
  sealChunk,
  unwrapDek,
  unwrapMetadataKey,
  type Bytes,
  type NameEnvelope,
} from './crypto';
import { formatBytes } from './format';
import { ServerTrust, verifiedRecipient, type VerifiedRecipient } from './recipient_verify';
import { trace, errorIdentity } from './trace';
import {
  TransferExhaustedError,
  MULTIPART_CHUNK_OVERHEAD,
  indicatesRateOverestimate,
  isRetryable,
  knobsFromResponse,
  transferWithRetry,
  type TransferKnobs,
  TransferGovernor,
  governorKnobsFromResponse,
  finalizeAttempts,
  backoffMs,
  sleep,
} from './transfer';
import { UploadSlots } from './upload-slots';

// The file ciphertext envelope is AES-256-GCM (Envelope §4.1/§4.2); the server
// stores this label verbatim in files.algorithm.
const FILE_ALGORITHM = 'A256GCM';

// ⚠ F1 (2026-09-21): this constant is now a SENTINEL, not a part size. A Drive
// constructed without an explicit chunk size gets this value, and
// `explicitChunkSize` is defined as "the caller passed something else" — that is
// the only thing it governs. Production part sizes come from
// `TransferGovernor.partSize`: the 5 MiB floor before any part has been measured
// on this Drive, then `rate × target_part_seconds` clamped. Before F1 the value
// was also the plan for a fresh page's first file (one 16 MiB stream for a 20 MB
// file — the two-minute upload that produced a cancel); no production path plans
// with it any more. Overridable per Drive so tests exercise multi-chunk without
// large fixtures.
const DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024;

/**
 * The object-storage floor for every multipart part except the last (S3 semantics,
 * which OVH follows): below it, `CompleteMultipartUpload` rejects the whole upload
 * *after* every byte has been transferred (bug060/S1).
 *
 * **Deliberately not enforced client-side here.** `chunkSize` is not user-settable on
 * this surface — production uses the default, and adaptive sizing clamps to this floor
 * by construction — while `multipart::initiate` on the server rejects any sub-floor
 * plan on the *first* request, before a single byte moves, for every client. A second
 * client-side throw would be redundant and would forbid the small-chunk fixtures the
 * transport tests legitimately use (8-byte chunks, to exercise multipart mechanics
 * cheaply). The authoritative guard is the server's; this constant documents the rule
 * and bounds the adaptive-sizing clamp.
 */
export const MIN_MULTIPART_CHUNK_SIZE = 5 * 1024 * 1024;

// bug192: the §4.2 per-chunk overhead constant now lives in transfer.ts (see
// the top-of-file import) — the part-sizing clamp needs it, and two homes for
// one number is how the plaintext and wire figures drifted apart at all.

/** The web's compiled ceiling on download concurrency (knob rule 1, S174).
 *
 *  ⚠ **Lower than the CLI's 8, and the difference is the point.** In-flight
 *  memory is `N × chunk` — transiently ~2× while an envelope is opened — and
 *  this surface already carries bug179's MEASURED 489 MiB renderer peak. A
 *  served value cannot raise the real ceiling; an unclamped one would be a DoS
 *  switch pointed at our own users. */
export const WEB_MAX_DOWNLOAD_CONCURRENCY = 4;

/** Resolve how many chunks to fetch at once from the served knob.
 *
 *  ⭐ **Anything unusable ⇒ 1, i.e. exactly the pre-S174 serial behaviour.** An
 *  older server that omits the field, a nonsense value, and a deliberate
 *  retraction all land on the same safe position rather than on a guess — knob
 *  rule 4's off-position, exercised by tests rather than declared. */
export function downloadConcurrency(served: number | undefined): number {
  if (typeof served !== 'number' || !Number.isFinite(served)) return 1;
  return Math.min(Math.max(Math.floor(served), 1), WEB_MAX_DOWNLOAD_CONCURRENCY);
}

/** bug209 (S181): the compiled default and ceiling for the per-chunk download
 *  attempt budget.
 *
 *  ⚠ **The old compiled value was 3, and 3 was effectively 2.** `backoffMs`
 *  returns 0 for attempts 1 AND 2, so the first two fire ~1 ms apart — against a
 *  failure that clears with ELAPSED TIME they are one moment, not two. Measured on
 *  deployed v0.5.44 (S181, Safari, trace on): failing chunks lost attempts 1 and 2
 *  at ~1 ms apart and succeeded on attempt 3 after the first real backoff, i.e. on
 *  the LAST available attempt with zero margin.
 *
 *  ⚠⚠ **10 is a dial position, not a discovered constant** (Chris, S181: *"We don't
 *  know what the magic number is. I'd doubt there is one"*). An attempt COUNT
 *  encodes a guess about someone else's implementation — how many dead connections
 *  a browser may have pooled. Two independent arguments happen to agree on 10:
 *  symmetry with the upload budget (served at 10 since migration 0036), and
 *  exceeding a browser's per-host pool depth (~6 in Safari). Neither is "10 is
 *  correct", which is why it is SERVED and why the trace now reports what a success
 *  actually costs.
 *
 *  ⛔ This settles no mechanism. bug206 stays open. */
export const DEFAULT_DOWNLOAD_RETRY_ATTEMPTS = 10;

/** The clamp ceiling on the served budget.
 *
 *  ⚠ **Un-derived, and labelled as such** — unlike the default, 25 rests on no
 *  measurement. What makes it defensible is arithmetic rather than an adjective
 *  (Gus R4, S181): `backoffMs` caps jitter at 8 s from attempt 6 on, so the
 *  worst-case time a chunk can spend in backoff is
 *    0 + 1 + 2 + 4 + (20 x 8) = **167 s ≈ 2.8 min**   at 25 attempts
 *    0 + 1 + 2 + 4 + ( 5 x 8) = **47 s**              at the default 10
 *  against a per-attempt backstop of ~17.9 min for a 16 MiB chunk. So even a
 *  maximally-clamped budget fails HONESTLY in under three minutes rather than
 *  hanging — which is the property the ceiling exists to guarantee. Verified by
 *  computation over `backoffMs`, not asserted. */
export const DOWNLOAD_RETRY_ATTEMPTS_MAX = 25;

/** Resolve the per-chunk attempt budget from the served knob.
 *
 *  ⚠ **Unusable ⇒ the compiled DEFAULT (10), not 1 and NOT the old 3.** This
 *  differs deliberately from `downloadConcurrency`, whose off-position is the safe
 *  *serial* behaviour. There is no safe "off" for a retry budget: 0 or 1 attempts
 *  would make every transient blip a user-visible failure.
 *
 *  ⚠⚠ **Do not read this as "the retraction position" — it is not** (Gus, S181 F1).
 *  The pre-0060 client did **3**, and landing absent on 3 would preserve the defect
 *  as the fallback: the ~42% Safari failure rate came from exactly that budget.
 *  **The old behaviour is the defect, not a refuge.** A reader reasoning about
 *  rollback from this comment must not infer 3.
 *
 *  ⭐ The genuine retraction position lives on the OTHER side of the wire: a
 *  pre-0060 *client* ignores the served field and keeps its own compiled budget.
 *  Retracting this fix means deploying a client that does not read the knob, or
 *  serving a lower value — not returning this resolver to 3.
 *
 *  Clamped above because an unclamped served value keeps a doomed chunk retrying
 *  instead of failing honestly. */
export function downloadRetryAttempts(served: number | undefined): number {
  if (typeof served !== 'number' || !Number.isFinite(served)) {
    return DEFAULT_DOWNLOAD_RETRY_ATTEMPTS;
  }
  return Math.min(Math.max(Math.floor(served), 1), DOWNLOAD_RETRY_ATTEMPTS_MAX);
}

/** The web's compiled ceiling on upload seal-ahead (knob rule 1, S174).
 *
 *  ⚠⚠ **1, and this surface pipelines EXACTLY ONE PART AHEAD.** The loop starts
 *  `prepare(queue[1])` and no more, so a served value above 1 would have no
 *  effect here — a clamp of 2 would have let the knob over-promise, with the
 *  memory note `(1 + prepareAhead) × chunk` implying a depth the code does not
 *  reach. (Gus F3, S174.)
 *
 *  ⭐ One ahead is also all this is for: the gap being closed is a single part's
 *  encryption time, and preparing further ahead cannot fill a gap that no longer
 *  exists. In-flight memory is therefore 2 × chunk = 32 MiB at the default, on a
 *  surface already carrying bug179's MEASURED 489 MiB renderer peak. */
export const WEB_MAX_UPLOAD_PREPARE_AHEAD = 1;

/** Resolve how many upload parts to seal ahead, from the served knob.
 *
 *  ⭐ **Anything unusable ⇒ 0, i.e. exactly the pre-S174 serial seal-then-send.**
 *  An older server that omits the field, a nonsense value, and a deliberate
 *  retraction all land on the same safe position — knob rule 4's off-position,
 *  exercised by tests rather than declared.
 *
 *  ⚠ Note the off-position differs from the download knob's: there, "off" is 1
 *  (one chunk at a time); here it is 0 (nothing prepared ahead). The knobs count
 *  different things, so a shared default would be wrong for one of them.
 *
 *  ⚠⚠ **On THIS surface the knob is effective only at `concurrency_upload ≤ 1`**
 *  (Gus F1, S175). At N > 1 the fan-out workers each seal their own part — the
 *  seal/send overlap comes from the workers themselves, and the one-ahead
 *  prefetch machinery never runs — so at the served defaults (N=4, pa=1) this
 *  knob is INERT here. Stated so an operator turning it expects no effect on a
 *  concurrent web upload (the S174 F3 class: a knob advertising an effect the
 *  deployed path never exercises). The CLI's producer thread honours it at
 *  every N. Web in-flight memory under fan-out is `N × chunk`; the CLI's is
 *  `(N + prepare_ahead) × chunk`. */
export function uploadPrepareAhead(served: number | undefined): number {
  if (typeof served !== 'number' || !Number.isFinite(served)) return 0;
  return Math.min(Math.max(Math.floor(served), 0), WEB_MAX_UPLOAD_PREPARE_AHEAD);
}

/** The web's compiled ceiling on upload send concurrency (knob rule 1, S175 —
 *  3b). Matches the download ceiling and for the same reason: in-flight memory
 *  is `N × chunk` (transiently ~2× while a part seals), on a surface already
 *  carrying bug179's measured 489 MiB renderer peak. The CLI clamps at 8. */
export const WEB_MAX_UPLOAD_CONCURRENCY = 4;

/** Resolve how many upload parts to SEND at once from the served knob.
 *
 *  ⭐ **Anything unusable ⇒ 1, i.e. exactly the serial send path.** An older
 *  server that omits the field, a nonsense value, and a deliberate retraction
 *  all land on the same safe position — knob rule 4's off-position, exercised
 *  by tests rather than declared. */
export function uploadConcurrency(served: number | undefined): number {
  if (typeof served !== 'number' || !Number.isFinite(served)) return 1;
  return Math.min(Math.max(Math.floor(served), 1), WEB_MAX_UPLOAD_CONCURRENCY);
}

/** Object storage's hard cap on parts in one multipart upload — the ceiling
 *  adaptive sizing must respect (a 100 GB file at the 5 MiB floor would need
 *  20,000 parts, so the planner enlarges parts rather than emit an illegal plan). */
const MAX_PARTS = 10_000;

/** One file's pre-flight facts: its display name and the STORED (ciphertext) size
 *  the server will bound and reserve against — never its size on disk. */
export interface UploadCandidate {
  name: string;
  storedSize: number;
}

/**
 * bug070: the pre-flight decision, as a pure function — a refusal message, or `null`
 * to proceed. The I/O (reading the live quota) is the caller's; keeping the *rule*
 * free of it is what makes it testable, and a check that cannot be tested is a check
 * that cannot be trusted.
 *
 * Two grounds, mirroring exactly what `multipart::initiate` enforces:
 *   1. any single file's stored size over the server's `max_upload_size_bytes`;
 *   2. the batch's total stored size over the remaining Guardian-pooled quota.
 *
 * `ceiling === null` means /v1/me has not loaded yet, and `remaining === null` means
 * the quota read failed. Both **fail OPEN** — the server is authoritative, so
 * proceeding costs nothing (a genuinely impossible upload is still refused, before
 * any byte reaches storage), while refusing on missing local information would block
 * legitimate uploads on a transient error.
 *
 * The CLI runs the same rule over a single candidate (`commands.rs::capacity_refusal`);
 * `drive.test.ts` and the CLI's unit tests share verbatim-identical vectors, the same
 * way the bug048 name rule is pinned across `names.ts` / `names.rs`.
 */
export function capacityRefusal(
  candidates: UploadCandidate[],
  ceiling: number | null,
  remaining: number | null,
): string | null {
  if (ceiling !== null) {
    const tooLarge = candidates.find((candidate) => candidate.storedSize > ceiling);
    if (tooLarge) {
      return `"${tooLarge.name}" is larger than the ${formatBytes(ceiling)} upload limit.`;
    }
  }
  if (remaining === null) return null;
  const needed = candidates.reduce((sum, candidate) => sum + candidate.storedSize, 0);
  if (needed <= remaining) return null;
  // bug070 follow-ups (S140), two defects in the sentence this used to build:
  //
  //  (1) The verb lived in the shared `detail`, so the plural branch read
  //      "these 3 files NEEDS ..." — the subject changes, the verb could not.
  //  (2) `formatBytes` rounds, so a genuine near-miss refusal rendered as
  //      "needs 2.0 GB but only 2.0 GB is available" — a true statement that reads
  //      as a contradiction, at exactly the moment the user is being told no. The
  //      shortfall is the number that is never zero here (we are inside
  //      `needed > remaining`), so leading with it is coherent at ANY rounding.
  const shortfall = formatBytes(needed - remaining);
  const detail = `${formatBytes(needed)}, which is ${shortfall} more than the ${formatBytes(remaining)} available`;
  return candidates.length === 1
    ? `Not enough storage: this upload needs ${detail}. Free some space or move to a larger plan.`
    : `Not enough storage: these ${candidates.length} files need ${detail}. Free some space, move to a larger plan, or upload fewer at once.`;
}

/**
 * The rate an upload assumes before it has measured anything (bytes/sec ≈ 1 Mbps).
 *
 * Deliberately pessimistic. The CLI needs no such seed — its rate-free
 * no-progress gap detector is complete without any estimate — but XHR gives this
 * surface no dead-flow detector other than the per-part ceiling, so the FIRST
 * part must still be bounded by something. A low seed makes that first bound
 * generous (a healthy slow part is never killed) at the accepted cost that one
 * genuinely dead first flow takes a couple of minutes to notice. That cost is
 * paid once per session, and only when there is nothing measured to do better.
 */
const BOOTSTRAP_RATE_BYTES_PER_SEC = 125_000;

/** Concatenate plaintext chunks into one buffer (download reassembly). */
function concat(chunks: Bytes[]): Bytes {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/** Live upload progress (bug046/bug047): real BYTES, not just parts — a
 *  slow-but-moving upload must never read as frozen — plus the resilience
 *  signals (retries, the paused state) the UI surfaces honestly. */
export interface UploadProgress {
  completedParts: number;
  totalParts: number;
  /** Plaintext bytes accounted as sent (completed parts + the in-flight
   *  part's live XHR progress, clamped). */
  sentBytes: number;
  totalBytes: number;
  /** Fresh-connection retries so far (counts only — never phoned home). */
  retries: number;
  /** True while the upload is PAUSED after a part exhausted its attempt
   *  budget (a bad network window) — waiting on resume() or cancel(). */
  paused: boolean;
  /** Coverage row 18 (bug075): seconds the server asked us to wait after a
   *  `503 relay-at-capacity`, or `null` when not waiting.
   *
   *  ⭐ Why this is a SEPARATE field from `paused`, and not folded into it: the
   *  two states look identical on a progress bar and are opposite in meaning.
   *  `paused` is "your network gave up; press Resume" — a user decision is
   *  owed. This is "the server is full and told us exactly how long to wait" —
   *  nothing is owed, it resumes itself. Collapsing them would tell a waiting
   *  user to act, which is the bug075 shape (a frozen bar a person cannot read
   *  as either healthy or broken) with a wrong instruction added on top. */
  waitingForCapacitySeconds: number | null;
  /** F3 (2026-09-21): parts whose PUT is in flight right now — a COUNT, never
   *  which part numbers (with fan-out and retries the numbers are not
   *  contiguous, and a claim about numbers could be false). Lets the panel say
   *  something true during the silent stretch a single big part used to be:
   *  the two minutes of "nothing" that produced Chris's cancel on 09-17. */
  inFlightParts: number;
  /** F3: the governor's link estimate, bytes/s, ONLY once a part has completed
   *  and been measured on this Drive; `null` before that. ⛔ Never the bootstrap
   *  seed: that is a stall-ceiling constant, and showing it as a rate would be
   *  an invented number in the wrong direction (Gus). */
  measuredRateBytesPerSec: number | null;
  /** F3: remaining plaintext ÷ the measured rate, whole seconds; `null`
   *  whenever the rate is. An estimate labelled "about", derived from
   *  completed parts only — never from `xhr.upload.onprogress` (bug060). */
  etaSeconds: number | null;
  /** F4 (2026-09-21): times this file's transfer was paused by a PAGE
   *  SUSPENSION (display sleep, a hidden tab) with parts in flight and then
   *  resumed. A fact the panel may state; measured three times in one evening
   *  batch on 09-17/18, each pausing the batch silently until the tab was
   *  visible again. */
  suspensions: number;
}

/** Live download progress (bug061): reported per fetched-and-decrypted chunk —
 *  the honest analog of the upload bar. Each Range-GET is atomic (no sub-chunk
 *  signal), so granularity is per-chunk, and every tick is a chunk whose bytes
 *  have actually arrived and opened — never buffered fiction (the bug060
 *  upload-bar lesson applied to the read path). */
export interface DownloadProgress {
  completedChunks: number;
  totalChunks: number;
  /** On-disk (ciphertext) bytes fetched so far — what the transfer wait is
   *  actually spent on. */
  receivedBytes: number;
  totalBytes: number;
}

/** bug179: where a streaming download puts each verified chunk.
 *
 *  Deliberately the narrowest useful shape — `FileSystemWritableFileStream`
 *  already satisfies it, so the production sink is the browser's own object
 *  with no adapter, and the in-memory fallback is four lines. A wider interface
 *  would be a second thing to keep in sync with the platform's.
 *
 *  ⚠ **The commit contract, and the whole point of the type:** `close` COMMITS,
 *  `abort` DISCARDS, and exactly one of them is called. A download that fails
 *  part-way must leave nothing behind — not a valid-but-short file, which is
 *  the failure bug180 documents on the CLI surface. */
export interface DownloadSink {
  /** Receives one chunk of AEAD-verified plaintext, in order. */
  write(chunk: Bytes): Promise<void>;
  /** Commit. Called once, only after every chunk has opened. */
  close(): Promise<void>;
  /** Discard everything written. Called instead of `close` on any failure. */
  abort(): Promise<void>;
  /** ⚠ bug195 (k): resolves when the BROWSER HAS TAKEN the download — not when we
   *  merely decided to offer it. Present on the SW path (the worker's fetch handler
   *  claiming the entry is the causal instant); absent on the capped fallback, whose
   *  anchor click hands over a complete Blob synchronously.
   *
   *  The success notice must await this AND `close()`. Gating on readiness instead
   *  is what let v0.5.39 announce "Saved" for downloads that never started.
   *
   *  ⚠ What this proves, exactly: handoff plus a finished write. It does NOT prove a
   *  landed file — a cancel or a full disk after handoff still ends with nothing on
   *  disk. The copy must claim only this much. */
  consumed?: Promise<void>;
}

/** bug193 (v03): what a sink factory learns before it must produce a sink —
 *  enough to carry an honest Content-Length (Gus F1) and to refuse pre-flight. */
export interface DownloadSinkMeta {
  /** The file's PLAINTEXT length — see {@link plaintextLength}. */
  plaintextBytes: number;
  totalChunks: number;
  /** The served SW-path kill-switch (migration 0059). Absent server ⇒ enabled. */
  swDownloadEnabled: boolean;
  /** The served per-file fallback ceiling (migration 0059). */
  bufferCapBytes: number;
}

/** Fallback for a pre-0059 server omitting the served cap: the S173-measured
 *  value the migration's default also carries. */
export const DEFAULT_WEB_DOWNLOAD_BUFFER_CAP = 1024 * 1024 * 1024;

/** ⚠ Gus F1 (v03) — THE one plaintext↔stored derivation site for a whole file.
 *  `size_bytes` is the STORED size: plaintext + `MULTIPART_CHUNK_OVERHEAD` on
 *  every chunk. A `Content-Length` served from the stored size would end every
 *  SW-streamed download "short" by `34 × chunks` — bug192's class, the other
 *  direction. Derive here, nowhere else. */
export function plaintextLength(sizeBytes: number, multipartChunks: number): number {
  return sizeBytes - multipartChunks * MULTIPART_CHUNK_OVERHEAD;
}

/** The user cancelled a paused/in-flight upload — the upload was aborted and
 *  its reservation freed. Not an error to toast. */
/** bug189 — name what actually arrived, for `uploadFile`'s type refusal.
 *
 *  ⚠ The whole cost of this defect was DIAGNOSTIC DISTANCE: a `Uint8Array` was
 *  accepted, the upload "succeeded" with `size_bytes: 0`, and the failure only
 *  surfaced later as an empty download. A refusal that said merely "wrong type"
 *  would refuse in the right place and still leave the caller guessing, so the
 *  message names the value it got.
 *
 *  Constructor name first (`Uint8Array`, `ArrayBuffer`, `String`), since that is
 *  the useful word; `typeof` is the fallback for primitives and null-prototype
 *  objects. ⛔ Never interpolates the VALUE itself — an upload source can be
 *  megabytes of user content, and it has no business in an error string. */
export function describeSource(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  const ctor = (value as { constructor?: { name?: unknown } })?.constructor?.name;
  return typeof ctor === 'string' && ctor.length > 0 ? ctor : typeof value;
}

export class UploadCancelledError extends Error {
  constructor() {
    super('upload cancelled');
    this.name = 'UploadCancelledError';
  }
}

/** In-session control of one upload (bug047): when a part exhausts its
 *  attempt budget the upload PAUSES (never silently dies) and waits here for
 *  the user's resume() or cancel(). The active ids let the UI fire a
 *  best-effort keepalive abort on pagehide (reload = rollback by design —
 *  the File handle cannot survive a reload, so cross-reload resume is
 *  structurally out; the server's expiry sweep is the backstop). */
export class UploadController {
  /** The in-flight upload's ids, set at initiate, cleared at completion. */
  active: { fileId: string; uploadId: string } | null = null;
  private gate: { resolve: (action: 'resume' | 'cancel') => void } | null = null;
  private cancelRequested = false;
  /** bug076: aborts the CURRENT part attempt's live XHR (armed by putPart via
   *  `onAbortReady`, re-armed per attempt, cleared when the part lands). */
  private abortInFlight: (() => void) | null = null;

  /** Drive-internal: park until the user acts. */
  waitForResume(): Promise<'resume' | 'cancel'> {
    if (this.cancelRequested) return Promise.resolve('cancel');
    return new Promise((resolve) => {
      this.gate = { resolve };
    });
  }

  get isPaused(): boolean {
    return this.gate !== null;
  }

  resume(): void {
    this.gate?.resolve('resume');
    this.gate = null;
  }

  /** Drive-internal (bug076): register/clear the current attempt's XHR abort. */
  registerInFlightAbort(abort: (() => void) | null): void {
    this.abortInFlight = abort;
  }

  /** Takes effect immediately: paused → resolves the gate; actively
   *  transferring → aborts the in-flight part's socket (bug076 — previously the
   *  cancel waited for the next part boundary, so on exactly the slow link
   *  where a user reaches for Cancel, the button appeared dead for a whole
   *  part). The part-purge backend then cleans up via `abortMultipart`. */
  cancel(): void {
    this.cancelRequested = true;
    this.gate?.resolve('cancel');
    this.gate = null;
    this.abortInFlight?.();
    this.abortInFlight = null;
  }

  get cancelled(): boolean {
    return this.cancelRequested;
  }

  // F4 (2026-09-21): page visibility, as the store reports it. The transfer
  // layer has no `document`; the store forwards `visibilitychange`.
  private visible = true;
  /** Drive-internal: uploadFile installs this to learn of each transition. */
  onVisibility: ((visible: boolean) => void) | null = null;

  /** The store calls this once, right after construction, with the document's
   *  CURRENT state — a batch begun while the page is hidden (files picked, tab
   *  switched before the first part lands) has no hide transition to learn
   *  from, and without this it would never count its wake (Gus, fold 2). No
   *  transition is signalled. */
  initVisibility(visible: boolean): void {
    this.visible = visible;
  }

  /** Called by the store on every `visibilitychange`. Nothing waits on this:
   *  retries decide from "was the page hidden during my attempt" (see
   *  uploadFile), so a background tab that is merely throttled keeps sending
   *  and re-sending on its own. */
  setVisibility(visible: boolean): void {
    if (visible === this.visible) return;
    this.visible = visible;
    this.onVisibility?.(visible);
  }

  get isVisible(): boolean {
    return this.visible;
  }
}

/** Parse a UUID string into its 16 raw bytes — the form used in the §7.3 name AAD
 *  and the §7.2 / P-015 metadata-key binding. */
export function uuidToBytes(uuid: string): Bytes {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32 || /[^0-9a-f]/i.test(hex)) {
    throw new InvalidInputError('invalid uuid');
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

// The recipient bundle-shape + verified-source layers (F-DOWNGRADE a+b) live
// in recipient_verify.ts — every third-party wrap routes through
// `verifiedRecipient` there; this module orchestrates the wraps.

/** The wrap alg of an envelope value, read from `alg` ALONE — never inferred
 *  from field presence (PQR §5.2). Anything else — including the reserved
 *  pure `ML-KEM-1024+A256KW` — is rejected. */
function wrapAlgOf(value: unknown): string {
  const alg = (value as { alg?: unknown } | null)?.alg;
  if (alg === ECDH_ES_A256KW || alg === ECDH_ES_MLKEM1024_A256KW) return alg;
  throw new InvalidInputError('unknown wrap alg');
}

/**
 * Drive operations for a signed-in session. Holds an in-memory cache of unwrapped
 * per-root-folder metadata keys (lives and dies with the session). Construct one
 * per session and discard it on sign-out.
 */
export class Drive {
  private readonly metadataKeys = new Map<string, Bytes>();

  /**
   * bug060: the transfer-rate governor, **session-scoped on purpose**.
   *
   * Every duration-shaped bound is derived from it, and it can only learn from
   * completed parts — so if it were per-upload, every upload's first part would
   * fall back to the conservative bootstrap and no measurement would ever carry
   * forward. Living on the Drive means the first upload of a session pays the
   * bootstrap once and every later one is sized and bounded from real
   * measurement of this device's actual link.
   */
  private readonly governor = new TransferGovernor();

  /** True when the caller pinned an explicit chunk size (the transport tests do,
   *  deliberately using tiny parts). An explicit size always beats adaptive
   *  sizing — otherwise those fixtures would silently become 5 MiB. */
  private readonly explicitChunkSize: boolean;

  constructor(
    private readonly api: DriveApi & Pick<AccountApi, 'listPrsns'>,
    private readonly session: Session,
    private readonly chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    this.explicitChunkSize = chunkSize !== DEFAULT_CHUNK_SIZE;
  }

  /** Create a private folder. A top-level folder mints a fresh metadata key
   *  wrapped to the owner; a nested folder reuses its root's key. */
  async createFolder(
    name: string,
    parent?: { folderId: string; rootFolderId: string },
  ): Promise<FolderView> {
    const folderId = crypto.randomUUID();

    if (!parent) {
      // Top-level: the folder is its own root, so it binds names to its own id.
      // The self-wrap is hybrid (a web session always holds a hybrid identity).
      const metadataKey = randomBytes(32);
      const rootBytes = uuidToBytes(folderId);
      const ownerWrap = await this.wrapMetadataKeyTo(this.selfRecipient(), metadataKey, rootBytes);
      const encryptedName = await encryptName(metadataKey, rootBytes, rootBytes, name);
      const body: CreateFolderBody = {
        folder_id: folderId,
        encrypted_name: encryptedName,
        owner_metadata_key_wrap: ownerWrap,
      };
      const view = await this.api.createFolder(body);
      this.metadataKeys.set(folderId, metadataKey);
      return view;
    }

    // Nested: reuse the root's metadata key; bind the name to (root, this folder).
    const metadataKey = await this.metadataKey(parent.rootFolderId);
    const encryptedName = await encryptName(
      metadataKey,
      uuidToBytes(parent.rootFolderId),
      uuidToBytes(folderId),
      name,
    );
    const body: CreateFolderBody = {
      folder_id: folderId,
      parent_folder_id: parent.folderId,
      encrypted_name: encryptedName,
    };
    return this.api.createFolder(body);
  }

  /** Upload a file via the §4.2 multipart transport — the unified path; every
   *  upload, large or small, goes direct-to-storage. A fresh DEK seals each chunk
   *  (AAD = file_id‖chunk_index), wrapped to the owner; the content never passes
   *  through the API. The name is encrypted under the folder's metadata key.
   *
   *  `source` is a Blob — a `File` from the picker, or a Blob wrapping in-memory
   *  bytes. Each chunk is read lazily via `source.slice(...).arrayBuffer()`, so a
   *  large File streams from disk one chunk at a time: peak memory is a single
   *  chunk, not the whole file.
   *
   *  bug047/bug046 resilience: each part transfers with stall-detection and
   *  fresh-connection retry (server-tuned knobs); `onProgress` reports live
   *  BYTES (XHR upload progress — a slow upload never reads as frozen) plus
   *  retry counts. With a `controller`, an exhausted part PAUSES the upload
   *  resumably (in-session — resume refreshes the authoritative state through
   *  the server's `/resume` endpoint) instead of failing; cancel aborts and
   *  frees the reservation. */
  /**
   * See the module-level {@link capacityRefusal} — this is its I/O-free companion.
   *
   * The §4.2 transport plan for a plaintext size: the part size THIS surface would
   * choose, the resulting part count, and the **stored (ciphertext) size** — the
   * figure the server reserves quota against and bounds by `max_upload_size_bytes`.
   *
   * **bug070: one home for the rule.** A pre-flight capacity check and the upload
   * that follows it have to agree about the number they are comparing, or the check
   * is theatre. Before this existed the guard compared raw `Blob.size` (plaintext)
   * against a ceiling the server applies to ciphertext, so a file within
   * `34 × chunkCount` of the ceiling passed the client and was rejected by the
   * server — ~332 KiB at the 10,000-part maximum. Both callers now derive the figure
   * here.
   *
   * Note the residual, stated rather than hidden: `partSize` reads the governor's
   * live rate estimate, so a forecast taken before a batch and the plan chosen
   * mid-batch can differ once measurements land. The divergence is bounded by the
   * per-chunk overhead across at most `MAX_PARTS` parts, and the server stays
   * authoritative either way — but it is why this is a forecast, not a promise.
   */
  uploadPlan(plaintextSize: number): {
    chunkSize: number;
    chunkCount: number;
    storedSize: number;
  } {
    const chunkSize = this.explicitChunkSize
      ? this.chunkSize
      : this.governor.partSize(plaintextSize, MAX_PARTS);
    const chunkCount = Math.max(1, Math.ceil(plaintextSize / chunkSize));
    return {
      chunkSize,
      chunkCount,
      storedSize: plaintextSize + chunkCount * MULTIPART_CHUNK_OVERHEAD,
    };
  }

  async uploadFile(
    target: { folderId: string; rootFolderId: string; shareFolder: boolean },
    name: string,
    source: Blob,
    onProgress?: (progress: UploadProgress) => void,
    controller?: UploadController,
    slots?: UploadSlots,
  ): Promise<FileView> {
    // bug189 — refuse a non-`Blob` source HERE, before any side effect.
    //
    // Passing a `Uint8Array` used to "succeed": nothing threw, and the server
    // recorded `size_bytes: 0, multipart_chunks: null`, because `source.size` is
    // `undefined` on a typed array and `uploadPlan(undefined)` plans nothing. The
    // failure then surfaced as an EMPTY DOWNLOAD, several steps from the mistake
    // — the expensive kind to diagnose.
    //
    // ⚠ Placement is the condition, not a detail (§3-1): before `randomUUID`,
    // before `uploadPlan`, before any quota reservation or network call. A guard
    // further down would still leave a reserved-then-abandoned upload behind.
    //
    // ⛔ This refuses the wrong TYPE, never the zero SIZE (§3-3). An empty `Blob`
    // is a legitimate thing to store and stays allowed — conflating the two would
    // break a real case to fix a synthetic one.
    if (!(source instanceof Blob)) {
      throw new InvalidInputError(
        `uploadFile: \`source\` must be a Blob (or File); received ${describeSource(source)}`,
      );
    }
    const fileId = crypto.randomUUID();
    const fileIdBytes = uuidToBytes(fileId);
    const dek = randomBytes(32);
    // bug060: size parts from the rate this session has already measured, so a
    // part takes roughly the governor's target duration. Load-bearing on THIS
    // surface (unlike the CLI's): XHR is blind mid-part, so the per-part ceiling
    // is the only dead-flow detector, and part duration therefore sets detection
    // latency. The governor is session-scoped, so the first upload runs on the
    // conservative bootstrap and every later one is sized from real measurement.
    //
    // An explicit `chunkSize` (tests, and any caller that passes one) always wins
    // — the transport tests use tiny parts deliberately.
    // bug070: derived by `uploadPlan`, the SAME function the pre-flight capacity
    // check calls — so the number the guard compared and the number declared here
    // cannot drift apart. Do not inline this arithmetic again.
    const { chunkSize, chunkCount, storedSize: declaredSize } = this.uploadPlan(source.size);

    // Wrap the DEK to the uploader (hybrid — the session identity), and — for
    // a share folder — to every current recipient too (S049), so a recipient
    // (notably a PRSN's mandatory Guardian) can read a file added after they
    // joined. Each recipient bundle is verified (P-011 classical + the §9.2
    // presence-gated PQ pair — a hybrid recipient gets a hybrid wrap or an
    // error, never a classical fallback); the server enforces the set covers
    // exactly the folder's recipients + uploader.
    const wrappedDeks = [
      {
        recipient_account_id: this.session.accountId,
        wrapped_dek: await this.wrapDekTo(this.selfRecipient(), dek),
      },
    ];
    if (target.shareFolder) {
      const { recipients, owner } = await this.api.listRecipients(target.rootFolderId);
      // Verified-source recipient keys (F-DOWNGRADE a+b): one server-trust
      // fetch for the whole recipient set; each recipient's keys verify
      // against their identity record (attestation / §10a receipts) before
      // any wrap. The OWNER is wrapped too (Bug038) so a read_write recipient
      // (a Guardian) uploading to a folder it does not own still covers the
      // owner; when we ARE the owner it is skipped (self-wrap covers it).
      const trust = new ServerTrust(this.api);
      const wrapTargets = [owner, ...recipients];
      const seen = new Set<string>([this.session.accountId]);
      for (const r of wrapTargets) {
        if (seen.has(r.recipient_account_id)) continue;
        seen.add(r.recipient_account_id);
        const recipient = await verifiedRecipient(
          trust,
          this.api,
          r,
          'server-listed',
          r.permission === 'owner' ? 'the folder owner' : 'a share recipient',
        );
        wrappedDeks.push({
          recipient_account_id: r.recipient_account_id,
          wrapped_dek: await this.wrapDekTo(recipient, dek),
        });
      }
    }

    const metadataKey = await this.metadataKey(target.rootFolderId);
    const encryptedName = await encryptName(
      metadataKey,
      uuidToBytes(target.rootFolderId),
      fileIdBytes,
      name,
    );

    const initiate = await this.api.initiateMultipart(fileId, {
      folder_id: target.folderId,
      encrypted_name: encryptedName,
      wrapped_deks: wrappedDeks,
      declared_size: declaredSize,
      chunk_size: chunkSize,
      chunk_count: chunkCount,
      algorithm: FILE_ALGORITHM,
    });

    let knobs: TransferKnobs = knobsFromResponse(initiate);
    // bug060: every duration-shaped bound comes from the rate this upload
    // measures on itself. Seeded pessimistically because — unlike the CLI, whose
    // rate-free gap detector needs no estimate — XHR gives this surface no other
    // dead-flow detector, so the FIRST part must still have some ceiling.
    const governor = this.governor;
    governor.applyKnobs(governorKnobsFromResponse(initiate));
    // bug178 phase 2 (S174): how many parts to seal ahead of the one in flight.
    // Read once per upload from the same served block as the governor knobs, so
    // a retraction takes effect on the next upload without a client release.
    const prepareAhead = uploadPrepareAhead(
      (initiate.governor as Record<string, unknown> | undefined)?.upload_prepare_ahead as
        | number
        | undefined,
    );
    // 3b (S175): how many parts to SEND at once. Read from the same served
    // block, same retraction semantics — anything unusable ⇒ 1 ⇒ the serial
    // send loop below runs exactly as deployed.
    const finalizeAttempts_ = finalizeAttempts(
      (initiate.governor as Record<string, unknown> | undefined)?.finalize_attempts as
        | number
        | undefined,
    );
    const sendConcurrency = uploadConcurrency(
      (initiate.governor as Record<string, unknown> | undefined)?.concurrency_upload as
        | number
        | undefined,
    );
    governor.seedBootstrap(BOOTSTRAP_RATE_BYTES_PER_SEC);
    // F2 (2026-09-23): the send slots this file draws from. A batch passes ONE
    // pool for all its files (the first to initiate teaches it the served N);
    // a lone file gets a private pool of its own N — the pre-F2 behaviour
    // exactly, so the CLI-parity path and every existing test are unchanged.
    // ⚠ Both send sites below take a slot for ONE attempt and release it in
    // that attempt's `finally` — so a part sleeping through a backoff, or
    // waiting the relay's `Retry-After`, holds no slot (Gus, v01 delta 2): a
    // part waiting on a full relay must not pin the pool exactly when the relay
    // is asking for less.
    const pool = slots ?? new UploadSlots(sendConcurrency);
    pool.learn(sendConcurrency);
    if (controller) controller.active = { fileId, uploadId: initiate.upload_id };

    const totalBytes = source.size;
    const plainSize = (partNumber: number): number =>
      Math.min(chunkSize, Math.max(0, source.size - (partNumber - 1) * chunkSize));

    let queue = [...initiate.part_urls];
    const etags = new Map<number, string>();
    let retries = 0;
    // bug060: progress is reported from COMPLETED PARTS only.
    //
    // The previous bar added the in-flight part's `xhr.upload.onprogress` bytes,
    // which report data buffered by the browser rather than delivered to storage
    // — it reaches "100% of this part" within about a second and then sits
    // there. On a slow link that produced a bar that raced ahead and stalled,
    // repeatedly. Completed parts are the only figure this surface can state
    // truthfully, so the bar advances in part-sized steps and every step is real.
    // Coverage row 18 (bug075): non-null while the server has refused a part
    // with `503 relay-at-capacity` and named a Retry-After. Set by the `onBusy`
    // hook — which `transfer.ts` has always fired and nothing has ever consumed
    // — and cleared the moment bytes move again.
    let waitingForCapacitySeconds: number | null = null;
    // F3: a count of PUTs in flight, maintained at the two send sites below.
    let inFlightParts = 0;
    // F4: page suspensions, and the wake's refresh (the barrier a retry awaits
    // before re-sending). `hideEpoch` advances on every hide transition; an
    // attempt stamps the epoch it started under, so a retry can tell whether
    // the page was hidden at any point during the attempt that failed.
    let suspensions = 0;
    let hideEpoch = 0;
    let lastRefreshedEpoch = -1;
    let countedEpoch = -1;
    let wakeRefresh: Promise<void> | null = null;
    const report = (paused = false) => {
      let doneBytes = 0;
      for (const partNumber of etags.keys()) doneBytes += plainSize(partNumber);
      const sentBytes = Math.min(totalBytes, doneBytes);
      // F3: the rate is a fact only once a part has completed on this Drive;
      // the governor's `measured` flag is what keeps the bootstrap seed out.
      const measuredRateBytesPerSec = governor.measured ? governor.rateEstimate : null;
      // F3-a (2026-09-23, filed at the v1.0.4 staging test): the governor's rate
      // is ONE STREAM's — each part is timed on its own while N are in flight —
      // so the remaining bytes divide by rate × the streams carrying them, not
      // by the rate alone, which read ~N× too long. The multiplier is the count
      // in flight NOW, a fact; "about" stays the label.
      const etaSeconds =
        measuredRateBytesPerSec !== null && measuredRateBytesPerSec > 0
          ? Math.ceil(
              (totalBytes - sentBytes) / (measuredRateBytesPerSec * Math.max(1, inFlightParts)),
            )
          : null;
      onProgress?.({
        completedParts: etags.size,
        totalParts: chunkCount,
        sentBytes,
        totalBytes,
        retries,
        paused,
        waitingForCapacitySeconds,
        inFlightParts,
        measuredRateBytesPerSec,
        etaSeconds,
        suspensions,
      });
    };

    try {
      // bug050 (web face): refresh the authoritative in-flight state from the
      // server's /resume — the stored-part set (anything that landed is
      // skipped), fresh URLs for the rest, current knobs. Shared by the
      // exhaustion pause and the finalize pause below; the same server
      // surface the CLI's cross-run resume uses (#298).
      const refreshFromResume = async () => {
        const resumed = await this.api.resumeMultipart(fileId, initiate.upload_id);
        knobs = knobsFromResponse(resumed);
        etags.clear();
        for (const part of resumed.uploaded_parts) etags.set(part.part_number, part.etag);
        queue = [...resumed.part_urls];
        report();
      };
      // F4: on wake, learn which in-flight parts the server already STORED, so
      // their retries return the stored etag instead of re-sending. The server's
      // `uploaded_parts` is the truth this relies on (an etag per part, the
      // resume path). ⚠ The queue is deliberately NOT rebuilt here — that
      // happens only between pool runs (see the pool comment below); in-flight
      // workers skip stored parts at the barrier instead, so no part can be
      // pulled twice.
      const refreshStoredFromResume = async () => {
        const resumed = await this.api.resumeMultipart(fileId, initiate.upload_id);
        for (const part of resumed.uploaded_parts) etags.set(part.part_number, part.etag);
      };
      // F4: ONE refresh per hide epoch, shared by whoever asks first — the wake
      // (`onVisibility`) or a retry. ⚠ The fresh `part_urls` the resume returns
      // are deliberately ignored here: URLs are stable on the relay path, and
      // under presign this is the pre-existing behaviour of an in-flight part's
      // retry (the queue is rebuilt only between pool runs). A failed refresh
      // falls through to the ordinary retry: the part is re-sent, which is what
      // happened before F4 — never worse.
      const countSuspension = () => {
        if (countedEpoch === hideEpoch) return;
        countedEpoch = hideEpoch;
        suspensions += 1;
      };
      const startWakeRefresh = (): Promise<void> => {
        if (wakeRefresh) return wakeRefresh;
        const epoch = hideEpoch;
        wakeRefresh = refreshStoredFromResume()
          .then(() => {
            lastRefreshedEpoch = epoch;
          })
          .catch(() => undefined)
          .finally(() => {
            wakeRefresh = null;
            report();
          });
        return wakeRefresh;
      };
      // F4: what a RETRY awaits before re-sending. The truth it needs is "was
      // the page hidden at any point during the attempt that failed": then the
      // server may already hold the part whose 200 died with the page, so
      // refresh (once per epoch) and skip if stored. A throttled hidden tab can
      // make that call itself; a truly suspended page surfaces its errors only
      // on wake, when the refresh runs either way — whichever of the error
      // callbacks and `visibilitychange` the browser fires first (Gus, fold 1).
      // Nothing ever parks on visibility.
      const refreshIfHiddenDuring = async (attemptEpoch: number, startedVisible: boolean) => {
        const hiddenDuring = attemptEpoch !== hideEpoch || !startedVisible;
        if (hiddenDuring) {
          countSuspension();
          if (lastRefreshedEpoch !== hideEpoch) await startWakeRefresh();
          else if (wakeRefresh) await wakeRefresh;
        } else if (wakeRefresh) {
          await wakeRefresh;
        }
      };
      if (controller) {
        controller.onVisibility = (visible) => {
          if (!visible) {
            hideEpoch += 1;
            return;
          }
          // Visible again with parts in flight: they were in flight across the
          // hidden interval — count the wake, refresh eagerly, tell the panel.
          if (inFlightParts === 0) return;
          countSuspension();
          if (lastRefreshedEpoch !== hideEpoch) void startWakeRefresh();
          report();
        };
      }
      report();
      // bug178 phase 2 (S174): SEAL AHEAD. Reading + encrypting a part is CPU
      // work that used to happen with the network idle — the relay's own counter
      // measured `effective_streams` at 0.80–0.93 during a 1 GB upload, i.e. less
      // than one stream active on average. Preparing part N+1 while part N is in
      // flight fills that gap and changes NO network behaviour: same requests,
      // same order, same retry machinery.
      const prepare = async (part: { part_number: number; url: string }) => {
        const index = part.part_number - 1;
        // Read just this chunk's bytes — a File-backed Blob reads the range from
        // disk, so the whole file is never held in memory at once.
        const slice = new Uint8Array(
          await source.slice(index * chunkSize, (index + 1) * chunkSize).arrayBuffer(),
        );
        return {
          partNumber: part.part_number,
          envelope: await sealChunk(dek, fileIdBytes, index, chunkCount, slice),
        };
      };
      type Prepared = Awaited<ReturnType<typeof prepare>>;
      let ahead: Promise<Prepared> | null = null;
      for (;;) {
        // 3b (S175): FAN OUT when the served knob asks for it. This loop fully
        // drains the queue at sendConcurrency > 1 (pausing resumably on a bad
        // window, exactly like the serial path), so the serial loop below then
        // sees an empty queue and is a no-op — at sendConcurrency <= 1 this
        // block never runs and the deployed serial path is byte-identical.
        //
        // ⚠ The queue is rebuilt (refreshFromResume) ONLY between pool runs,
        // never while a worker holds an entry — so the staleness the n=1
        // prefetch guards against has no window to occur in here. Workers pull
        // with `queue.shift()`, atomic between awaits on a single thread.
        while (sendConcurrency > 1 && queue.length > 0) {
          // bug076 under fan-out: the controller's single abort slot holds an
          // AGGREGATE that aborts every in-flight socket, so cancel stays
          // prompt for all N workers, not just the last to register.
          const liveAborts = new Set<() => void>();
          controller?.registerInFlightAbort(() => {
            for (const abort of liveAborts) abort();
          });
          // One exhausted part must pause the UPLOAD promptly: workers finish
          // the part in hand and stop pulling, rather than draining the whole
          // queue around a bad network window.
          let stopPulling = false;
          const worker = async (): Promise<void> => {
            for (;;) {
              if (controller?.cancelled) throw new UploadCancelledError();
              if (stopPulling || queue.length === 0) return;
              // F2: SLOT FIRST, then seal, then PUT (Gus, v01 delta 1). With K
              // files open, a worker that sealed and THEN waited for a slot
              // would hold a sealed part per worker — K × N parts in memory,
              // 80 MB on the shipped defaults, the phone hazard bug075 lived
              // in. Taking the slot before reading the chunk keeps the peak at
              // N × chunk across the whole batch, as it is for one file.
              let held: (() => void) | null = await pool.acquire();
              // The wait may have outlived the reason to pull.
              if (controller?.cancelled) {
                held();
                throw new UploadCancelledError();
              }
              const entry = stopPulling ? undefined : queue.shift();
              if (!entry) {
                held();
                return;
              }
              const { part_number, url } = entry;
              // F2 (Gus, review fold at b3ef83ce): SEALED ⇒ HOLDING A SLOT,
              // everywhere. The envelope lives exactly as long as the slot: it
              // is sealed under the slot, sent, and DROPPED with the slot at
              // the end of every attempt, success or failure. A retry takes a
              // fresh slot and re-seals — byte-identical, since `sealChunk`
              // derives the IV from the DEK and the chunk index and the AAD
              // from the file id, index and is_last; nothing random. Without
              // this, a worker whose PUT failed kept its envelope through the
              // backoff sleep while a fresh slot-holder sealed another, and on
              // a dropped link (every attempt failing) the sealed count could
              // climb to N² — the bug075 number, in exactly the case the bound
              // exists for. A re-seal costs one chunk read and one AES-GCM,
              // milliseconds against a backoff of seconds.
              let envelope: Prepared['envelope'] | null;
              let partBytes: number;
              try {
                ({ envelope } = await prepare(entry));
                partBytes = envelope.byteLength;
              } catch (error) {
                held();
                stopPulling = true;
                throw error;
              }
              let attemptGeneration = governor.generation;
              let myAbort: (() => void) | null = null;
              // F3: the part is in flight from here until it lands or fails.
              inFlightParts += 1;
              report();
              let skippedStored = false;
              let attemptEpoch = hideEpoch;
              let attemptStartedVisible = controller?.isVisible ?? true;
              try {
                const startedAt = Date.now();
                const etag = await transferWithRetry(
                  async (attempt) => {
                    // F4: a retry after an attempt during which the page was
                    // hidden refreshes from the server and skips a part it
                    // already stored (its 200 died with the page).
                    if (attempt > 1) {
                      await refreshIfHiddenDuring(attemptEpoch, attemptStartedVisible);
                      const stored = etags.get(part_number);
                      if (stored !== undefined) {
                        skippedStored = true;
                        return stored;
                      }
                    }
                    attemptEpoch = hideEpoch;
                    attemptStartedVisible = controller?.isVisible ?? true;
                    attemptGeneration = governor.generation;
                    // F2: the slot is held for THIS attempt only. The first
                    // attempt inherits the one taken before the seal; a retry
                    // (after a backoff or a relay-busy wait, during which it
                    // held nothing and had dropped its envelope) takes a fresh
                    // slot here and re-seals under it.
                    if (!held) held = await pool.acquire();
                    if (!envelope) ({ envelope } = await prepare(entry));
                    try {
                      return await this.api.putPart(url, envelope, {
                        ceilingMs: governor.ceilingMs(partBytes) ?? undefined,
                        onAbortReady: controller
                          ? (abort) => {
                              if (myAbort) liveAborts.delete(myAbort);
                              myAbort = abort;
                              liveAborts.add(abort);
                            }
                          : undefined,
                      });
                    } finally {
                      // The slot and the envelope go together.
                      held();
                      held = null;
                      envelope = null;
                    }
                  },
                  knobs,
                  'upload',
                  {
                    onRetry: (_attempt, _attempts, error) => {
                      retries += 1;
                      if (indicatesRateOverestimate(error)) {
                        governor.penalizeStall(attemptGeneration);
                      }
                      report();
                    },
                    onBusy: (retryAfterSeconds) => {
                      waitingForCapacitySeconds = retryAfterSeconds;
                      report();
                    },
                  },
                );
                if (myAbort) liveAborts.delete(myAbort);
                waitingForCapacitySeconds = null;
                // A skipped (already-stored) part is not a transfer measurement.
                if (!skippedStored) governor.observePart(partBytes, Date.now() - startedAt);
                etags.set(part_number, etag);
                inFlightParts -= 1;
                report();
              } catch (error) {
                if (myAbort) liveAborts.delete(myAbort);
                // F2: every attempt releases in its own `finally`; this is the
                // belt for a throw between the slot and the PUT (a re-seal that
                // fails), so a failed part can never keep a slot from the rest
                // of the batch.
                if (held) {
                  held();
                  held = null;
                }
                envelope = null;
                inFlightParts -= 1;
                stopPulling = true;
                throw error;
              }
            }
          };
          const results = await Promise.allSettled(
            Array.from({ length: Math.min(sendConcurrency, queue.length) }, () => worker()),
          );
          controller?.registerInFlightAbort(null);
          // Classify in severity order: cancel > fatal > exhausted-pause. The
          // un-stored part a pause abandoned reappears when refreshFromResume
          // rebuilds the queue from the server's truth — nothing is re-queued
          // by hand, so a part can never be queued twice.
          let pause: TransferExhaustedError | null = null;
          for (const r of results) {
            if (r.status !== 'rejected') continue;
            const error = r.reason;
            if (controller?.cancelled || error instanceof UploadCancelledError) {
              throw new UploadCancelledError();
            }
            if (error instanceof TransferExhaustedError && controller) {
              pause = error;
              continue;
            }
            throw error;
          }
          if (pause) {
            report(true);
            const action = await controller!.waitForResume();
            if (action === 'cancel') throw new UploadCancelledError();
            await refreshFromResume();
          }
        }
        while (queue.length > 0) {
          if (controller?.cancelled) throw new UploadCancelledError();
          const { part_number, url } = queue[0];
          // ⚠⚠ THE STALENESS GUARD, and it is the whole safety of this change.
          // `refreshFromResume` REBUILDS `queue` mid-flight (exhaustion pause,
          // finalize pause), so a part sealed ahead may no longer be the one due.
          // Sending it would upload correct ciphertext under the WRONG part
          // number — an error the AEAD would catch only at download, long after
          // the upload reported success.
          // ⭐ So the prefetch is USED ONLY IF IT MATCHES the part now due, and
          // discarded otherwise. Acting on a stale prefetch is unrepresentable
          // rather than merely unlikely.
          // ⚠ `.catch(() => null)` HERE, not just on the side: a rejected
          // prefetch must fall through to the re-derive below rather than
          // fail the upload. The side `.catch` suppresses the unhandled-
          // rejection warning; it does not make this `await` safe. For a
          // deterministic seal error the outcome is the same either way —
          // for a transient Blob-read hiccup, re-deriving succeeds.
          // (Gus F2, S174: the comment promised this and the code did not.)
          let prepared = ahead ? await ahead.catch(() => null) : null;
          ahead = null;
          if (prepared && prepared.partNumber !== part_number) prepared = null;
          const { envelope } = prepared ?? (await prepare(queue[0]));
          // Start the NEXT part's read+seal before sending this one — the whole
          // point. Bounded at one part ahead, so in-flight memory is 2 x chunk.
          if (prepareAhead > 0 && queue.length > 1 && !controller?.cancelled) {
            ahead = prepare(queue[1]);
            // An unconsumed prefetch must not surface as an unhandled rejection
            // if this part throws first; the value is re-derived when needed.
            ahead.catch(() => undefined);
          }
          // F3: in flight from here until it lands or fails (serial path).
          inFlightParts += 1;
          report();
          let skippedStored = false;
          let attemptEpoch = hideEpoch;
          let attemptStartedVisible = controller?.isVisible ?? true;
          try {
            const startedAt = Date.now();
            // 3a-i (S175): stamp the estimate's epoch per ATTEMPT (re-stamped on
            // each retry, so a retry's evidence stays fresh). Under upload
            // fan-out, one link event trips N parts at once; the stamp is how
            // the governor answers the burst once instead of N times.
            let attemptGeneration = governor.generation;
            const etag = await transferWithRetry(
              async (attempt) => {
                // F4: as in the pool — a retry after a hidden interval refreshes
                // and skips a part the server already stored.
                if (attempt > 1) {
                  await refreshIfHiddenDuring(attemptEpoch, attemptStartedVisible);
                  const stored = etags.get(part_number);
                  if (stored !== undefined) {
                    skippedStored = true;
                    return stored;
                  }
                }
                attemptEpoch = hideEpoch;
                attemptStartedVisible = controller?.isVisible ?? true;
                attemptGeneration = governor.generation;
                // F2: one slot per attempt on the serial path too — a private
                // pool of 1 here is a no-op, a shared pool bounds this file's
                // single stream against the batch's other files.
                const release = await pool.acquire();
                try {
                  return await this.api.putPart(url, envelope, {
                    // Rate-derived, never a fixed number of seconds.
                    ceilingMs: governor.ceilingMs(envelope.byteLength) ?? undefined,
                    // bug076: a user cancel aborts THIS attempt's socket promptly.
                    onAbortReady: controller
                      ? (abort) => controller.registerInFlightAbort(abort)
                      : undefined,
                  });
                } finally {
                  release();
                }
              },
              knobs,
              'upload',
              {
                onRetry: (_attempt, _attempts, error) => {
                  retries += 1;
                  // Retreat only when the failure actually indicts our rate
                  // estimate — a stall, or a network-level failure with no HTTP
                  // response. A 5xx is storage hiccuping, not evidence about our
                  // bandwidth, and halving on it would draw a conclusion the
                  // evidence does not support. Matches the CLI's rule exactly
                  // (`http.rs` relaxes only on `transfer_stalled`); the two had
                  // drifted apart. Gus, S127 W1.
                  if (indicatesRateOverestimate(error)) {
                    governor.penalizeStall(attemptGeneration);
                  }
                  report();
                },
                // Coverage row 18 (bug075): the server said "full, wait N
                // seconds". Surface it as its own honest state instead of a
                // frozen bar. ⚠ This does NOT touch the governor: a capacity
                // refusal is the server rationing slots, not evidence about
                // this client's bandwidth — the same distinction `onRetry`
                // above draws for a 5xx (Gus, S127 W1).
                onBusy: (retryAfterSeconds) => {
                  waitingForCapacitySeconds = retryAfterSeconds;
                  report();
                },
              },
            );
            controller?.registerInFlightAbort(null);
            // Row 18: a part landed, so we are demonstrably no longer waiting
            // on capacity. Cleared HERE — on observed progress — rather than on
            // a timer, so the state can never outlive the condition it names.
            waitingForCapacitySeconds = null;
            if (!skippedStored) governor.observePart(envelope.byteLength, Date.now() - startedAt);
            etags.set(part_number, etag);
            queue.shift();
            inFlightParts -= 1;
            report();
          } catch (error) {
            inFlightParts -= 1;
            // bug076: an aborted-by-cancel attempt (TransferCancelledError, or any
            // failure while cancel is requested) is the user's decision, not a
            // network verdict — surface it as the cancel it is.
            if (controller?.cancelled) throw new UploadCancelledError();
            if (!(error instanceof TransferExhaustedError) || !controller) throw error;
            // The retry budget is exhausted (classically bug047's bad network
            // window, but S185 measured an expired presigned URL producing the
            // IDENTICAL exhaustion — the cause is NOT knowable here, only the
            // count): PAUSE resumably — never silently die — and wait for the
            // user.
            report(true);
            const action = await controller.waitForResume();
            if (action === 'cancel') throw new UploadCancelledError();
            // Resumed: refresh the authoritative state (refreshFromResume — the
            // same surface the CLI's cross-run resume uses, #298).
            await refreshFromResume();
          }
        }
        const parts = [...etags.entries()]
          .sort(([a], [b]) => a - b)
          .map(([part_number, etag]) => ({ part_number, etag }));
        // bug050 (web face): every part is stored — the transfer is DONE. A
        // transient finalize failure (a network blip, a 5xx) must not fall to
        // the abort path below and destroy a fully-transferred upload: pause
        // resumably and let Resume re-drive /resume → re-complete (the resume
        // response then reports every part stored, none to send; the part loop
        // above is a no-op and this finalize re-runs — and if storage somehow
        // lost a part, the refreshed queue re-uploads exactly that part first).
        // Only a definitive server verdict (a 4xx — e.g. the upload was swept)
        // or a controller-less caller falls through to the abort path. The
        // reload=rollback boundary is unchanged (a File handle cannot survive
        // a reload); this governs in-session failures only.
        // ── bug211 §11: the finalize gets a retry budget ──────────────────
        //
        // ⭐ Chris's bar (S182): "we don't want a user to have to [click
        // Resume]. The upload should just complete." This used to call
        // `completeMultipart` ONCE and, on any retryable failure, park on
        // `waitForResume()` — a human click. Part uploads get 10 attempts; the
        // finalize got zero, which runs backwards: by the time a user reaches
        // the finalize they have spent hours uploading.
        //
        // ⭐ Why a retry actually WORKS here rather than just trying again:
        // measured at S182, the storage-side merge completes 5-12 s AFTER our
        // bound cuts it. So attempt 2 lands when the object already exists, and
        // bug212's server-side probe finalizes it FORWARD — the file appears
        // with no user action. Neither fix delivers that alone.
        //
        // ⚠ The budget stays LEAN on purpose (served, default 3). Exhausting it
        // is no longer "the upload is lost": 212's recovery means the parked
        // state is recoverable by resume OR by the sweeper. And a large budget
        // against a part-count-sized deadline is how you get an hour of spinner
        // on a deterministic failure (Gus).
        let finalizeError: unknown = null;
        for (let attempt = 1; attempt <= finalizeAttempts_; attempt += 1) {
          try {
            const view = await this.api.completeMultipart(fileId, initiate.upload_id, { parts });
            if (controller) {
              controller.active = null;
              controller.onVisibility = null;
            }
            return view;
          } catch (error) {
            finalizeError = error;
            if (!controller || !isRetryable(error)) throw error;
            if (attempt < finalizeAttempts_) {
              // Same backoff the part path uses; `attempt + 2` starts at a real
              // delay rather than the 0 ms double-tap, because the condition we
              // are waiting out is ELAPSED TIME (the merge landing), not a fresh
              // try — bug209's lesson about attempts 1 and 2 firing ~1 ms apart.
              await sleep(backoffMs(attempt + 2));
              report();
            }
          }
        }
        // Budget spent: park resumably, exactly as before.
        if (!controller || !isRetryable(finalizeError)) throw finalizeError;
        report(true);
        {
          const action = await controller.waitForResume();
          if (action === 'cancel') throw new UploadCancelledError();
          await refreshFromResume();
        }
      }
    } catch (error) {
      // ── bug212 G2 (Gus, narrowed at S182) ─────────────────────────────────
      // Free the reservation on failure by aborting — but once EVERY part is
      // stored, suppress that auto-abort for the CONFLICT class (409) alone.
      // On these endpoints a 409 is the server's answer whenever a merge MAY be
      // running (resume's Absent/Unknown/OverDeclared arms, the CAS-loss, the
      // abort refusals — multipart.rs). Aborting into that window is the
      // DEK-cascade danger: the server's probe would see an as-yet-unmaterialised
      // object, reclaim the row, and the merge would then land orphaned.
      //
      // A 404 is the opposite: it CERTIFIES the pending row is gone (swept, or
      // already finalized/active — resolve_in_progress). A follow-up abort on a
      // 404 cannot resolve any row, so it is harmless in every reachable state —
      // which is exactly bug050's definitive-verdict contract (a swept 404 still
      // fires its cleanup abort), preserved unchanged. A genuine user CANCEL
      // always aborts (user intent; the server-side probe governs what it may
      // do). A retryable 5xx/network finalize failure never reaches here — the
      // finalize loop above parks it on resume.
      const allPartsStored = etags.size >= chunkCount;
      const status =
        error && typeof error === 'object' && 'status' in error
          ? (error as { status: number }).status
          : undefined;
      const inMergeConflict =
        allPartsStored && status === 409 && !(error instanceof UploadCancelledError);
      if (!inMergeConflict) {
        await this.api.abortMultipart(fileId, initiate.upload_id).catch(() => undefined);
      }
      if (controller) {
        controller.active = null;
        controller.onVisibility = null;
      }
      throw error;
    }
  }

  /** Download + decrypt a file, buffering the whole plaintext in memory.
   *
   *  ⚠ bug179: peak memory is the file size. Prefer {@link downloadFileTo} with
   *  a streaming sink wherever one is available — this overload exists for the
   *  fallback path (browsers without the File System Access API) and for tests.
   *
   *  The §4.2 multipart file is fetched chunk-by-chunk via Range reads of its
   *  pre-signed GetObject URL (each chunk opened with AAD = file_id‖chunk_index,
   *  position-checked). The legacy single-PUT (§4.1) transport was retired (S042). */
  async downloadFile(
    fileId: string,
    onProgress?: (progress: DownloadProgress) => void,
  ): Promise<Bytes> {
    const parts: Bytes[] = [];
    await this.downloadFileTo(
      fileId,
      {
        write: async (chunk) => {
          parts.push(chunk);
        },
        close: async () => {},
        abort: async () => {
          parts.length = 0;
        },
      },
      onProgress,
    );
    return concat(parts);
  }

  /** bug179: download + decrypt a file, handing each verified chunk to `sink`
   *  as it opens. **Peak memory is bounded at the window**, not the file.
   *
   *  ⭐ ONE chunk loop serves this, {@link downloadFile} (buffering sink) and
   *  {@link downloadFileVia} (sink factory). Copies would drift — ROOTS §B-3.5,
   *  and the loop carries the AAD/position checks that make a chunk trustworthy.
   *
   *  ⭐ **Only verified plaintext is ever written.** `openChunk` performs the
   *  AEAD open, so a chunk reaching `sink.write` has already had its tag
   *  verified against AAD = file_id‖chunk_index — bug061's honesty rule is
   *  preserved by construction, not by ordering discipline.
   *
   *  ⚠ **The sink commits only on `close`.** Any failure calls `abort` instead,
   *  so a partial download never lands. That is the web half of bug180's
   *  rename-on-success. */
  async downloadFileTo(
    fileId: string,
    sink: DownloadSink,
    onProgress?: (progress: DownloadProgress) => void,
  ): Promise<void> {
    await this.downloadFileVia(fileId, async () => sink, onProgress);
  }

  /** bug193 (v03): like {@link downloadFileTo}, but the sink is built AFTER the
   *  chunk metadata is known — `makeSink` receives the file's plaintext length
   *  and the served web knobs, which is what lets the SW-streamed sink carry an
   *  honest `Content-Length` (Gus F1) and the fallback refuse PRE-FLIGHT. */
  async downloadFileVia(
    fileId: string,
    makeSink: (meta: DownloadSinkMeta) => Promise<DownloadSink>,
    onProgress?: (progress: DownloadProgress) => void,
  ): Promise<void> {
    const { wrapped_dek } = await this.api.getWrappedDek(fileId);
    const dek = await this.unwrapDekEnvelope(wrapped_dek);
    const fileIdBytes = uuidToBytes(fileId);
    const {
      download_url: initialDownloadUrl,
      size_bytes,
      multipart_chunks,
      chunk_size,
      concurrency,
      web_sw_download_enabled,
      web_download_buffer_cap_bytes,
      download_part_retry_attempts,
      expires_at: initialExpiresAt,
    } = await this.api.getDownloadUrl(fileId);

    // ⚠⚠ THE PRE-SIGNED URL EXPIRES MID-DOWNLOAD ON A LARGE FILE, AND THE CLIENT
    // CANNOT SEE IT HAPPEN. `DOWNLOAD_URL_TTL_SECS` is 3600 (server
    // `multipart.rs:54`), whose comment claims "the client re-requests a fresh URL
    // if a very large download outlives the window" — nothing implemented that.
    //
    // Observed live (S184, 100 GB web download): every range fetch past the
    // expiry returned S3 **403**, and because S3 omits CORS headers on an error
    // response the browser surfaces it as `TypeError: Failed to fetch` with NO
    // status. ⇒ **Expiry is INDISTINGUISHABLE from a network blip at this layer**,
    // so the retry budget was spent re-fetching a URL that could never work; all
    // ten attempts carried the identical `X-Amz-Signature`.
    //
    // ⚠ A wall-clock TTL bounding a `bytes ÷ rate` quantity silently declares a
    // MINIMUM DOWNLOAD BANDWIDTH (ROOTS §B-3.4, the bug060 class): at 3600 s a
    // 100 GB file demands ~222 Mbps, and every honest link below that fails at a
    // size that scales with the link. Raising the constant only moves the floor.
    //
    // ⇒ Refresh PROACTIVELY on the clock, never reactively on the error: the
    // failure is invisible, so waiting to observe it is waiting for a signal that
    // does not arrive. The server already returns `expires_at`; it was received
    // and discarded here.
    let downloadUrl = initialDownloadUrl;
    let urlExpiresAt = initialExpiresAt;

    /** Headroom before stated expiry at which we PROACTIVELY re-presign.
     *
     *  ⭐ The quantity to cover is GUARD-TO-DISPATCH, not guard-to-completion,
     *  because **S3 validates the signature when the request is DISPATCHED, not
     *  while it streams.** A range fetch that leaves with a live signature
     *  completes normally however long it takes; only fetches *issued* after
     *  expiry are rejected. So the margin must cover: the presign round-trip when
     *  we do refresh (seconds), the guard-to-`fetch` gap when we do not
     *  (microseconds — no await between them), and honest client/server clock
     *  drift. 300 s clears all three by orders of magnitude. A dishonest clock is
     *  NOT this constant's job: the `attempt > 1` forced refresh below is what
     *  survives that, at a cost of one already-budgeted failure.
     *
     *  Evidence for dispatch-validation, from the live S185 failure rather than
     *  from the S3 docs: the 403s and successes INTERLEAVED — `chunk-done
     *  {index: 4755}` landed *inside* the 403 storm, an in-flight request that had
     *  been dispatched pre-expiry finishing long after it. That ragged edge is
     *  only possible if validation happens at dispatch.
     *
     *  ⛔ THIS PARAGRAPH PREVIOUSLY DERIVED THE MARGIN WRONGLY, AND THE ERROR IS
     *  KEPT HERE ON PURPOSE. It added "one chunk's in-flight ceiling
     *  (`downloadBackstopMs`, ≤ tens of seconds at 16 MiB)" as a term. Both halves
     *  were false: the term does not belong (dispatch-validation, above), and the
     *  figure was invented — `downloadBackstopMs` is rate-derived against a
     *  500 kbps floor (`api.ts`), so at 16 MiB it is **1,073,744 ms ≈ 17.9 min**,
     *  a number printed in every `range-start` trace line of the very log that
     *  proved the defect. Taken seriously the old derivation demanded a margin
     *  > ~1,074 s and so invalidated its own 300. ⚠ The number was right and the
     *  reasoning was wrong — which is the failure mode a derivation-in-a-comment
     *  exists to catch, so leaving the correction visible is the point of it.
     *  (Gus, S185 attack A7.)
     *
     *  It remains a margin on a deadline we are GIVEN, never a rate threshold we
     *  invented — §B-3.4's distinction, and the reason this is not itself a
     *  wall-clock bound on a `bytes ÷ rate` quantity. */
    const URL_REFRESH_MARGIN_SECS = 300;

    /** Return a live download URL, re-presigning when needed.
     *
     *  Two triggers, and the second is the correctness backstop (Gus, S184):
     *  - **proactive**: within the margin of stated expiry — avoids the first 403.
     *  - **forced** (`force=true`, passed on any retry): re-presign
     *    UNCONDITIONALLY. Retrying a URL that just failed is the anti-pattern
     *    regardless of *why* it failed — and because an expired-URL 403 is
     *    indistinguishable from a network blip here (S3 drops CORS headers on
     *    errors ⇒ a bare `TypeError`), this is the ONLY expiry defence that
     *    survives an arbitrarily wrong client clock. A re-presign costs one API
     *    call; a failed attempt is already evidence some assumption was wrong.
     *
     *  ⚠ Idempotent and cheap: a no-op when there is headroom and not forced. */
    const freshDownloadUrl = async (force = false): Promise<string> => {
      const nowSecs = Math.floor(Date.now() / 1000);
      if (!force && nowSecs < urlExpiresAt - URL_REFRESH_MARGIN_SECS) return downloadUrl;
      trace('download-url-refresh', {
        reason: force ? 'retry-forced' : 'proactive-margin',
        expiresInSecs: urlExpiresAt - nowSecs,
        marginSecs: URL_REFRESH_MARGIN_SECS,
      });
      const refreshed = await this.api.getDownloadUrl(fileId);
      downloadUrl = refreshed.download_url;
      urlExpiresAt = refreshed.expires_at;
      return downloadUrl;
    };

    // §4.2 multipart only — the legacy single-PUT (§4.1) transport was retired (S042).
    if (multipart_chunks === null || chunk_size === null) {
      throw new IntegrityError('download-url returned no multipart chunk metadata');
    }

    // bug061: report a 0-baseline now that the totals are known, then a tick per
    // completed chunk below — so the UI shows honest progress across the (on a
    // slow link, ~100 s) transfer instead of a frozen-looking screen.
    // The sink is built from the metadata (v03: Content-Length for the SW path,
    // the pre-flight cap for the fallback), BEFORE any progress is shown — a
    // refusal must never render behind a started-looking banner (bug187's rule).
    const sink = await makeSink({
      plaintextBytes: plaintextLength(size_bytes, multipart_chunks),
      totalChunks: multipart_chunks,
      swDownloadEnabled: web_sw_download_enabled ?? true,
      bufferCapBytes: web_download_buffer_cap_bytes ?? DEFAULT_WEB_DOWNLOAD_BUFFER_CAP,
    });
    onProgress?.({
      completedChunks: 0,
      totalChunks: multipart_chunks,
      receivedBytes: 0,
      totalBytes: size_bytes,
    });

    // §4.2 multipart: each on-disk chunk is `chunk_size + overhead` bytes (the last
    // is whatever remains), Range-fetched and opened in order. Each Range-GET
    // carries a defensive fresh-connection retry (bug047 symmetry — downloads
    // measured clean in the same bad windows uploads stalled; exp B).
    // bug209 (S181): SERVED, not compiled. Was a hard-coded `attempts: 3` that read
    // no knob at all, while two documents said 10 and the upload path has served
    // `multipart_part_retry_attempts` since migration 0036 — three surfaces, three
    // answers, one of them compiled. Migration 0036's own header names the standing
    // rule this violated ("the no-hard-coded-control-numbers rule").
    const downloadKnobs: TransferKnobs = {
      attempts: downloadRetryAttempts(download_part_retry_attempts),
    };
    const onDiskChunk = chunk_size + MULTIPART_CHUNK_OVERHEAD;
    const n = downloadConcurrency(concurrency);
    const chunkEnd = (index: number) =>
      index < multipart_chunks - 1 ? index * onDiskChunk + onDiskChunk - 1 : size_bytes - 1;
    try {
      // bug193 (S176): a SLIDING WINDOW replaces the S174 rounds loop. The old
      // round joined all `n` fetches before draining, so every round cost its
      // slowest member — measured at 2.41× effective parallelism against the
      // upload path's 3.83–3.92× at the same `n` (~26% of wall clock lost at the
      // barriers; next-start waited for the SLOWEST of the prior round on 10/10
      // measured transitions). Now a new fetch starts the moment the window has
      // room. Owner: bug193 + Download-Loop-Rewrite v03 §3a.
      //
      // ⭐⭐ THE SINK STILL NEVER SEES AN OUT-OF-ORDER WRITE. Completed chunks
      // ahead of the head wait in `opened` — the reorder head (v03 §3b) — and
      // only the contiguous run drains. The window counts STARTED-BUT-UNWRITTEN
      // chunks, so `opened` is bounded at `n − 1` and total in-flight memory
      // stays `n × chunk` (transiently ~2x while an envelope opens), the same
      // bound the rounds loop had. The streaming property survives by
      // construction rather than by the acceptance test noticing.
      //
      // ⚠ The head-of-line case is inherent: if the OLDEST chunk is the slow
      // one, starts stall until it lands — bounded memory with an in-order sink
      // permits nothing better. The measured upload-side shape (3.86×) is the
      // realistic ceiling, not 4.0.
      const opened = new Map<number, Bytes>();
      const inFlight = new Map<number, Promise<void>>();
      let firstError: unknown = null;
      let sawError = false;
      let nextStart = 0;
      let nextWrite = 0;
      while (nextWrite < multipart_chunks) {
        if (sawError) throw firstError;
        while (nextStart < multipart_chunks && nextStart - nextWrite < n && !sawError) {
          const index = nextStart++;
          const task = (async () => {
            trace('chunk-start', { index, of: multipart_chunks });
            const envelope = await transferWithRetry(
              // ⚠ Resolved INSIDE the attempt factory, not captured outside it: a
              // URL captured once is exactly the defect this fixes. `attempt > 1`
              // forces a re-presign — the backstop that survives a wrong clock.
              async (attempt) =>
                this.api.getRange(
                  await freshDownloadUrl(attempt > 1),
                  index * onDiskChunk,
                  chunkEnd(index),
                ),
              downloadKnobs,
              'download',
            );
            trace('chunk-done', { index });
            // openChunk verifies before it returns: what reaches the sink is
            // authenticated plaintext, never a byte we have not checked (bug061).
            opened.set(index, await openChunk(dek, fileIdBytes, index, multipart_chunks, envelope));
          })();
          inFlight.set(
            index,
            task
              .catch((error: unknown) => {
                // First error wins; the others drain (the CLI half's semantics).
                if (!sawError) {
                  sawError = true;
                  firstError = error;
                  // ⚠ FIRST ERROR WINS and the others drain — so this is the ONLY
                  // place the killing error's identity is unambiguous. By the time
                  // it reaches the banner it is one flattened string.
                  trace('loop-first-error', { index, ...errorIdentity(error) });
                }
              })
              .finally(() => {
                inFlight.delete(index);
              }),
          );
        }
        if (!opened.has(nextWrite)) {
          if (inFlight.size === 0) {
            // Completeness assertion (v03 §2's sibling): the head is neither
            // opened nor in flight and no error was recorded — refuse to stall
            // silently rather than hang a green-looking transfer.
            if (sawError) throw firstError;
            throw new IntegrityError('download scheduler stalled with no error recorded');
          }
          await Promise.race(inFlight.values());
          continue;
        }
        while (opened.has(nextWrite)) {
          const chunk = opened.get(nextWrite)!;
          opened.delete(nextWrite);
          await sink.write(chunk);
          // A chunk is counted only once fetched, opened AND written — every
          // tick is real bytes delivered (bug061). Ticking per WRITE rather than
          // per fetch keeps that true under concurrency: a fetched-but-unwritten
          // chunk is not progress the user can rely on.
          onProgress?.({
            completedChunks: nextWrite + 1,
            totalChunks: multipart_chunks,
            receivedBytes: chunkEnd(nextWrite) + 1,
            totalBytes: size_bytes,
          });
          nextWrite++;
        }
      }
    } catch (error) {
      // bug179/bug180: discard rather than commit. A failed download must leave
      // nothing, not a valid-but-short file. Best-effort — the caller is owed
      // the ORIGINAL error, never a cleanup failure that masks it.
      await sink.abort().catch(() => undefined);
      throw error;
    }
    // The commit point, reached only when every chunk opened.
    await sink.close();
  }

  /** Decrypt a folder's name (a root uses its own metadata key; a nested folder
   *  uses its root's). */
  async folderName(folder: FolderView): Promise<string> {
    const rootFolderId = folder.root_folder_id ?? folder.folder_id;
    const metadataKey = await this.metadataKey(rootFolderId);
    return decryptName(
      metadataKey,
      uuidToBytes(rootFolderId),
      uuidToBytes(folder.folder_id),
      folder.encrypted_name as NameEnvelope,
    );
  }

  /** Decrypt a file's name under its folder hierarchy's root metadata key. */
  async fileName(file: FileView, rootFolderId: string): Promise<string> {
    const metadataKey = await this.metadataKey(rootFolderId);
    return decryptName(
      metadataKey,
      uuidToBytes(rootFolderId),
      uuidToBytes(file.file_id),
      file.encrypted_name as NameEnvelope,
    );
  }

  /** EVERY top-level folder, or EVERY child of `parentFolderId` — the cursor is
   *  followed to exhaustion (no crypto; names are decrypted separately via
   *  {@link folderName}).
   *
   *  ⛔ EXHAUSTIVE BY CONTRACT (bug241). These wrappers previously forwarded one
   *  page and dropped `next_cursor`, so the web Drive showed at most 50 folders
   *  and 50 files per folder — the 51st invisible, with no message and no
   *  load-more. The return type omits `next_cursor` deliberately: there is no
   *  more to fetch, and a load-more written against this fails to compile rather
   *  than reading a field that would always be null.
   *
   *  ⚠ A caller that genuinely wants ONE page must use `this.api.*` directly —
   *  which is what {@link filesUnder} does. */
  async listFolders(parentFolderId?: string): Promise<Pick<ListFoldersResponse, 'folders'>> {
    const folders = await fetchAllPages(async (cursor) => {
      const page = await this.api.listFolders(parentFolderId, cursor);
      return { items: page.folders, next_cursor: page.next_cursor };
    });
    return { folders };
  }

  /** EVERY file in `folderId` — the cursor is followed to exhaustion. Exhaustive
   *  by contract; see {@link listFolders} for why the return type omits
   *  `next_cursor`. (Names are decrypted separately via {@link fileName}.) */
  async listFiles(folderId: string): Promise<Pick<ListFilesResponse, 'files'>> {
    const files = await fetchAllPages(async (cursor) => {
      const page = await this.api.listFiles(folderId, cursor);
      return { items: page.files, next_cursor: page.next_cursor };
    });
    return { files };
  }

  /** Rename a folder: re-encrypt the name under the same metadata key. The §7.3
   *  AAD (root_folder_id‖folder_id) is unchanged, so only the plaintext differs. */
  async renameFolder(folder: FolderView, newName: string): Promise<FolderView> {
    const rootFolderId = folder.root_folder_id ?? folder.folder_id;
    const metadataKey = await this.metadataKey(rootFolderId);
    const encryptedName = await encryptName(
      metadataKey,
      uuidToBytes(rootFolderId),
      uuidToBytes(folder.folder_id),
      newName,
    );
    return this.api.updateFolder(folder.folder_id, { encrypted_name: encryptedName });
  }

  /** Rename a file: re-encrypt the name under its root's metadata key. */
  async renameFile(file: FileView, rootFolderId: string, newName: string): Promise<FileView> {
    const metadataKey = await this.metadataKey(rootFolderId);
    const encryptedName = await encryptName(
      metadataKey,
      uuidToBytes(rootFolderId),
      uuidToBytes(file.file_id),
      newName,
    );
    return this.api.updateFile(file.file_id, { encrypted_name: encryptedName });
  }

  /** Move a folder under a new parent within the same root (server-enforced). No
   *  name re-encryption — the §7.3 AAD binds root + folder id, both unchanged. */
  moveFolder(folderId: string, targetParentId: string): Promise<FolderView> {
    return this.api.updateFolder(folderId, { parent_folder_id: targetParentId });
  }

  /** Move a file into another folder within the same root (server-enforced). No
   *  name re-encryption — the §7.3 AAD binds root + file id, both unchanged. */
  moveFile(fileId: string, targetFolderId: string): Promise<FileView> {
    return this.api.updateFile(fileId, { folder_id: targetFolderId });
  }

  /** Delete a single file. */
  deleteFile(fileId: string): Promise<void> {
    return this.api.deleteFile(fileId);
  }

  /** Delete a single folder (its children + files cascade server-side). */
  deleteFolder(folderId: string): Promise<void> {
    return this.api.deleteFolder(folderId);
  }

  /** Delete several files at once (all-or-nothing); returns the count deleted. */
  async deleteFiles(fileIds: string[]): Promise<number> {
    const { deleted } = await this.api.deleteFilesBatch(fileIds);
    return deleted;
  }

  /** Delete several folders at once (all-or-nothing); returns the count deleted. */
  async deleteFolders(folderIds: string[]): Promise<number> {
    const { deleted } = await this.api.deleteFoldersBatch(folderIds);
    return deleted;
  }

  /** Storage usage + limit (plaintext metadata — no crypto). */
  quota(): Promise<QuotaResponse> {
    return this.api.getQuota();
  }

  /** The signed-in account's self-view: kind (human vs PRSN), handle, and a
   *  PRSN's Guardian + sharing capability. Drives View 1 vs the 1b variant. */
  me(): Promise<MeResponse> {
    return this.api.getMe();
  }

  /** Resolve a recipient handle to their verified hybrid key bundle: the full
   *  verified-source resolution (F-DOWNGRADE a+b) — fingerprints, mandatory
   *  hybrid, and the keys verified against the recipient's identity record
   *  (attestation for a PRSN, §10a log receipts for a human) before any
   *  secret is wrapped to them. */
  async recipientKey(
    handle: string,
  ): Promise<{ recipient: VerifiedRecipient; view: RecipientKey }> {
    const view = await this.api.getRecipientKey(handle);
    const trust = new ServerTrust(this.api);
    // F-PIN1: `handle` is the user-typed name — the bundle's echo must match it.
    const recipient = await verifiedRecipient(
      trust,
      this.api,
      view,
      { userNamed: handle },
      `recipient '${handle}'`,
    );
    return { recipient, view };
  }

  /** Create a top-level share folder: a fresh metadata key wrapped to the owner
   *  and — for a PRSN owner — to its Guardian (the mandatory recipient, resolved
   *  + fingerprint-verified via /v1/recipients). The §7.3 name binds to the
   *  folder's own id (it is its own root). */
  async createShareFolder(name: string): Promise<ShareFolderView> {
    const folderId = crypto.randomUUID();
    const rootBytes = uuidToBytes(folderId);
    const metadataKey = randomBytes(32);
    const ownerWrap = await this.wrapMetadataKeyTo(this.selfRecipient(), metadataKey, rootBytes);
    const encryptedName = await encryptName(metadataKey, rootBytes, rootBytes, name);

    const body: CreateShareFolderBody = {
      folder_id: folderId,
      encrypted_name: encryptedName,
      owner_metadata_key_wrap: ownerWrap,
    };

    const me = await this.api.getMe();
    if (me.account_type === 'prsn') {
      const guardianHandle = me.guardian?.handle;
      if (!guardianHandle) {
        throw new InvalidInputError('a PRSN must have a Guardian to create a share folder');
      }
      // Hybrid when the Guardian's bundle is hybrid (§9.2/N6).
      const guardian = await this.recipientKey(guardianHandle);
      body.guardian_metadata_key_wrap = await this.wrapMetadataKeyTo(
        guardian.recipient,
        metadataKey,
        rootBytes,
      );
    }

    const view = await this.api.createShareFolder(body);
    this.metadataKeys.set(folderId, metadataKey);
    return view;
  }

  /** List a share folder's recipients (handles + permissions). */
  listRecipients(folderId: string): Promise<RecipientsResponse> {
    return this.api.listRecipients(folderId);
  }

  /** The folder's pending invitations — the owner's view (S121, W6). */
  listInvitations(folderId: string): Promise<PendingInvitationsResponse> {
    return this.api.listInvitations(folderId);
  }

  /** Cancel a pending invitation (owner action; releases the write-lock). */
  cancelInvitation(folderId: string, invitationId: string): Promise<void> {
    return this.api.cancelInvitation(folderId, invitationId);
  }

  /** The share folders the caller is a recipient of (shared with me). */
  sharedFolders(): Promise<SharedWithMeResponse> {
    return this.api.listSharedWithMe();
  }

  /** The PRSNs under the caller's guardianship (humans only; empty for a PRSN). */
  listPrsns(): Promise<ListPrsnsResponse> {
    return this.api.listPrsns();
  }

  /** Invite a recipient to a share folder: wrap the folder's metadata key + every
   *  file's DEK to the recipient's KEM key. These pre-computed wraps are what the
   *  server stages and the recipient activates on accept — the first time the
   *  client wraps secrets to someone else's key. The recipient's fingerprint is
   *  verified (P-011) before anything is wrapped to it. */
  async inviteToShareFolder(
    folder: { folderId: string; rootFolderId: string },
    recipientHandle: string,
    permission: string,
  ): Promise<CreateInvitationResponse> {
    const { recipient } = await this.recipientKey(recipientHandle);
    const rootBytes = uuidToBytes(folder.rootFolderId);

    const metadataKey = await this.metadataKey(folder.rootFolderId);
    const metadataKeyWrap = await this.wrapMetadataKeyTo(recipient, metadataKey, rootBytes);

    const fileIds = await this.filesUnder(folder.folderId);
    const fileDekWraps = await Promise.all(
      fileIds.map(async (fileId) => {
        const { wrapped_dek } = await this.api.getWrappedDek(fileId);
        const dek = await this.unwrapDekEnvelope(wrapped_dek);
        return { file_id: fileId, wrap: await this.wrapDekTo(recipient, dek) };
      }),
    );

    const body: CreateInvitationBody = {
      recipient_handle: recipientHandle,
      permission,
      pre_computed_wraps: { metadata_key_wrap: metadataKeyWrap, file_dek_wraps: fileDekWraps },
    };
    return this.api.createInvitation(folder.folderId, body);
  }

  /** Preview an invitation (inviter, permission, file count, timing). */
  previewInvitation(token: string): Promise<InvitationPreview> {
    return this.api.previewInvitation(token);
  }

  /** Accept an invitation — activates the pre-staged wraps, after which the folder
   *  appears in the recipient's browser with names + contents decryptable. */
  acceptInvitation(token: string): Promise<AcceptInvitationResponse> {
    return this.api.acceptInvitation(token);
  }

  /** Remove a recipient from a share folder (owner action). */
  removeRecipient(folderId: string, recipientId: string): Promise<void> {
    return this.api.removeRecipient(folderId, recipientId);
  }

  /** Leave a share folder (recipient self-removal). */
  leaveShareFolder(folderId: string): Promise<void> {
    return this.api.leaveShareFolder(folderId);
  }

  /** Every file id under a folder (it + its subfolders), following pagination —
   *  the full set an invitation must re-wrap DEKs for. */
  private async filesUnder(folderId: string): Promise<string[]> {
    const fileIds: string[] = [];
    const queue: string[] = [folderId];
    while (queue.length > 0) {
      const current = queue.pop();
      if (current === undefined) break;
      // Both loops were hand-rolled here and correct, but had no no-progress
      // guard — a server repeating a cursor would spin a share forever. One
      // drain, one guard (bug241, Gus's A2).
      const files = await fetchAllPages(async (cursor) => {
        const page = await this.api.listFiles(current, cursor);
        return { items: page.files, next_cursor: page.next_cursor };
      });
      for (const file of files) fileIds.push(file.file_id);

      const subs = await fetchAllPages(async (cursor) => {
        const page = await this.api.listFolders(current, cursor);
        return { items: page.folders, next_cursor: page.next_cursor };
      });
      for (const sub of subs) queue.push(sub.folder_id);
    }
    return fileIds;
  }

  /** Drop cached metadata keys (call alongside the session clear on sign-out). */
  clearCache(): void {
    this.metadataKeys.clear();
  }

  /** The session KEM public key as raw X9.63 bytes (for self-wrap). */
  private selfPub(): Bytes {
    return b64uDecode(this.session.kemPubkeyX963);
  }

  /** The session ML-KEM encapsulation key (self-wrap PQ half — verified
   *  against the blob seed at sign-in). */
  private selfPq(): Bytes {
    return b64uDecode(this.session.kemPqPubkeyEk);
  }

  /** Wrap a DEK to a verified recipient — hybrid ALWAYS (mandatory hybrid
   *  write, F-DOWNGRADE(a)): the web writer has no classical-only arm at all.
   *  Unlike the CLI (whose retained arm sits behind the hard-off
   *  `classical-write` cargo feature for a future non-Mac custody decision),
   *  the browser is already cross-OS — no future rationale exists, so the
   *  code is simply gone. The classical READ path (unwrapDekEnvelope) stays. */
  private wrapDekTo(recipient: VerifiedRecipient, dek: Bytes): Promise<unknown> {
    if (!recipient.pqPubkey) {
      throw new IntegrityError(
        'refusing a classical-only DEK wrap (mandatory hybrid write, PQR §9.2)',
      );
    }
    return hybridWrapDek(recipient.pubkey, recipient.pqPubkey, dek);
  }

  /** Wrap a metadata key to a verified recipient (P-015 binds `root`) — the
   *  same mandatory-hybrid dispatch as {@link wrapDekTo}. */
  private wrapMetadataKeyTo(
    recipient: VerifiedRecipient,
    metadataKey: Bytes,
    rootBytes: Bytes,
  ): Promise<unknown> {
    if (!recipient.pqPubkey) {
      throw new IntegrityError(
        'refusing a classical-only metadata-key wrap (mandatory hybrid write, PQR §9.2)',
      );
    }
    return hybridWrapMetadataKey(recipient.pubkey, recipient.pqPubkey, metadataKey, rootBytes);
  }

  /** My own wrap target: a web session is ALWAYS hybrid (signup generates the
   *  ML-KEM identity; sign-in refuses a session without one), so self-wraps
   *  are hybrid unconditionally. */
  private selfRecipient(): VerifiedRecipient {
    return { pubkey: this.selfPub(), pqPubkey: this.selfPq() };
  }

  /** Unwrap a wrapped-DEK envelope addressed to me — classical or hybrid,
   *  dispatched on `alg` alone (§5.2), each side strictly parsed. */
  private async unwrapDekEnvelope(value: unknown): Promise<Bytes> {
    if (wrapAlgOf(value) === ECDH_ES_MLKEM1024_A256KW) {
      return hybridUnwrapDek(
        this.session.kemPrivateKey,
        this.session.mlkemSeed,
        parseHybridWrapEnvelope(value),
        this.selfPub(),
        this.selfPq(),
      );
    }
    return unwrapDek(this.session.kemPrivateKey, parseWrapEnvelope(value));
  }

  /** Fetch + unwrap (and cache) a root folder's metadata key (same dispatch
   *  as {@link unwrapDekEnvelope}, with the P-015 root binding). */
  private async metadataKey(rootFolderId: string): Promise<Bytes> {
    const cached = this.metadataKeys.get(rootFolderId);
    if (cached) return cached;
    const { wrapped_key } = await this.api.getMetadataKeyWrap(rootFolderId);
    const rootBytes = uuidToBytes(rootFolderId);
    const metadataKey =
      wrapAlgOf(wrapped_key) === ECDH_ES_MLKEM1024_A256KW
        ? await hybridUnwrapMetadataKey(
            this.session.kemPrivateKey,
            this.session.mlkemSeed,
            parseHybridWrapEnvelope(wrapped_key),
            this.selfPub(),
            this.selfPq(),
            rootBytes,
          )
        : await unwrapMetadataKey(
            this.session.kemPrivateKey,
            parseWrapEnvelope(wrapped_key),
            rootBytes,
          );
    this.metadataKeys.set(rootFolderId, metadataKey);
    return metadataKey;
  }
}
