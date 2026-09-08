// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Typed client for the B3 server endpoints the human web client uses (signup,
// passkey registration + sign-in ceremonies, KEM key init). The fetch impl is
// injectable — default is same-origin global fetch with the session cookie
// (`credentials: 'include'`); unit tests + flows inject a fake. Non-2xx responses
// are parsed from the `{ error: { code, message } }` envelope into SignetApiError.

import { RelayBusyError, StallError, TransferCancelledError } from './transfer';
import { trace, errorIdentity } from './trace';

/** How long a chunk download may wait for the store to *begin* answering
 *  `[rate-free]`. First-byte latency is a latency, not a transfer — it does not
 *  scale with the chunk size — so a constant legitimately bounds it. */
const DOWNLOAD_FIRST_BYTE_MS = 60_000;

/** No-progress gap for a chunk download `[rate-free]` — the honest detector for
 *  this path.
 *
 *  A download that delivers *any* bytes within this window is alive at any link
 *  speed, which is exactly why a constant is legitimate here and was not
 *  legitimate as a whole-chunk deadline (bug060 §1; W3). Download progress is
 *  genuine in a way socket-write progress is not: an arriving byte means a byte
 *  arrived, so unlike the upload path this needs no send-buffer correction.
 *
 *  ⚠ This is a *per-read* value and must never be used as a total. Doing exactly
 *  that was W5 — see [`downloadBackstopMs`]. */
const DOWNLOAD_GAP_MS = 20_000;

/** The slowest link a download is held open for, bytes/sec (0.5 Mbps) — matching
 *  the CLI transport's `MIN_CREDIBLE_RATE_BPS` so the two surfaces derive their
 *  backstops from the same floor. */
const DOWNLOAD_MIN_CREDIBLE_RATE = 500_000 / 8;

/** Generosity multiplier over the derived expectation `[dimensionless]`. */
const DOWNLOAD_BACKSTOP_K = 4;

/** Floor for the derived backstop `[rate-free]`, so a tiny range still gets a
 *  sane allowance. */
const DOWNLOAD_BACKSTOP_FLOOR_MS = 300_000;

/** Upper clamp on the derived backstop `[rate-free]` — 24 h, matching the CLI
 *  transport's own `.min(86_400)` on `response_backstop`.
 *
 *  **Not cosmetic: without it the backstop inverts.** `setTimeout` takes a signed
 *  32-bit delay, so any value above 2³¹−1 ms (~24.8 days) **fires immediately** in
 *  browsers rather than never — turning a last-resort ceiling into an instant
 *  abort that would fail every attempt of that download. The derived value crosses
 *  that limit above a ~33.5 GiB range.
 *
 *  Unreachable today (a chunk is one §4.2 envelope, ≤64 MiB, and the server caps
 *  part size), so this is latent — but it is exactly the class this arc has been
 *  clearing, and the CLI already had the clamp. **I wrote both surfaces hours
 *  apart today and clamped only one** — the same decision made twice, correct
 *  once, which is the divergence mechanism in miniature (Gus, S127 W6). */
const DOWNLOAD_BACKSTOP_MAX_MS = 86_400_000;

/** Absolute per-chunk ceiling for a download, **derived from the requested
 *  range** — the download counterpart of the transport's `response_backstop`.
 *
 *  # Why a gap alone is not enough (W4)
 *
 *  The no-progress gap is a correct dead-flow detector, but a sender delivering
 *  one byte just under it is making *genuine* progress, so the gap correctly
 *  allows it — forever, if nothing else caps the total. That "one byte per op,
 *  just under the threshold" case is the adversarial-trickle residual the upload
 *  transport documents as accepted — and it is accepted there **because the
 *  governor ceiling bounds it absolutely**. On the CLI download it is bounded by
 *  `response_backstop`. Here it was bounded by nothing: only per-read timers, and
 *  `transferWithRetry` caps attempt *count*, not time. The one residual every
 *  other path caps was uncapped on this one.
 *
 *  # Why this does not itself violate §1
 *
 *  It scales with the bytes actually requested, against a stated worst-case link.
 *  The constant floor applies only where the quantity is genuinely rate-free (a
 *  trivially small range). Same shape as the transport's backstop:
 *  `max(floor, k × expected)`, never a bare constant — which is precisely the
 *  mistake W5 made by reusing the per-read gap value as an atomic total. */
export function downloadBackstopMs(bytes: number): number {
  const expectedMs = (bytes / DOWNLOAD_MIN_CREDIBLE_RATE) * 1000;
  const derived = Math.max(DOWNLOAD_BACKSTOP_FLOOR_MS, expectedMs * DOWNLOAD_BACKSTOP_K);
  return Math.min(derived, DOWNLOAD_BACKSTOP_MAX_MS);
}

/** The server's declared code for "the relay has too many parts in flight"
 *  (`ErrorCode::RelayAtCapacity` → `"relay_at_capacity"`, `server/src/error.rs`). */
const RELAY_AT_CAPACITY_CODE = 'relay_at_capacity';

/** bug219 — does this response body carry OUR at-capacity envelope?
 *
 *  Replaces the URL-shape test (`url.startsWith('/')`) that identified a relay
 *  response before parts moved to a dedicated upload host. ⚠ A URL-shape test is
 *  a claim about the DEPLOYMENT TOPOLOGY; this is a claim about the RESPONSE, so
 *  a future transport change cannot silently invert it.
 *
 *  ⛔ Deliberately returns `false` for anything that is not exactly our envelope
 *  — unparseable bodies, S3's XML, `null`, a JSON scalar, a different code. That
 *  is the SAFE direction: a false negative leaves a 503 as an ordinary retryable
 *  error, which is what it was before this branch existed. A false POSITIVE
 *  would park a storage 503 on a Retry-After wait it will never satisfy. */
export function isRelayAtCapacityBody(responseText: string | null | undefined): boolean {
  if (!responseText) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    return false; // S3 answers 503 in XML — not ours, not at-capacity.
  }
  if (typeof parsed !== 'object' || parsed === null) return false;
  const error = (parsed as { error?: unknown }).error;
  if (typeof error !== 'object' || error === null) return false;
  return (error as { code?: unknown }).code === RELAY_AT_CAPACITY_CODE;
}

export class SignetApiError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'SignetApiError';
    this.status = status;
    this.code = code;
  }
}

export interface BeginResponse {
  ceremony_id: string;
  options: unknown;
}

export interface VerifyEmailResponse {
  account_id: string;
  handle: string;
}

export interface SigninResponse {
  account_id: string;
  wrapped_kem_privkey_blob?: unknown;
  kem_pubkey?: string;
  /** The ML-KEM-1024 encapsulation key (1568 B, base64url) published at
   *  signup — the PQ half of the hybrid KEM directory pair (PQR §7). The
   *  client byte-compares it against ek-from-seed at sign-in. */
  kem_pq_pubkey?: string;
}

export interface PublicConfig {
  /** The Cloudflare Turnstile sitekey for the signup widget, or null when the
   *  bot-check is unconfigured. Served at runtime (Option C) so the web image
   *  isn't built per-environment; the server secret is the authoritative gate. */
  turnstile_sitekey: string | null;
  /** How long (hours) a persisted web unlock survives without a fresh passkey
   *  gesture (`web_unlock_persist_hours`, migration 0032) — stamped into the
   *  persisted record's expiry at persist time (S116 unlock persistence). */
  unlock_persist_hours?: number;
}

/** The signup gate, as an ADMIN sees it. Never served on a public route: the public
 *  endpoint returns a bare boolean so a capped round cannot be told from an open one. */
export interface SignupGateStatus {
  mode: 'open' | 'paused' | 'limited';
  cohort: SignupCohort | null;
}

export interface SignupCohort {
  cohort_id: string;
  label: string;
  cohort_ref: string;
  max_accounts: number;
  used: number;
  remaining: number;
}

export interface SignetApi {
  beginSignup(input: { handle: string; email: string; turnstileToken?: string }): Promise<void>;
  verifyEmail(token: string): Promise<VerifyEmailResponse>;
  beginRegistration(accountId: string): Promise<BeginResponse>;
  completeRegistration(
    accountId: string,
    body: { ceremony_id: string; credential: unknown },
  ): Promise<void>;
  beginSignin(email: string): Promise<BeginResponse>;
  completeSignin(body: { ceremony_id: string; credential: unknown }): Promise<SigninResponse>;
  /** End the server session + clear the cookie. Public + idempotent; the client
   *  calls it on sign-out so a later refresh can't silently re-unlock the account. */
  logout(): Promise<void>;
  keysInitialize(body: {
    kem_pubkey: string;
    /** The ML-KEM-1024 encapsulation key (1568 B, base64url) — the PQ half of
     *  the hybrid KEM directory pair (PQR §7; accounts.kem_pq_pubkey). */
    kem_pq_pubkey: string;
    /** bug245: the WebAuthn credential id (base64url) of the passkey whose PRF
     *  derived the wrap key. The server commits the key material only if that
     *  passkey is ACTIVE for the account. */
    credential_id: string;
    wrapped_kem_privkey_blob: unknown;
  }): Promise<void>;
  /** Public runtime config served by the env-agnostic image (Option C): the
   *  Turnstile sitekey for the signup widget (null when unconfigured). */
  getSignupGate(): Promise<SignupGateStatus>;
  setSignupGateMode(mode: string): Promise<SignupGateStatus>;
  openSignupCohort(label: string, maxAccounts: number): Promise<SignupCohort>;
  closeSignupCohort(cohortId: string): Promise<void>;
  createSignupInvite(email: string, handle: string): Promise<void>;
  getPublicConfig(): Promise<PublicConfig>;
  /** Whether public signup is open. A BARE BOOLEAN by design — the server never
   *  reveals the mode or any cohort counts, or a capped round would be
   *  distinguishable from an open one. */
  getSignupStatus(): Promise<{ open: boolean }>;
}

// --- data plane (A3 folders/files + B1 wraps), consumed by the C2 client ------
// Crypto-bearing fields (encrypted_name, wrapped_dek, wrapped_key) are opaque
// `unknown` here — the raw client stays crypto-agnostic; drive.ts casts them to
// the §7.3 / §5 envelope shapes.

export interface FolderView {
  folder_id: string;
  parent_folder_id: string | null;
  root_folder_id: string | null;
  folder_type: string;
  encrypted_name: unknown;
  /** Unix seconds (the file browser's "Modified" column). */
  created_at: number;
  modified_at: number;
}

export interface FileView {
  file_id: string;
  folder_id: string;
  encrypted_name: unknown;
  /** The stored CIPHERTEXT length (what storage holds and quota charges). */
  size_bytes: number;
  /** The PLAINTEXT length — the number a user calls "the file's size" (bug083).
   *  Server-derived exactly from the §4.2 framing; absent for a row the server
   *  cannot derive (display falls back to `size_bytes` rather than fabricating). */
  plaintext_bytes?: number | null;
  etag: string;
  algorithm: string;
  /** Unix seconds (the file browser's "Modified" column). */
  created_at: number;
  modified_at: number;
}

export interface CreateFolderBody {
  folder_id: string;
  parent_folder_id?: string;
  encrypted_name: unknown;
  owner_metadata_key_wrap?: unknown;
}

export interface UploadFileBody {
  folder_id: string;
  encrypted_name: unknown;
  ciphertext: string;
  wrapped_deks: { recipient_account_id: string; wrapped_dek: unknown }[];
  algorithm: string;
}

// --- direct-to-storage multipart transport (S039; Large-File Design §4) --------

export interface InitiateMultipartBody {
  folder_id: string;
  encrypted_name: unknown;
  wrapped_deks: { recipient_account_id: string; wrapped_dek: unknown }[];
  /** Total ciphertext (stored) bytes — what the server reserves quota against and
   *  HeadObject-reconciles at complete. */
  declared_size: number;
  /** Per-chunk plaintext size (Envelope §4.2). */
  chunk_size: number;
  /** Number of §4.2 chunks / S3 parts (1..=10000). */
  chunk_count: number;
  algorithm: string;
}

export interface PartUrl {
  part_number: number;
  /** Pre-signed UploadPart URL — the client PUTs one encrypted chunk here. */
  url: string;
}

export interface InitiateMultipartResponse {
  upload_id: string;
  part_urls: PartUrl[];
  expires_at: number;
  /** bug047 client-resilience knobs (`system_config`-served so tuning never
   *  needs a client release); optional — an older server omits them and the
   *  client falls back to its own defaults. */
  part_retry_attempts?: number;
  stall_timeout_seconds?: number;
  /** bug060 transfer-governor knobs. Optional for the same reason: an older
   *  server omits them and the client uses its own defaults. Kept loosely typed
   *  so a knob added server-side never needs a coordinated client release. */
  governor?: Record<string, unknown>;
}

/** The server's authoritative view of an interrupted multipart upload
 *  (bug047 resume): which parts storage already holds (with the ETags to use
 *  at complete), fresh URLs for the rest, the caller's own wrapped DEK, and
 *  the chunk geometry. */
export interface ResumeMultipartResponse {
  uploaded_parts: { part_number: number; etag: string }[];
  part_urls: PartUrl[];
  wrapped_dek: unknown;
  chunk_size: number;
  chunk_count: number;
  expires_at: number;
  part_retry_attempts?: number;
  stall_timeout_seconds?: number;
  /** bug060 transfer-governor knobs. Optional for the same reason: an older
   *  server omits them and the client uses its own defaults. Kept loosely typed
   *  so a knob added server-side never needs a coordinated client release. */
  governor?: Record<string, unknown>;
}

/** Options for one pre-signed part-PUT attempt (bug047 + bug060). */
export interface PutPartOptions {
  /** Rate-DERIVED per-attempt ceiling in ms (`k × bytes ÷ measured rate`, from
   *  the caller's `TransferGovernor`). Omit when no credible rate estimate
   *  exists yet; the absolute backstop then applies alone.
   *
   *  There is deliberately **no fixed stall timeout**: bounding a transfer by a
   *  constant number of seconds encodes a minimum bandwidth, which is what made
   *  every sub-9 Mbps link unable to upload at all (bug060). */
  ceilingMs?: number;
  /** bug076: receives an abort function for THIS attempt's live XHR the moment it
   *  is armed. A user cancel calls it to abort the in-flight socket immediately
   *  (rejecting with `TransferCancelledError`, which `isRetryable` refuses), so
   *  cancel is prompt instead of waiting for the next part boundary. */
  onAbortReady?: (abort: () => void) => void;
  /** Absolute last-resort per-attempt ceiling ms (default 5 min). Automatically
   *  widened above `ceilingMs` so it can never become the effective — and
   *  rate-blind — limit. */
  backstopMs?: number;
}

export interface CompleteMultipartBody {
  parts: { part_number: number; etag: string }[];
}

export interface DownloadUrlResponse {
  download_url: string;
  size_bytes: number;
  /** §4.2 chunk count + per-chunk plaintext size (both null for a single-PUT
   *  file) — the client uses them to compute on-disk chunk boundaries for Range
   *  reads. */
  multipart_chunks: number | null;
  chunk_size: number | null;
  expires_at: number;
  /** bug178 (S174): how many chunks to fetch CONCURRENTLY. Served so retraction
   *  is a SQL update on the running box rather than a client release.
   *  ⚠ Optional because an older server omits it — and absent must mean
   *  strictly-serial, which is exactly the pre-S174 behaviour. Clamped
   *  client-side; the web ceiling is lower than the CLI's because in-flight
   *  memory is `N × chunk` on top of bug179's measured 489 MiB renderer peak. */
  concurrency?: number;
  /** bug193 (v0.5.39): the web SW-streamed download kill-switch. Optional for a
   *  pre-0059 server; absent means enabled (the SW path is the path). */
  web_sw_download_enabled?: boolean;
  /** bug193 (v0.5.39): the fallback's served per-file ceiling. Optional for a
   *  pre-0059 server; absent falls back to the S173-measured default. */
  web_download_buffer_cap_bytes?: number;
  /** bug209 (0060): the per-chunk attempt budget — the download mirror of the
   *  upload path's served `multipart_part_retry_attempts`. This path previously
   *  compiled `3` and read nothing, while two documents said 10.
   *  ⚠ Optional because a pre-0060 server omits it; absent means the compiled
   *  default (10). ⚠⚠ **That is NOT "the retraction position"** (Gus, S181 F1) —
   *  the old client did 3, and falling back to 3 would preserve the defect as the
   *  fallback. See `downloadRetryAttempts` for the full reasoning.
   *  ⚠ Clamped client-side (`DOWNLOAD_RETRY_ATTEMPTS_MAX`) — an unclamped served
   *  value keeps a doomed chunk retrying instead of failing honestly. */
  download_part_retry_attempts?: number;
}

// Rename = a new encrypted_name; same-root move = a new parent. Omit a field to
// leave it unchanged (the server COALESCEs). At least one is required.
export interface UpdateFileBody {
  encrypted_name?: unknown;
  folder_id?: string;
}

export interface UpdateFolderBody {
  encrypted_name?: unknown;
  parent_folder_id?: string;
}

export interface ListFoldersResponse {
  folders: FolderView[];
  next_cursor: string | null;
}

export interface ListFilesResponse {
  files: FileView[];
  next_cursor: string | null;
}

export interface WrappedDekResponse {
  wrapped_dek: unknown;
}

export interface MetadataKeyWrapResponse {
  wrapped_key: unknown;
}

export interface BatchDeleteResponse {
  deleted: number;
}

export interface QuotaResponse {
  bytes_used: number;
  bytes_quota: number;
}

// GET /v1/me. The file browser reads the account kind (human vs PRSN — drives
// View 1 vs 1b), the display handle, and a PRSN's Guardian handle + sharing
// capability (the sidebar's dependent-status indicators); Account Settings
// (Views 5/5b) additionally reads paid_until, the key fingerprints, and the
// attestation summary. The server always sends paid_until; the rest are
// conditional (a human has no attestation; a Guardian-less account has no
// guardian block).
export interface AttestationSummary {
  attestation_id: string;
  created_at: number;
  expires_at: number | null;
  status: string;
  key_protection: string;
  signing_pubkey_fingerprint: string;
  /** The ML-DSA-87 signing-key fingerprint (fingerprint_raw, PQR §8.5) —
   *  present for a four-key hybrid identity. The account page's PQ rows. */
  signing_pq_pubkey_fingerprint?: string | null;
}

export interface MeResponse {
  account_id: string;
  account_type: 'human' | 'prsn' | 'server';
  /** Whether the caller holds the admin role (gates the View 6 dashboard nav +
   *  route). Only humans can be admins; absent/false otherwise. */
  admin_role?: boolean;
  handle: string | null;
  email?: string | null;
  /** Account creation time, unix seconds. */
  created_at: number;
  paid_until: number;
  /** True when the account is write-blocked — a lapsed subscription in the grace
   *  window, or a never-activated account. The banner + read-only UI key off this.
   *  (Over-quota is separate — derive it from the quota readout.) */
  read_only: boolean;
  /** True when this human has never billing-activated (`activated_at` NULL). Under
   *  the two-window free trial (S134) a brand-new account is a never-activated
   *  *trial* (usable, not read_only); the banner uses this with read_only +
   *  paid_until to pick the trial surface vs. "your subscription lapsed". Always
   *  false for PRSNs. */
  needs_activation: boolean;
  /** True when a free-trial account has already used its ONE-TIME card extension
   *  (S135). The billing section hides "Add a card to extend" once true — a carded
   *  trial cannot re-extend (one-time bound), only upgrade. False otherwise. */
  trial_card_added: boolean;
  /** bug244: true when an ACTIVE passkey exists. With `kem_pubkey_fingerprint`
   *  null it separates the two unfinished-signup states: no passkey yet (resume
   *  registration) vs a passkey and no keys (finish at sign-in). */
  has_passkey: boolean;
  /** The server's current single-file upload ceiling in bytes
   *  (system_config.max_upload_size_bytes). The upload UI reads it to guard file
   *  size + message, so a runtime bump takes effect without a client redeploy. */
  max_upload_size_bytes: number;
  prsn_sharing_capability?: string | null;
  kem_pubkey?: string | null;
  kem_pubkey_fingerprint?: string | null;
  /** The caller's own hybrid PQ KEM half (PQR §7) — the attested ek for a
   *  PRSN, the account-stored ek for a human; present iff hybrid. */
  kem_pq_pubkey?: string | null;
  kem_pq_pubkey_fingerprint?: string | null;
  attestation?: AttestationSummary | null;
  guardian?: {
    /** The Guardian's account id — the identity the PRSN writer's
     *  verified-source check binds the guardian-wrap keys to (guardians are
     *  humans → §10a log receipts; F-DOWNGRADE(b)). */
    account_id: string;
    handle: string | null;
    kem_pubkey?: string | null;
    kem_pubkey_fingerprint?: string | null;
    /** Hybrid PQ half (see RecipientKey) — presence triggers §9.2/N6. */
    kem_pq_pubkey?: string | null;
    kem_pq_pubkey_fingerprint?: string | null;
  } | null;
  /** The Guardian's effective PRSN-account cap and current active-PRSN count
   *  (humans only; absent for PRSNs). bug098: the add-PRSN client fail-fasts at
   *  the cap (the wizard page gate + the "+ Add PRSN" button) instead of
   *  dead-ending on the server's `confirm` rejection. Same source as the
   *  authoritative server gate, so the client can't disagree with it — but the
   *  server `confirm` check stays the authoritative gate (advisory only here). */
  prsn_cap?: number | null;
  prsn_count?: number | null;
  /** The PRSN's own Signet Drive (Garnet) access state (§1-62 PR-D) — the
   *  agent-facing "where am I" behind the step-aware CLI output. PRSN accounts
   *  only; absent for humans. `contested` is deliberately not distinguishable
   *  here (guardian-facing alarm — see server `me.rs`). */
  drive_access?: {
    /** none | awaiting_pickup | awaiting_confirmation | authorized */
    status: string;
    overdue: boolean;
    reconfirm_interval_days?: number | null;
  } | null;
}

// --- billing (D2 web cluster) -------------------------------------------------

export interface RedirectResponse {
  /** The Stripe-hosted URL to redirect the browser to. */
  url: string;
}

/** One currency's list amount for a tier (bug171). Minor units as Stripe holds
 *  them (CA$8 = 800); the client formats, the server never does money math. */
export interface TierAmount {
  /** Lowercase ISO code ("cad", "usd"). */
  currency: string;
  amount_minor: number;
}

export interface TiersResponse {
  /** Configured tier labels (e.g. ["10gb","100gb","1tb"]); empty when billing is
   *  unconfigured. The web maps each to a display name + orders by size. */
  tiers: string[];
  /** bug171 (ruled Option 3): tier label → per-currency list amounts, fetched
   *  from the Stripe price objects server-side. ABSENT when unavailable — the
   *  screen then renders labels without prices (the degrade contract: a
   *  billing outage must not break /account). */
  prices?: Record<string, TierAmount[]>;
}

export interface BillingApi {
  /** Start a subscription Checkout for a tier (the trial upgrade path); returns the Stripe URL. */
  createCheckout(tier: string): Promise<RedirectResponse>;
  /** Start a setup-mode Checkout to save a card and extend the free trial's with-card
   *  window (never charged, S134); returns the Stripe URL. */
  addCard(): Promise<RedirectResponse>;
  /** Open the Stripe Billing Portal (manage card / change tier / cancel). */
  createBillingPortal(): Promise<RedirectResponse>;
  /** The configured storage tiers for the subscribe-to-activate screen. */
  getTiers(): Promise<TiersResponse>;
}

// --- C4 account settings + Guardian management --------------------------------

export interface AuditEvent {
  event_id: string;
  event_type: string;
  /** Unix seconds. */
  event_time: number;
  target_resource_id?: string;
  target_resource_type?: string;
  actor_account_id?: string;
  event_data?: unknown;
}

export interface ListAuditResponse {
  events: AuditEvent[];
  next_cursor: string | null;
}

export interface PrsnAttestationSummary {
  attestation_id: string;
  /** `active` / `revoked` / `expired`. */
  status: string;
  key_protection: string;
  created_at: number;
  expires_at: number | null;
}

export interface GuardedPrsn {
  account_id: string;
  handle: string | null;
  prsn_sharing_capability?: string | null;
  /** `active` / `pending_deletion` / `suspended`. */
  status: string;
  /** bug114 Part B (additive): the unix timestamp this account's setup expires
   *  (`created_at + prsn_setup_deadline_minutes`) — present ONLY while still in
   *  setup; the authoritative clock the 5-minute warning counts against. Absent
   *  on servers predating the bug114 server PR (the warning simply never arms). */
  setup_deadline?: number | null;
  /** §1-64 (additive, S166): the server-projected Drive-grant state — one of
   *  `never_authorized` / `waiting_to_connect` / `active` / `writes_paused` /
   *  `stopped` / `revoked` / `contested`. THE one source every surface reads for
   *  the state tag (account `pending_deletion` overrides, from `status` above).
   *  Absent on servers predating the S166 PR; treat absent OR unrecognized as
   *  "render no tag", never guess. */
  grant_state?: string;
  /** bug156 (additive): the earliest unix timestamp the pending deletion can execute —
   *  `pending_deletion_at + share_folder_recipient_grace_hours`, SERVER-computed (the
   *  grace window is a runtime knob; a client "+24 h" diverges the day it moves). A
   *  soonest-bound, not an exact time. Present only while `status = 'pending_deletion'`,
   *  and absent on servers predating the S168 PR — render no date rather than guess. */
  deletes_at?: number | null;
  attestation?: PrsnAttestationSummary | null;
}

export interface ListPrsnsResponse {
  prsns: GuardedPrsn[];
}

/** The complete-phase body every op-bound ceremony posts: the correlation id +
 *  the raw WebAuthn assertion (PRF stripped per INV-13 by the serializer). */
export interface CeremonyCompleteBody {
  ceremony_id: string;
  credential: unknown;
}

// --- C3 sharing ---------------------------------------------------------------

export interface RecipientKey {
  handle: string;
  account_type: string;
  /** The recipient's account id — the identity the writer's verified-source
   *  check binds the keys to (F-DOWNGRADE(b)): a PRSN's attestation names it
   *  as subject_account_id; a human's §10a log receipts name it. */
  account_id: string;
  /** The active attestation this bundle was resolved from (PRSN recipients
   *  only) — the writer's verified source (F-DOWNGRADE(b)). */
  attestation_id?: string | null;
  /** X9.63 KEM public key, base64url. */
  kem_pubkey: string;
  kem_pubkey_fingerprint: string;
  /** The recipient's ML-KEM-1024 encapsulation key (1568 B, base64url), when
   *  their attested bundle is hybrid. Presence triggers the writer's
   *  refuse-to-downgrade (PQR §9.2/N6): a hybrid recipient MUST be wrapped
   *  hybrid, never classical. */
  kem_pq_pubkey?: string | null;
  /** Lowercase-hex SHA-256 over the RAW FIPS 203 ek bytes (fingerprint_raw,
   *  PQR §8.5) — NOT the classical SHA-256(SPKI) convention. */
  kem_pq_pubkey_fingerprint?: string | null;
}

export interface RecipientView {
  recipient_account_id: string;
  handle: string | null;
  /** `human` | `prsn` — the writer's verified-source dispatch key (see
   *  RecipientKey.account_id / attestation_id). */
  account_type: string;
  /** The active attestation this row's keys were resolved from (PRSN rows
   *  only) — the writer's verified source (F-DOWNGRADE(b)). */
  attestation_id?: string | null;
  kem_pubkey: string | null;
  /** Lowercase-hex SHA-256(SPKI) of kem_pubkey; P-011-checked before a DEK is
   *  wrapped to the key on upload. Null when the recipient has no current key. */
  kem_pubkey_fingerprint: string | null;
  /** Hybrid PQ half (see RecipientKey) — presence triggers §9.2/N6. */
  kem_pq_pubkey?: string | null;
  /** fingerprint_raw over the ek bytes (PQR §8.5). */
  kem_pq_pubkey_fingerprint?: string | null;
  permission: string;
  is_mandatory_guardian: boolean;
}

/** One pending invitation, the owner's view (S121, W6). The server deliberately
 *  never re-serves the bearer token — a lost link is cancel + re-invite. */
export interface PendingInvitationView {
  invitation_id: string;
  recipient_handle: string;
  permission: string;
  created_at: number;
  expires_at: number;
}

export interface PendingInvitationsResponse {
  invitations: PendingInvitationView[];
}

export interface RecipientsResponse {
  recipients: RecipientView[];
  /** The folder OWNER's verified KEM identity (Bug038; `permission = "owner"`).
   *  An uploader wraps the file DEK to the owner too, so a `read_write` recipient
   *  (a Guardian) uploading to a folder it does not own still covers the owner.
   *  Skipped when the owner is the uploader (self-wrap already covers it). Not a
   *  "recipient" — the sharing dialog does not list it. */
  owner: RecipientView;
}

// --- verified-source identity records (F-DOWNGRADE(b)) -------------------------
// These are cryptographically verified from the raw JSON (recipient_verify.ts) —
// the types carry only the fields the client navigates; verification never
// trusts the TS shape.

export interface ServerInfoKey {
  key_id: string;
  purpose: string;
  /** base64url — X9.63 for ES256 keys, raw FIPS 204 vk for ML-DSA-87. */
  public_key: string;
}

export interface ServerInfoResponse {
  version?: string;
  current_signing_keys?: ServerInfoKey[];
  retired_signing_keys?: ServerInfoKey[];
}

/** A §9 attestation-verification response (Envelope Format §9). Verified
 *  field-by-field from the raw JSON; `attestation` stays unknown-shaped on
 *  purpose — its bytes are what the server signature covers. */
export interface AttestationVerificationResponse {
  attestation: Record<string, unknown>;
  server_key_id: string;
  server_signature: string;
  server_pq_key_id?: string | null;
  server_signature_mldsa87?: string | null;
  signed_at: number;
  [receipt: string]: unknown;
}

/** A §10a transparency-log receipt (Envelope Format §10a), raw-shaped for the
 *  same reason. */
export type LogReceipt = Record<string, unknown>;

export interface ShareFolderView {
  folder_id: string;
  root_folder_id: string;
  folder_type: string;
  encrypted_name: unknown;
  recipients: RecipientView[];
}

export interface CreateShareFolderBody {
  folder_id?: string;
  encrypted_name: unknown;
  owner_metadata_key_wrap: unknown;
  guardian_metadata_key_wrap?: unknown;
}

export interface CreateInvitationBody {
  recipient_handle: string;
  permission: string;
  pre_computed_wraps: {
    metadata_key_wrap: unknown;
    file_dek_wraps: { file_id: string; wrap: unknown }[];
  };
}

export interface CreateInvitationResponse {
  invitation_id: string;
  token: string;
  expires_at: number;
}

export interface InvitationPreview {
  inviter_handle: string | null;
  permission: string;
  file_count: number;
  expires_at: number;
  accepted_at: number | null;
}

export interface AcceptInvitationResponse {
  share_folder_id: string;
  permission: string;
  files_granted: number;
}

export interface SharedFolderView {
  folder_id: string;
  root_folder_id: string | null;
  folder_type: string;
  encrypted_name: unknown;
  permission: string;
  /** The folder owner's account id — lets the client group "shared with me" by
   *  owner (the Guardian's per-PRSN nav, Bug009). */
  owner_account_id: string;
}

export interface SharedWithMeResponse {
  folders: SharedFolderView[];
}

export interface DriveApi {
  createFolder(body: CreateFolderBody): Promise<FolderView>;
  listFolders(parentFolderId?: string, cursor?: string): Promise<ListFoldersResponse>;
  listFiles(folderId: string, cursor?: string): Promise<ListFilesResponse>;
  uploadFile(fileId: string, body: UploadFileBody): Promise<FileView>;
  /** Raw ciphertext envelope bytes (the §4.1 single-PUT blob). */
  downloadFileBytes(fileId: string): Promise<Uint8Array<ArrayBuffer>>;
  getWrappedDek(fileId: string): Promise<WrappedDekResponse>;
  /** Begin a direct-to-storage multipart upload: reserves quota, returns one
   *  pre-signed UploadPart URL per chunk. */
  initiateMultipart(
    fileId: string,
    body: InitiateMultipartBody,
  ): Promise<InitiateMultipartResponse>;
  /** Finish a multipart upload (the server HeadObject-reconciles the actual size). */
  completeMultipart(
    fileId: string,
    uploadId: string,
    body: CompleteMultipartBody,
  ): Promise<FileView>;
  /** Cancel an in-progress multipart upload. */
  abortMultipart(fileId: string, uploadId: string): Promise<void>;
  /** The authoritative state of an interrupted upload + fresh URLs for its
   *  missing parts (bug047 resume; extends the server-side idle deadline). */
  resumeMultipart(fileId: string, uploadId: string): Promise<ResumeMultipartResponse>;
  /** A short-TTL pre-signed GetObject URL + chunk metadata for download. */
  getDownloadUrl(fileId: string): Promise<DownloadUrlResponse>;
  /** PUT one encrypted chunk straight to its pre-signed URL; returns the part
   *  ETag. One ATTEMPT on one fresh connection (XHR) with a no-progress stall
   *  watchdog (bug047) — the retry policy lives in the caller via
   *  `transferWithRetry`, keeping this mechanical and the policy pure. */
  putPart(url: string, chunk: Uint8Array, opts?: PutPartOptions): Promise<string>;
  /** Range-GET ciphertext bytes `[start, end]` from a pre-signed GetObject URL. */
  getRange(url: string, start: number, end: number): Promise<Uint8Array<ArrayBuffer>>;
  getMetadataKeyWrap(folderId: string): Promise<MetadataKeyWrapResponse>;
  updateFile(fileId: string, body: UpdateFileBody): Promise<FileView>;
  updateFolder(folderId: string, body: UpdateFolderBody): Promise<FolderView>;
  deleteFile(fileId: string): Promise<void>;
  deleteFolder(folderId: string): Promise<void>;
  deleteFilesBatch(fileIds: string[]): Promise<BatchDeleteResponse>;
  deleteFoldersBatch(folderIds: string[]): Promise<BatchDeleteResponse>;
  getQuota(): Promise<QuotaResponse>;
  getMe(): Promise<MeResponse>;
  // C3 sharing.
  getRecipientKey(handle: string): Promise<RecipientKey>;
  // The verified-source identity records the writer checks recipient keys
  // against before wrapping (F-DOWNGRADE(b)) — all three are public reads.
  getServerInfo(): Promise<ServerInfoResponse>;
  getAttestationVerification(attestationId: string): Promise<AttestationVerificationResponse>;
  getLogReceipt(fingerprint: string, purpose: string): Promise<LogReceipt>;
  createShareFolder(body: CreateShareFolderBody): Promise<ShareFolderView>;
  listRecipients(folderId: string): Promise<RecipientsResponse>;
  createInvitation(folderId: string, body: CreateInvitationBody): Promise<CreateInvitationResponse>;
  listInvitations(folderId: string): Promise<PendingInvitationsResponse>;
  cancelInvitation(folderId: string, invitationId: string): Promise<void>;
  previewInvitation(token: string): Promise<InvitationPreview>;
  acceptInvitation(token: string): Promise<AcceptInvitationResponse>;
  removeRecipient(folderId: string, recipientId: string): Promise<void>;
  leaveShareFolder(folderId: string): Promise<void>;
  listSharedWithMe(): Promise<SharedWithMeResponse>;
}

// The C4 account surface: the two reads (audit history, guarded PRSNs) plus the
// generic op-bound ceremony pair. Every account-management action (issue / revoke
// / change-capability / delete) is a `begin` (returns WebAuthn assertion options
// with the operation-bound challenge injected) then a `complete` (posts the
// assertion). `operation` is the kebab-case URL slug (e.g. `issue-attestation`);
// the runner in ceremony.ts orchestrates the navigator.credentials round-trip
// between them. Passkey rotation is NOT here — its 3-gesture shape is distinct
// (C4-S4 / PR B).
// Passkey rotation (C4-S4) is its own 3-gesture shape, distinct from the generic
// op-bound ceremony: `begin` (no body) returns BOTH an operation-bound assertion
// (to authorize with the current passkey) and a registration challenge (for the
// new passkey); `complete` carries the old assertion, the new credential, and the
// KEM key re-wrapped under the new passkey's PRF (opaque to the server).
export interface RotatePasskeyBeginResponse {
  ceremony_id: string;
  /** Assertion options for the CURRENT passkey (the client adds the prf.eval
   *  salt locally to also harvest its PRF). */
  options: unknown;
  registration_ceremony_id: string;
  /** Creation options for the NEW passkey (prf capability already requested). */
  registration_options: unknown;
}

export interface RotatePasskeyCompleteBody {
  ceremony_id: string;
  registration_ceremony_id: string;
  old_credential_assertion: unknown;
  new_credential: unknown;
  new_wrapped_kem_privkey_blob: unknown;
}

export interface RotatePasskeyResult {
  rotated: boolean;
}

// --- Garnet (Phase 4 guardian dashboard — the standing-grant lifecycle) --------
// The guardian's web surface for Garnet, the PRSN Drive-access layer. The active-PRSN
// panel is a plain authenticated read; authorize + revoke are passkey-ceremony gated
// and reuse the generic `ceremonyBegin`/`ceremonyComplete` above (operations
// `garnet-authorize-grant` / `garnet-revoke-grant`). Authorization state only — no
// content surveillance (the no-PRSN-dashboards bright line). Canonical: Garnet
// Design-Spec v05 §6. Timestamps are unix seconds (mirrors the server `GrantSummary`).

export interface GarnetGrant {
  grant_id: string;
  prsn_handle: string;
  /** `active` | `revoked`. */
  status: string;
  /** Whether enrollment is confirmed. Stamped by the agent's own signature-authenticated
   *  pickup (bug084 — the signature IS the verification); an active grant is inert until
   *  this is true, and the guardian has nothing to do but wait for the agent to connect. */
  enrollment_confirmed: boolean;
  /** Two distinct credentials tried to claim this grant (the §5 collision alarm,
   *  re-pointed by bug084 to the F2 CSR binding). A contested grant hard-blocks pickups
   *  and re-confirms; recovery is revoke-and-re-authorize. */
  contested: boolean;
  /** A confirmed grant past its re-confirmation deadline (the bug085 platform-fixed
   *  cadence). Access degrades read-only through `grace_read_only`, then stops. */
  overdue: boolean;
  /** bug085: past the deadline but inside the read-only grace window — the PRSN keeps
   *  reading; writes are refused at the Drive API. `overdue` is also true; `overdue`
   *  without this flag means the grace has ended (the hard stop). */
  grace_read_only: boolean;
  /** The re-confirmation deadline (unix seconds) under the platform-fixed period, or
   *  `null` (unconfirmed / ops-disabled cadence). Banners + warning copy render from this. */
  reconfirm_deadline_at: number | null;
  /** bug085: the one-tap Re-confirm is offerable NOW (server-side eligibility — the
   *  window opens `warning_lead_days` before the deadline, no upper bound, and a
   *  contested grant is never eligible). The panel shows the button exactly when true. */
  reconfirm_available: boolean;
  /** The enrolled credential's `x5t#S256` fingerprint (display state — the identity
   *  proof is the signed pickup itself, bug084), or `null` if the agent hasn't
   *  connected yet. */
  enrolling_fingerprint: string | null;
  created_at: number;
  last_confirmed_at: number | null;
  revoked_at: number | null;
}

export interface ListGarnetGrantsResponse {
  grants: GarnetGrant[];
  /** bug161 step 6: the read-only grace length (days) after a missed re-confirm
   *  deadline — a runtime knob (`garnet_reconfirm_grace_days`), so copy interpolates
   *  it rather than hardcoding. Optional to tolerate deploy skew against an older
   *  server; consumers omit the grace sentence when absent. */
  grace_days?: number;
}

/** The authorize ceremony's complete-phase result. No pairing code (bug084 flag-day):
 *  the agent claims the grant by SIGNING its pickup with its attested SE-bound key —
 *  there is nothing for the guardian to hand over; the wizard shows the state-derived
 *  "waiting for {handle} to connect". */
export interface GarnetAuthorizeResult {
  grant_id: string;
  prsn_handle: string;
}

export interface GarnetRevokeResult {
  grant_id: string;
  revoked_at: number;
}

/** A broker provisioned under the guardian (v1 = one per guardian). The dashboard reads this to
 *  know whether the guardian has set up `signet` on their Mac yet — no secrets, authorization/setup
 *  state only. */
export interface GarnetBroker {
  broker_id: string;
  provisioned_at: number;
}

export interface ListGarnetBrokersResponse {
  brokers: GarnetBroker[];
}

/** The broker-provisioning-code mint result — a single-use setup code the guardian enters when they
 *  install `signet` on their Mac (returned once; only its SHA-256 is persisted). Session-authed (not
 *  a passkey ceremony): a provisioned-but-unconfirmed broker is inert, so this is a low-stakes mint. */
export interface GarnetProvisionCodeResult {
  provision_code: string;
  expires_in_seconds: number;
}

/** The guardian's Garnet reads + the broker-setup mint. Authorize + revoke reuse AccountApi's generic
 *  `ceremonyBegin`/`ceremonyComplete` (operations `garnet-authorize-grant` / `garnet-revoke-grant`);
 *  the grant list, the broker list, and the provision-code mint are plain session-authed calls. */
export interface GarnetApi {
  listGarnetGrants(): Promise<ListGarnetGrantsResponse>;
  listGarnetBrokers(): Promise<ListGarnetBrokersResponse>;
  mintBrokerProvisionCode(): Promise<GarnetProvisionCodeResult>;
}

/** bug108: the server ack for discarding an in-progress PRSN (`POST /v1/me/prsns/{id}/discard`). */
export interface DiscardInProgressResult {
  discarded: boolean;
}

export interface AccountApi {
  listAudit(cursor?: string): Promise<ListAuditResponse>;
  listPrsns(): Promise<ListPrsnsResponse>;
  /** bug108: discard a PRSN still in setup (never-authorized) — session-authed, no ceremony.
   *  The server refuses anything that has ever been authorized (400). */
  discardInProgressPrsn(accountId: string): Promise<DiscardInProgressResult>;
  ceremonyBegin(operation: string, body: unknown): Promise<BeginResponse>;
  ceremonyComplete<T>(operation: string, body: CeremonyCompleteBody): Promise<T>;
  rotatePasskeyBegin(): Promise<RotatePasskeyBeginResponse>;
  rotatePasskeyComplete(body: RotatePasskeyCompleteBody): Promise<RotatePasskeyResult>;
}

// --- PRSN enrollment (S052 onboarding automation; server `enrollment` module) ---
// The web side of the agent↔server↔human rendezvous that replaces hand-transcribing
// keys. `create` (browser-first: the Guardian opens a rendezvous) is inert until
// `confirm` (the Guardian's authenticated approval — sets the handle + sharing);
// `status` is the code-authed poll the confirm page drives while the agent generates
// keys. The attestation itself is the existing `issue-attestation` ceremony, now
// passed an `enrollment_code` so the server sources the pubkeys from the confirmed
// row (no hand-transcription). Canonical: Signet-Drive-PRSN-Account-and-Kit-Spec.

export interface CreateEnrollmentResponse {
  enrollment_id: string;
  /** The single-use code — embedded in the confirm URL + handed to the agent. */
  code: string;
  /** Where the agent opens the human's browser (`/account/add-prsn/confirm?code=`). */
  confirm_url: string;
  expires_in_seconds: number;
}

export interface EnrollmentStatusResponse {
  /** pending | confirmed | keys_submitted | completed | expired | cancelled | failed */
  status: string;
  /** The Guardian-set handle, once confirmed. */
  handle: string | null;
  /** The issued attestation, once completed. */
  attestation_id: string | null;
}

export interface EnrollmentApi {
  createEnrollment(): Promise<CreateEnrollmentResponse>;
  confirmEnrollment(code: string, handle: string, sharing: string): Promise<void>;
  pollEnrollment(code: string): Promise<EnrollmentStatusResponse>;
  /** bug108: cancel the wizard before an account exists — remove the pre-account
   *  pending-enrollment record (by code). A no-op (expired/completed/unknown) is not an error. */
  cancelPendingEnrollment(code: string): Promise<{ cancelled: boolean }>;
}

// --- C5 admin dashboard (Platform Overview §8) --------------------------------

export interface AdminConfigEntry {
  key: string;
  value: string;
  /** `integer` / `boolean` / `string` — drives the edit dialog's input + validation. */
  value_type: string;
  min_value: string | null;
  max_value: string | null;
  description: string;
  updated_at: number;
  updated_by_account_id: string | null;
}

export interface AdminConfigListResponse {
  config: AdminConfigEntry[];
}

export interface RootSummary {
  log_size: number;
  /** The Merkle root, base64url. */
  merkle_root: string;
  computed_at: number;
  /** When committed to the public location (D1) — null until D1. */
  committed_at: number | null;
  commit_url: string | null;
}

export interface TransparencyStatusResponse {
  log_size: number;
  last_computed: RootSummary | null;
  last_committed: RootSummary | null;
  recent_roots: RootSummary[];
}

/** The account's active comp grant — present iff an unrevoked, unexpired grant
 *  covers it; the dashboard extends/revokes via its `grant_id`. */
export interface ActiveGrant {
  grant_id: string;
  granted_until: number;
}

export interface AdminAccount {
  account_id: string;
  handle: string | null;
  email: string | null;
  account_type: string;
  status: string;
  admin_role: boolean;
  created_at: number;
  paid_until: number;
  active_grant: ActiveGrant | null;
  /** bug244: false while a human account has no key material — signup never
   *  finished; the account cannot sign in and holds no data. Always true for PRSNs. */
  keys_initialized: boolean;
}

export interface ListAdminAccountsResponse {
  accounts: AdminAccount[];
  next_cursor: string | null;
}

export interface Grant {
  grant_id: string;
  granted_account_id: string;
  granted_by_account_id: string;
  granted_until: number;
  created_at: number;
  revoked_at: number | null;
  note: string | null;
}

export interface CreateGrantBody {
  granted_account_id: string;
  duration_days: number;
  /** Optional storage grant in bytes; omitted → the server's default tier quota. */
  granted_bytes_quota?: number;
  note?: string;
}

export interface AdminApi {
  listConfig(): Promise<AdminConfigListResponse>;
  updateConfig(key: string, value: string): Promise<AdminConfigEntry>;
  getTransparencyStatus(): Promise<TransparencyStatusResponse>;
  listAdminAccounts(cursor?: string): Promise<ListAdminAccountsResponse>;
  createGrant(body: CreateGrantBody): Promise<Grant>;
  extendGrant(grantId: string, durationDays: number): Promise<Grant>;
  revokeGrant(grantId: string): Promise<Grant>;
  /** v1.0.3: an operator puts a HUMAN account into the deletion pipeline — the
   *  holder's own deletion with a second actor. Refused for PRSNs, admins, a human
   *  who guards a PRSN, a wrong confirmation handle, or a non-active account. */
  deleteAccount(
    accountId: string,
    confirmationHandle: string,
  ): Promise<{ account_id: string; status: string; pending_deletion_at: number }>;
}

export interface ApiOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
}

export function createApiClient(
  options: ApiOptions = {},
): SignetApi & DriveApi & AccountApi & GarnetApi & EnrollmentApi & AdminApi & BillingApi {
  const baseUrl = options.baseUrl ?? '';
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const init: RequestInit = { method, credentials: 'include' };
    if (body !== undefined) {
      init.headers = { 'content-type': 'application/json' };
      init.body = JSON.stringify(body);
    }
    const response = await doFetch(`${baseUrl}${path}`, init);
    if (!response.ok) throw await toApiError(response);
    // 202 (begin-signup) and 204 (complete-registration, keys/initialize) carry no body.
    if (response.status === 204 || response.status === 202) return undefined as T;
    return (await response.json()) as T;
  }

  // Binary GET (the file ciphertext envelope) — not a JSON body.
  async function requestBytes(method: string, path: string): Promise<Uint8Array<ArrayBuffer>> {
    const response = await doFetch(`${baseUrl}${path}`, { method, credentials: 'include' });
    if (!response.ok) throw await toApiError(response);
    return new Uint8Array(await response.arrayBuffer());
  }

  return {
    beginSignup: (input) =>
      request<void>('POST', '/v1/accounts/begin-signup', {
        handle: input.handle,
        email: input.email,
        turnstile_token: input.turnstileToken ?? null,
      }),
    verifyEmail: (token) =>
      request<VerifyEmailResponse>(
        'GET',
        `/v1/accounts/verify-email?token=${encodeURIComponent(token)}`,
      ),
    beginRegistration: (accountId) =>
      request<BeginResponse>(
        'POST',
        `/v1/accounts/${encodeURIComponent(accountId)}/begin-registration`,
      ),
    completeRegistration: (accountId, body) =>
      request<void>(
        'POST',
        `/v1/accounts/${encodeURIComponent(accountId)}/complete-registration`,
        body,
      ),
    beginSignin: (email) => request<BeginResponse>('POST', '/v1/auth/passkey/begin', { email }),
    completeSignin: (body) => request<SigninResponse>('POST', '/v1/auth/passkey/complete', body),
    logout: () => request<void>('POST', '/v1/auth/logout'),
    keysInitialize: (body) => request<void>('POST', '/v1/me/keys/initialize', body),
    getSignupGate: () => request<SignupGateStatus>('GET', '/v1/admin/signup-gate'),
    setSignupGateMode: (mode) =>
      request<SignupGateStatus>('PATCH', '/v1/admin/signup-gate', { mode }),
    openSignupCohort: (label, maxAccounts) =>
      request<SignupCohort>('POST', '/v1/admin/signup-cohorts', {
        label,
        max_accounts: maxAccounts,
      }),
    closeSignupCohort: (cohortId) =>
      request<void>('POST', `/v1/admin/signup-cohorts/${cohortId}/close`),
    createSignupInvite: (email, handle) =>
      request<void>('POST', '/v1/admin/signup-invites', { email, handle }),
    getPublicConfig: () => request<PublicConfig>('GET', '/v1/config'),
    getSignupStatus: () => request<{ open: boolean }>('GET', '/v1/signup-status'),
    createFolder: (body) => request<FolderView>('POST', '/v1/folders', body),
    listFolders: (parentFolderId, cursor) => {
      const params = new URLSearchParams();
      if (parentFolderId) params.set('parent_folder_id', parentFolderId);
      if (cursor) params.set('cursor', cursor);
      const qs = params.toString();
      return request<ListFoldersResponse>('GET', qs ? `/v1/folders?${qs}` : '/v1/folders');
    },
    listFiles: (folderId, cursor) => {
      const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
      return request<ListFilesResponse>(
        'GET',
        `/v1/folders/${encodeURIComponent(folderId)}/files${qs}`,
      );
    },
    uploadFile: (fileId, body) =>
      request<FileView>('PUT', `/v1/files/${encodeURIComponent(fileId)}`, body),
    downloadFileBytes: (fileId) => requestBytes('GET', `/v1/files/${encodeURIComponent(fileId)}`),
    getWrappedDek: (fileId) =>
      request<WrappedDekResponse>('GET', `/v1/files/${encodeURIComponent(fileId)}/wrapped-dek`),
    initiateMultipart: (fileId, body) =>
      request<InitiateMultipartResponse>(
        'POST',
        `/v1/files/${encodeURIComponent(fileId)}/multipart`,
        body,
      ),
    completeMultipart: (fileId, uploadId, body) =>
      request<FileView>(
        'POST',
        `/v1/files/${encodeURIComponent(fileId)}/multipart/${encodeURIComponent(uploadId)}/complete`,
        body,
      ),
    abortMultipart: (fileId, uploadId) =>
      request<void>(
        'DELETE',
        `/v1/files/${encodeURIComponent(fileId)}/multipart/${encodeURIComponent(uploadId)}`,
      ),
    getDownloadUrl: (fileId) =>
      request<DownloadUrlResponse>('GET', `/v1/files/${encodeURIComponent(fileId)}/download-url`),
    resumeMultipart: (fileId, uploadId) =>
      request<ResumeMultipartResponse>(
        'POST',
        `/v1/files/${encodeURIComponent(fileId)}/multipart/${encodeURIComponent(uploadId)}/resume`,
      ),
    // bug047 + bug060: one part-PUT ATTEMPT on one FRESH connection.
    //
    // ⚠ `xhr.upload.onprogress` MUST NOT be used as a stall signal. It reports
    // bytes handed to the browser's network stack, not bytes delivered: measured
    // in S126, it fires ONCE at ~0.4–1.5 s claiming 100% "loaded" and then goes
    // silent for the entire real transmission. The previous watchdog reset on it
    // and therefore killed healthy uploads mid-flight — verified aborting at
    // 16.3 s a transfer that needed 25 s. XHR exposes no wire-level upload
    // progress at all, by design.
    //
    // So the only honest clock on this surface is part COMPLETION, and the bound
    // below is a rate-DERIVED per-part ceiling (`k × bytes ÷ measured rate`,
    // supplied by the caller's governor) rather than any fixed number of seconds.
    // A missing ceiling falls back to the absolute backstop.
    //
    // Retry policy lives in the caller (`transferWithRetry`); a ceiling breach
    // rejects `StallError`, an HTTP error rejects `SignetApiError` (its `status`
    // drives retryability: 0/5xx retry, 4xx is definitive — an expired URL needs
    // resume's fresh URLs).
    putPart: (url, chunk, opts = {}) =>
      new Promise<string>((resolve, reject) => {
        // The rate-derived ceiling, when the governor has an estimate. The
        // backstop is the last-resort bound and is itself widened to sit above
        // any ceiling, so it can never become the effective (rate-blind) limit.
        const ceilingMs = opts.ceilingMs ?? null;
        const backstopMs = Math.max(
          opts.backstopMs ?? 300_000,
          ceilingMs === null ? 0 : Math.ceil(ceilingMs * 1.5),
        );
        const xhr = new XMLHttpRequest();
        let settled = false;
        const finish = (act: () => void) => {
          if (settled) return;
          settled = true;
          clearTimeout(ceiling);
          clearTimeout(backstop);
          act();
        };
        const ceiling =
          ceilingMs === null
            ? undefined
            : setTimeout(() => {
                finish(() => {
                  xhr.abort();
                  reject(
                    new StallError(
                      `the part took longer than its measured transfer rate predicts ` +
                        `(over ${Math.round(ceilingMs / 1000)}s) — retrying on a fresh connection`,
                    ),
                  );
                });
              }, ceilingMs);
        const backstop = setTimeout(() => {
          finish(() => {
            xhr.abort();
            reject(new StallError('part transfer exceeded the absolute per-attempt ceiling'));
          });
        }, backstopMs);
        xhr.onload = () =>
          finish(() => {
            // The relay's at-capacity signal (v04 S2): a DISTINCT disposition
            // that waits Retry-After without spending the retry budget.
            //
            // ⛔ bug219 — RE-KEYED FROM URL SHAPE TO THE DECLARED ERROR CODE.
            // This branch used to read `url.startsWith('/')`, because relay URLs
            // were relative by construction and presigned storage URLs absolute
            // (F3). The h1 transport fix serves parts from a dedicated upload
            // host, which makes relay URLs ABSOLUTE and INVERTS that test. Left
            // as it was, a relay `503 relay_at_capacity` would stop matching and
            // degrade to an ordinary retryable error — spending
            // `multipart_part_retry_attempts`, the exact budget the S2 review
            // protected it from, and silently killing `waitingForCapacitySeconds`
            // (bug075 row 18's server-busy UI). Nothing would have thrown.
            //
            // ⚠ The scope is UNCHANGED, only the evidence is: a storage 503
            // (S3 `SlowDown` etc.) answers with XML, not our error envelope, so
            // it does not match and stays an ordinary retryable error exactly as
            // before. We now identify a relay response by what it SAYS rather
            // than by where it came from — which is a property of the response,
            // not of the deployment topology, so the next transport change
            // cannot quietly invert it again.
            if (xhr.status === 503 && isRelayAtCapacityBody(xhr.responseText)) {
              const ra = Number.parseInt(xhr.getResponseHeader('retry-after') ?? '', 10);
              reject(new RelayBusyError(Number.isFinite(ra) && ra > 0 ? ra : 5));
              return;
            }
            if (xhr.status !== 200 && xhr.status !== 204) {
              reject(new SignetApiError(xhr.status, 'chunk_upload_failed', 'chunk PUT failed'));
              return;
            }
            const etag = xhr.getResponseHeader('etag');
            if (!etag) {
              reject(
                new SignetApiError(xhr.status, 'chunk_upload_failed', 'chunk PUT returned no ETag'),
              );
              return;
            }
            resolve(etag);
          });
        xhr.onerror = () =>
          finish(() =>
            reject(
              new SignetApiError(0, 'chunk_upload_failed', 'network failure during chunk PUT'),
            ),
          );
        opts.onAbortReady?.(() =>
          finish(() => {
            xhr.abort();
            reject(new TransferCancelledError());
          }),
        );
        xhr.open('PUT', url);
        xhr.send(chunk as XMLHttpRequestBodyInit);
      }),
    // Downloads are bounded by a rate-free NO-PROGRESS GAP, never by a flat
    // per-chunk deadline (bug060 §1; Gus, S127 W3).
    //
    // This previously armed a single flat 120 s `AbortController` deadline for the
    // whole chunk — an absolute wall-time constant bounding a `bytes ÷ rate`
    // quantity, i.e. bug060's exact shape on the download path. A chunk download is
    // one §4.2 envelope, so it is as large as the upload's chunk_size: ~0.35 Mbps
    // floor at the web's 5 MiB default, and **~4.4 Mbps** for a file uploaded at
    // 64 MiB (CLI `--chunk-size`) — squarely inside normal download speeds on a poor
    // link. And retries could not rescue it, because every attempt re-armed the same
    // wrong constant: the B3 structure again.
    //
    // It survived four review rounds because we had both accepted "downloads are
    // immune". That was true of the *stall* mechanism — reads observe arrival, so a
    // dead download flow really is detected — but immunity to silent stalls is not
    // immunity to a flat deadline, and this path never came under the governor at
    // all. The framing masked a different bound.
    //
    // A no-progress gap is the honest detector here precisely because download
    // progress is genuine: unlike a socket write, an arriving byte means a byte
    // actually arrived. Any chunk resets the timer, so a slow-but-moving download
    // runs as long as it needs while a dead one still dies in one gap interval.
    // Streaming the body also stops buffering an entire chunk before we can observe
    // any of it.
    getRange: async (url, start, end) => {
      const controller = new AbortController();
      // ⚠⚠ WHICH TIMER FIRED — the attribution S180 could not get from outside.
      // Our own aborts and Safari's CORS refusal both surface at the call site as
      // one rejected promise with `name: 'AbortError'` or a bare `TypeError`;
      // nothing downstream can tell "we gave up" from "the platform refused".
      // Recording the cause AT THE THROWER is the only place the answer exists.
      let abortCause: 'backstop' | 'first-byte' | 'gap' | null = null;
      // The ABSOLUTE per-chunk ceiling, derived from the requested range. The gap
      // below detects a dead flow; this bounds a live-but-trickling one, which the
      // gap correctly cannot (one byte just under the threshold IS progress). W4.
      const backstopMs = downloadBackstopMs(end - start + 1);
      const backstop = setTimeout(() => {
        abortCause = 'backstop';
        controller.abort();
      }, backstopMs);
      // First-byte bound `[rate-free]`: waiting for the store to begin answering is
      // a latency, not a transfer, so a constant is legitimate here.
      let timer = setTimeout(() => {
        abortCause = 'first-byte';
        controller.abort();
      }, DOWNLOAD_FIRST_BYTE_MS);
      trace('range-start', {
        bytes: end - start + 1,
        backstopMs,
        firstByteMs: DOWNLOAD_FIRST_BYTE_MS,
        gapMs: DOWNLOAD_GAP_MS,
      });
      try {
        const response = await doFetch(url, {
          method: 'GET',
          headers: { Range: `bytes=${start}-${end}` },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new SignetApiError(
            response.status,
            'chunk_download_failed',
            'chunk Range GET failed',
          );
        }

        const body = response.body;
        if (!body) {
          // No streaming reader (older environments, some test doubles). This path
          // cannot observe progress at all — `arrayBuffer()` is atomic — so it has
          // no gap to apply and relies entirely on the range-derived backstop above.
          //
          // A first draft armed DOWNLOAD_GAP_MS here and called it "degraded, not
          // unbounded". That was wrong twice over: a per-read gap value used as an
          // ATOMIC TOTAL is not a gap, and 20 s over a whole chunk is a *stricter*
          // cliff than the 120 s W3 removed — 2 Mbps at 5 MiB, 27 Mbps at 64 MiB —
          // i.e. a worse version of the defect, inside its own fix, under a comment
          // asserting it was safe (Gus, S127 W5). The gap timer is now cleared here
          // rather than repurposed.
          clearTimeout(timer);
          return new Uint8Array(await response.arrayBuffer());
        }

        const reader = body.getReader();
        const parts: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          clearTimeout(timer);
          timer = setTimeout(() => {
            abortCause = 'gap';
            controller.abort();
          }, DOWNLOAD_GAP_MS);
          const { done, value } = await reader.read();
          if (done) break;
          if (value && value.length > 0) {
            parts.push(value);
            total += value.length;
          }
        }
        clearTimeout(timer);

        const out = new Uint8Array(total);
        let offset = 0;
        for (const part of parts) {
          out.set(part, offset);
          offset += part.length;
        }
        trace('range-ok', { bytes: out.length });
        return out;
      } catch (error) {
        // ⭐ THE THREE-WAY SPLIT, resolved where it is knowable. `cause: null` on an
        // AbortError means the abort came from OUTSIDE our timers — the platform or
        // the page — which is a different finding from any ceiling of ours firing,
        // and the two are identical to every caller above this line.
        trace('range-failed', { cause: abortCause, ...errorIdentity(error) });
        throw error;
      } finally {
        clearTimeout(timer);
        clearTimeout(backstop);
      }
    },
    getMetadataKeyWrap: (folderId) =>
      request<MetadataKeyWrapResponse>(
        'GET',
        `/v1/folders/${encodeURIComponent(folderId)}/metadata-key-wrap`,
      ),
    updateFile: (fileId, body) =>
      request<FileView>('PATCH', `/v1/files/${encodeURIComponent(fileId)}`, body),
    updateFolder: (folderId, body) =>
      request<FolderView>('PATCH', `/v1/folders/${encodeURIComponent(folderId)}`, body),
    deleteFile: (fileId) => request<void>('DELETE', `/v1/files/${encodeURIComponent(fileId)}`),
    deleteFolder: (folderId) =>
      request<void>('DELETE', `/v1/folders/${encodeURIComponent(folderId)}`),
    deleteFilesBatch: (fileIds) =>
      request<BatchDeleteResponse>('DELETE', '/v1/files', { file_ids: fileIds }),
    deleteFoldersBatch: (folderIds) =>
      request<BatchDeleteResponse>('DELETE', '/v1/folders', { folder_ids: folderIds }),
    getQuota: () => request<QuotaResponse>('GET', '/v1/me/quota'),
    getMe: () => request<MeResponse>('GET', '/v1/me'),
    createCheckout: (tier) => request<RedirectResponse>('POST', '/v1/billing/checkout', { tier }),
    addCard: () => request<RedirectResponse>('POST', '/v1/billing/add-card'),
    createBillingPortal: () => request<RedirectResponse>('POST', '/v1/billing/portal'),
    getTiers: () => request<TiersResponse>('GET', '/v1/billing/tiers'),
    getRecipientKey: (handle) =>
      request<RecipientKey>('GET', `/v1/recipients/${encodeURIComponent(handle)}`),
    getServerInfo: () => request<ServerInfoResponse>('GET', '/v1/server-info'),
    getAttestationVerification: (attestationId) =>
      request<AttestationVerificationResponse>(
        'GET',
        `/v1/attestations/${encodeURIComponent(attestationId)}/verification`,
      ),
    getLogReceipt: (fingerprint, purpose) =>
      request<LogReceipt>(
        'GET',
        `/v1/transparency/log/receipt?fingerprint=${encodeURIComponent(fingerprint)}&purpose=${encodeURIComponent(purpose)}`,
      ),
    createShareFolder: (body) => request<ShareFolderView>('POST', '/v1/share-folders', body),
    listRecipients: (folderId) =>
      request<RecipientsResponse>(
        'GET',
        `/v1/share-folders/${encodeURIComponent(folderId)}/recipients`,
      ),
    createInvitation: (folderId, body) =>
      request<CreateInvitationResponse>(
        'POST',
        `/v1/share-folders/${encodeURIComponent(folderId)}/invitations`,
        body,
      ),
    listInvitations: (folderId) =>
      request<PendingInvitationsResponse>(
        'GET',
        `/v1/share-folders/${encodeURIComponent(folderId)}/invitations`,
      ),
    cancelInvitation: (folderId, invitationId) =>
      request<void>(
        'DELETE',
        `/v1/share-folders/${encodeURIComponent(folderId)}/invitations/${encodeURIComponent(invitationId)}`,
      ),
    previewInvitation: (token) =>
      request<InvitationPreview>('GET', `/v1/invitations/${encodeURIComponent(token)}`),
    acceptInvitation: (token) =>
      request<AcceptInvitationResponse>(
        'POST',
        `/v1/invitations/${encodeURIComponent(token)}/accept`,
      ),
    removeRecipient: (folderId, recipientId) =>
      request<void>(
        'DELETE',
        `/v1/share-folders/${encodeURIComponent(folderId)}/recipients/${encodeURIComponent(recipientId)}`,
      ),
    leaveShareFolder: (folderId) =>
      request<void>('POST', `/v1/share-folders/${encodeURIComponent(folderId)}/leave`),
    // bug130 (F-12): the honest path. `GET /v1/share-folders` now returns folders you OWN —
    // the collection its POST creates into — so shared-with-me has its own route.
    listSharedWithMe: () => request<SharedWithMeResponse>('GET', '/v1/shared-with-me'),
    listAudit: (cursor) =>
      request<ListAuditResponse>(
        'GET',
        cursor ? `/v1/me/audit?cursor=${encodeURIComponent(cursor)}` : '/v1/me/audit',
      ),
    listPrsns: () => request<ListPrsnsResponse>('GET', '/v1/me/prsns'),
    discardInProgressPrsn: (accountId: string) =>
      request<DiscardInProgressResult>(
        'POST',
        `/v1/me/prsns/${encodeURIComponent(accountId)}/discard`,
      ),
    listGarnetGrants: () => request<ListGarnetGrantsResponse>('GET', '/v1/garnet/grants'),
    listGarnetBrokers: () => request<ListGarnetBrokersResponse>('GET', '/v1/garnet/brokers'),
    mintBrokerProvisionCode: () =>
      request<GarnetProvisionCodeResult>('POST', '/v1/garnet/broker/provision-code'),
    ceremonyBegin: (operation, body) =>
      request<BeginResponse>('POST', `/v1/${operation}/ceremony/begin`, body),
    ceremonyComplete: <T>(operation: string, body: CeremonyCompleteBody) =>
      request<T>('POST', `/v1/${operation}/ceremony/complete`, body),
    rotatePasskeyBegin: () =>
      request<RotatePasskeyBeginResponse>('POST', '/v1/rotate-passkey/ceremony/begin'),
    rotatePasskeyComplete: (body) =>
      request<RotatePasskeyResult>('POST', '/v1/rotate-passkey/ceremony/complete', body),
    createEnrollment: () => request<CreateEnrollmentResponse>('POST', '/v1/prsn-enrollments'),
    confirmEnrollment: (code, handle, sharing) =>
      request<void>('POST', '/v1/prsn-enrollments/confirm', {
        code,
        handle,
        prsn_sharing_capability: sharing,
      }),
    cancelPendingEnrollment: (code) =>
      request<{ cancelled: boolean }>('POST', '/v1/prsn-enrollments/cancel', { code }),
    pollEnrollment: (code) =>
      request<EnrollmentStatusResponse>(
        'GET',
        `/v1/prsn-enrollments/status?code=${encodeURIComponent(code)}`,
      ),
    listConfig: () => request<AdminConfigListResponse>('GET', '/v1/admin/config'),
    updateConfig: (key, value) =>
      request<AdminConfigEntry>('PATCH', `/v1/admin/config/${encodeURIComponent(key)}`, { value }),
    getTransparencyStatus: () =>
      request<TransparencyStatusResponse>('GET', '/v1/admin/transparency-status'),
    listAdminAccounts: (cursor) =>
      request<ListAdminAccountsResponse>(
        'GET',
        cursor ? `/v1/admin/accounts?cursor=${encodeURIComponent(cursor)}` : '/v1/admin/accounts',
      ),
    createGrant: (body) => request<Grant>('POST', '/v1/admin/grants', body),
    extendGrant: (grantId, durationDays) =>
      request<Grant>('POST', `/v1/admin/grants/${encodeURIComponent(grantId)}/extend`, {
        duration_days: durationDays,
      }),
    revokeGrant: (grantId) =>
      request<Grant>('DELETE', `/v1/admin/grants/${encodeURIComponent(grantId)}`),
    deleteAccount: (accountId, confirmationHandle) =>
      request<{ account_id: string; status: string; pending_deletion_at: number }>(
        'POST',
        `/v1/admin/accounts/${encodeURIComponent(accountId)}/delete`,
        { confirmation_handle: confirmationHandle },
      ),
  };
}

async function toApiError(response: Response): Promise<SignetApiError> {
  let code = 'unknown_error';
  let message = response.statusText || 'request failed';
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    if (body.error?.code) code = body.error.code;
    if (body.error?.message) message = body.error.message;
  } catch {
    // non-JSON error body — keep the status-derived defaults
  }
  return new SignetApiError(response.status, code, message);
}
