// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Reactive state for the PRSN confirm-and-approve page (S052 onboarding
// automation; canonical: Signet-Drive-PRSN-Account-and-Kit-Spec §a). This is the
// *visible* half of the 1-23 fix: the Guardian approves an enrollment their agent
// (or they, browser-first) opened, with NO hand-transcription of keys.
//
// The flow the page drives:
//   1. confirm  — the Guardian names the PRSN + sets its sharing capability
//                 (POST /confirm; all gating runs here, server-side).
//   2. waiting  — poll status while the agent generates keys in the Secure Enclave
//                 and submits the public halves (status → keys_submitted).
//   3. approve  — one Touch ID: the issue-attestation ceremony, passed the
//                 enrollment_code so the server attests exactly the keys the agent
//                 submitted (the ceremony↔enrollment binding — not client input).
//   4. done.
//
// The agent is never authenticated; every step here rides the Guardian's session
// (and one passkey gesture at approve). Session-free otherwise — no KEM key touched.

import { SignetApiError, createApiClient } from './api';
import type { AccountDeps, SharingCapability } from './account.svelte';
import { runCeremony } from './ceremony';
import { friendlyCeremonyError } from './errors';
import { appendAiSuffix, normalizeHandle, validatePrsnHandle } from './handle';
import { browserGateway } from './webauthn';

/** In THIS flow a `not_found` means the enrollment row itself is gone — almost
 *  always TTL expiry (the guardian came back to a stale tab or re-entered an
 *  old code). The shared ceremony mapping words `not_found` for its
 *  guardianship context, which is wrong here (Bug031-3) — the enrollment
 *  wording matches the agent-side CLI's equivalent message. */
function friendlyEnrollError(error: unknown): string {
  if (error instanceof SignetApiError && error.code === 'not_found') {
    return 'This enrollment expired — start over from + Add PRSN.';
  }
  return friendlyCeremonyError(error);
}

export type EnrollPhase = 'resolving' | 'confirm' | 'waiting' | 'approve' | 'done';

/** Poll cadence while waiting for the agent's keys. Overridable for tests. */
const POLL_MS = 2000;

/** How long to wait before showing the "taking longer than expected" reassurance
 *  (Bug018). The keygen itself is sub-second; a longer wait usually means the agent
 *  hasn't run `signet enroll <code>` yet. Overridable for tests. */
const SLOW_AFTER_MS = 45000;

export class EnrollmentStore {
  private readonly deps: AccountDeps;
  private readonly pollMs: number;
  private readonly slowMs: number;
  private readonly code: string;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private slowTimer: ReturnType<typeof setTimeout> | null = null;

  phase = $state<EnrollPhase>('resolving');
  /** The PRSN handle — editable until confirm; ends in `-ai`. */
  handle = $state('');
  sharing = $state<SharingCapability>('read_only');
  busy = $state(false);
  error = $state('');
  /** The latest server-reported enrollment status (drives the waiting copy). */
  status = $state('pending');
  /** True once the wait has exceeded {@link SLOW_AFTER_MS} — the page then shows a
   *  "taking longer than expected? make sure your agent ran enroll" hint (Bug018). */
  slow = $state(false);

  constructor(
    code: string,
    deps?: AccountDeps,
    pollMs: number = POLL_MS,
    slowMs: number = SLOW_AFTER_MS,
  ) {
    this.code = code;
    this.deps = deps ?? { api: createApiClient(), gateway: browserGateway };
    this.pollMs = pollMs;
    this.slowMs = slowMs;
  }

  /** The `signet enroll <code>` command to hand the agent (browser-first; harmless
   *  in agent-first, where the agent is already running it). */
  get enrollCommand(): string {
    return `signet enroll ${this.code}`;
  }

  /** Bug028: derive the starting phase from the SERVER's row, not a hardcoded
   *  'confirm'. The wizard's phase used to live only in client memory, so a lost
   *  tab / navigation / sign-in bounce between the agent's key submission and the
   *  Touch-ID approve restarted the wizard at naming — Confirm then failed (the row
   *  is `keys_submitted`, not `pending`) and NO surface listed the in-flight
   *  enrollment: unrecoverable by the guardian, dead at TTL. Called once on mount
   *  (the page's store-creating $effect); one poll, then:
   *    pending                    → 'confirm'  (a genuinely new enrollment)
   *    confirmed                  → 'waiting'  (re-enter the poll loop mid-flow)
   *    keys_submitted / completed → 'approve'  (the stranded case this fixes)
   *    expired/cancelled/failed   → 'confirm' + the start-over error
   *  A transient error also falls back to 'confirm' (the pre-fix behavior). */
  async resume(): Promise<void> {
    try {
      const res = await this.deps.api.pollEnrollment(this.code);
      this.status = res.status;
      if (res.handle) this.handle = res.handle;
      switch (res.status) {
        case 'keys_submitted':
        case 'completed':
          this.phase = 'approve';
          return;
        case 'confirmed':
          this.phase = 'waiting';
          this.slow = false;
          this.slowTimer = setTimeout(() => {
            this.slow = true;
          }, this.slowMs);
          this.timer = setTimeout(() => void this.poll(), this.pollMs);
          return;
        case 'expired':
          this.phase = 'confirm';
          this.error = 'This enrollment expired — start over from + Add PRSN.';
          return;
        case 'cancelled':
          this.phase = 'confirm';
          this.error = 'This enrollment was cancelled — start over from + Add PRSN.';
          return;
        case 'failed':
          this.phase = 'confirm';
          this.error = 'This enrollment failed — start over from + Add PRSN.';
          return;
        default:
          // 'pending' — the ordinary fresh flow.
          this.phase = 'confirm';
      }
    } catch (e) {
      // not_found → the row is gone (TTL); anything else → degrade to the pre-fix
      // behavior (show the form) rather than stranding on the resolving spinner.
      this.phase = 'confirm';
      if (e instanceof SignetApiError && e.code === 'not_found') {
        this.error = friendlyEnrollError(e);
      }
    }
  }

  /** Step 1 → 2. Suffix + validate the name locally, then POST /confirm (server
   *  gating: Guardian in good standing, the pooled cap, handle availability +
   *  `-ai`). On success, advance to waiting and start polling.
   *
   *  §1-62 / design note §4: the user types the BASE — `-ai` is appended here,
   *  idempotently (the field shows the suffix as a fixed adornment). The old
   *  reject-with-an-error is gone; the rule is invariant, so the user never has
   *  to know it. */
  async confirm(): Promise<void> {
    const handle = appendAiSuffix(normalizeHandle(this.handle));
    if (validatePrsnHandle(handle) != null) {
      this.error = 'Use lowercase letters, digits and hyphens (2–61 characters).';
      return;
    }
    this.handle = handle;
    this.busy = true;
    this.error = '';
    try {
      await this.deps.api.confirmEnrollment(this.code, handle, this.sharing);
      this.phase = 'waiting';
      this.slow = false;
      this.slowTimer = setTimeout(() => {
        this.slow = true;
      }, this.slowMs);
      this.poll();
    } catch (e) {
      this.error = friendlyEnrollError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Poll the rendezvous while waiting for the agent. `keys_submitted` → advance to
   *  approve; a terminal failure → surface it and stop. */
  private async poll(): Promise<void> {
    try {
      const res = await this.deps.api.pollEnrollment(this.code);
      this.status = res.status;
      switch (res.status) {
        case 'keys_submitted':
        case 'completed':
          this.clearSlow();
          this.phase = 'approve';
          return; // stop polling — the human approves next
        case 'expired':
          this.fail('This enrollment expired. Start over from Add PRSN.');
          return;
        case 'cancelled':
          this.fail('This enrollment was cancelled.');
          return;
        case 'failed':
          this.fail('This enrollment failed. Start over from Add PRSN.');
          return;
        default:
          // pending / confirmed — keep waiting.
          this.timer = setTimeout(() => void this.poll(), this.pollMs);
      }
    } catch (e) {
      // A transient poll error: keep trying (the agent may still be working).
      this.timer = setTimeout(() => void this.poll(), this.pollMs);
      void e;
    }
  }

  /** Step 3 → 4. One Touch ID: issue the attestation, bound to this enrollment (the
   *  server sources the keys from the confirmed row — no hand-transcription). */
  async approve(): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await runCeremony(this.deps, 'issue-attestation', { enrollment_code: this.code });
      this.phase = 'done';
    } catch (e) {
      this.error = friendlyEnrollError(e);
    } finally {
      this.busy = false;
    }
  }

  private fail(message: string): void {
    this.clearSlow();
    this.error = message;
    this.status = 'failed';
  }

  private clearSlow(): void {
    if (this.slowTimer) clearTimeout(this.slowTimer);
    this.slowTimer = null;
  }

  /** Stop the poll + slow timers (the page calls this on teardown). */
  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.clearSlow();
  }
}
