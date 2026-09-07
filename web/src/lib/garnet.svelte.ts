// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Reactive state for the Garnet guardian dashboard (Phase 4 §6) — the guardian's
// web surface for the PRSN Drive-access standing-grant lifecycle. Holds the active
// grants + the guarded-PRSN roster (the roster supplies the `subject_account_id` an
// authorize needs — the grants list carries only handles), and owns the two
// gesture-bearing actions (authorize / revoke), each an operation-bound ceremony
// (one passkey gesture) via the shared runner, then a refresh.
//
// Self-contained + session-free by design: every read rides the session cookie and
// every action a passkey assertion — none touches the KEM key. Modeled on
// AccountStore. Canonical: Garnet Design-Spec v05 §6 + Auth-Core v08 §5/§7.
//
// Scope: the active-PRSN panel + one-click revoke + authorize (Phase-4 Inc.2) + the
// bug085 one-tap RE-confirm for a grant inside its eligibility window. No pairing
// codes and no hard-confirm match-gate (bug084 flag-day): the agent claims a grant by
// SIGNING its pickup, which auto-confirms it — after authorize the guardian only
// waits. Re-grant (reactivate-vs-fresh) is still deferred.

import {
  createApiClient,
  type GarnetAuthorizeResult,
  type GarnetBroker,
  type GarnetGrant,
  type GarnetProvisionCodeResult,
  type GuardedPrsn,
} from './api';
import type { AccountDeps } from './account.svelte';
import { hasHotGrant, neverAuthorizedPrsns, revokedPrsns } from './garnet';
import { runCeremony } from './ceremony';
import { friendlyCeremonyError } from './errors';
import { browserGateway } from './webauthn';

/** How often the dashboard re-reads grant state while a grant is "hot" (Bug033 — the
 *  no-reload standard): pickup/contest/overdue changes arrive from outside the browser,
 *  so an awaiting/contested/overdue panel refreshes itself instead of teaching the
 *  guardian the reload habit (each reload also costs an unlock gesture, Bug014). */
const HOT_POLL_MS = 10_000;

export type GarnetDialog =
  // §1-64: `account_id` preselects the picker when the dialog is opened from a
  // specific PRSN's row (the consolidated card's inline Authorize); absent for
  // the generic open. The picker itself stays — the bug086 allocation facts
  // render before the gesture either way.
  | { kind: 'authorize'; account_id?: string }
  | { kind: 'revoke'; grant: GarnetGrant }
  // The bug085 one-tap RE-confirm (the narrowed ceremony — no fingerprint entry; the
  // server gates eligibility via `reconfirm_available`).
  | { kind: 'confirm'; grant: GarnetGrant }
  // The broker-setup code hand-off: shown once, after minting a provisioning code.
  | { kind: 'provision'; result: GarnetProvisionCodeResult }
  // "Remove this Mac": the guardian deregisters their provisioned broker (a passkey confirm).
  | { kind: 'removeBroker'; broker: GarnetBroker }
  | null;

export class GarnetStore {
  private readonly deps: AccountDeps;

  /** The guardian's Garnet grants (active + revoked), newest-server-order. */
  grants = $state<GarnetGrant[]>([]);
  /** PRSNs under the caller's guardianship — the source of `subject_account_id`
   *  for an authorize, and of the authorizable-PRSN picker. */
  prsns = $state<GuardedPrsn[]>([]);
  /** Brokers provisioned under the guardian (v1 = 0 or 1). Empty ⇒ the guardian has not set up
   *  `signet` on their Mac yet, so the dashboard shows the setup step before any PRSN can connect. */
  brokers = $state<GarnetBroker[]>([]);
  /** bug161 step 6: the read-only grace length (days) after a missed re-confirm deadline —
   *  a runtime knob delivered with the grants list. `null` until the first response (or
   *  against an older server); copy omits the grace sentence in that case rather than
   *  hardcoding a figure. */
  graceDays = $state<number | null>(null);

  loading = $state(true);
  busy = $state(false);
  error = $state('');
  dialog = $state<GarnetDialog>(null);
  /** bug114 Part E, relocated for §1-64: which PRSN's connection-instructions modal
   *  is open (the handle), or null. Pure UI state — it lives on the store so the
   *  consolidated card (the trigger) and the dialog host (the renderer) share it
   *  without a component-tree channel. */
  instructionsFor = $state<string | null>(null);

  /** Whether the guardian has provisioned a broker (set up `signet` on their Mac). A PRSN's pickup
   *  requires it (the §4 SPKI pin is delivered from the registered broker), so the dashboard guides
   *  the guardian to set it up first. */
  get hasBroker(): boolean {
    return this.brokers.length > 0;
  }

  /** The pending hot-poll timer (Bug033), or null when the panel is quiet. */
  #pollTimer: ReturnType<typeof setTimeout> | null = null;
  /** Bound once so dispose() can remove exactly the listener init() added. */
  readonly #onVisibilityChange = () => {
    if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
      // Refetch-on-return: the tab was backgrounded (or the user came back to it) —
      // state may have moved while we weren't looking. Quiet refresh + re-arm the poll.
      void this.#quietRefresh();
    }
  };

  constructor(deps?: AccountDeps) {
    this.deps = deps ?? { api: createApiClient(), gateway: browserGateway };
  }

  /** PRSNs that can be authorized for the FIRST time: a guarded PRSN in good standing
   *  with NO grant of any kind yet (the server re-checks guardianship + the no-duplicate
   *  invariant — this is the friendly client-side filter). Drives the "Authorize a PRSN"
   *  picker. A deliberately-revoked PRSN is NOT here — it re-authorizes via `revokedPrsns`
   *  (bug108 §6). */
  get neverAuthorizedPrsns(): GuardedPrsn[] {
    return neverAuthorizedPrsns(this.grants, this.prsns);
  }

  /** PRSNs the guardian authorized and then deliberately revoked (a grant exists, none
   *  active). bug108 §6: each gets a muted "Revoked · Re-authorize" row in the panel;
   *  Re-authorize reuses `authorize()` (a fresh grant, new 30-day window). */
  get revokedPrsns(): GuardedPrsn[] {
    return revokedPrsns(this.grants, this.prsns);
  }

  async init(): Promise<void> {
    this.loading = true;
    this.error = '';
    try {
      const [{ grants, grace_days }, { prsns }, { brokers }] = await Promise.all([
        this.deps.api.listGarnetGrants(),
        this.deps.api.listPrsns(),
        this.deps.api.listGarnetBrokers(),
      ]);
      this.grants = grants;
      this.graceDays = grace_days ?? null;
      this.prsns = prsns;
      this.brokers = brokers;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.loading = false;
    }
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', this.#onVisibilityChange);
    }
    this.#schedulePoll();
  }

  /** Tear down the timers/listeners init() armed. The component calls this on unmount —
   *  without it a navigated-away panel would keep polling forever. Idempotent. */
  dispose(): void {
    if (this.#pollTimer != null) {
      clearTimeout(this.#pollTimer);
      this.#pollTimer = null;
    }
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.#onVisibilityChange);
    }
  }

  private async loadGrants(): Promise<void> {
    const { grants, grace_days } = await this.deps.api.listGarnetGrants();
    this.grants = grants;
    this.graceDays = grace_days ?? null;
    this.#schedulePoll();
  }

  /** Arm one hot-poll tick iff the panel is hot + visible and none is pending (Bug033).
   *  Every grants read re-calls this, so polling continues exactly as long as a hot
   *  state exists and stops on its own the moment the panel goes quiet. Two hot
   *  conditions: a hot GRANT (awaiting pickup / contested / overdue — an
   *  awaiting-pickup grant is hot by definition, so the post-authorize wait polls
   *  without extra machinery), and NO REGISTERED BROKER (Chris, S145: the Mac-setup
   *  card clears by itself when the connection registers — the old explicit
   *  "check again" button was user confusion; the poll is visibility-gated, so a
   *  hidden tab costs nothing, and it stops the moment a broker appears). */
  #schedulePoll(): void {
    if (this.#pollTimer != null) return;
    if (!hasHotGrant(this.grants) && this.hasBroker) return;
    if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
    this.#pollTimer = setTimeout(() => {
      this.#pollTimer = null;
      void this.#quietRefresh();
    }, HOT_POLL_MS);
  }

  /** Re-read the panel's server state WITHOUT the loading flag (no flicker) and without
   *  clobbering a user-facing error with a transient poll failure — a failed tick just
   *  re-arms and tries again. Also refreshes the roster + brokers (cheap session-cookie
   *  GETs), so refetch-on-return covers the whole panel, not only grant rows. */
  async #quietRefresh(): Promise<void> {
    try {
      const [{ grants, grace_days }, { prsns }, { brokers }] = await Promise.all([
        this.deps.api.listGarnetGrants(),
        this.deps.api.listPrsns(),
        this.deps.api.listGarnetBrokers(),
      ]);
      this.grants = grants;
      this.graceDays = grace_days ?? null;
      this.prsns = prsns;
      this.brokers = brokers;
    } catch {
      // Transient (network blip, laptop wake): keep the last-known state; the re-armed
      // poll below retries while the panel stays hot.
    }
    this.#schedulePoll();
  }

  // (The explicit "check again" broker re-fetch is GONE — Chris, S145: the
  //  broker-less state is a hot-poll condition, so the setup card clears by
  //  itself when the connection registers. See #schedulePoll.)

  // --- dialog openers -------------------------------------------------------

  openAuthorize(accountId?: string): void {
    this.dialog = { kind: 'authorize', account_id: accountId };
    this.error = '';
  }
  openRevoke(grant: GarnetGrant): void {
    this.dialog = { kind: 'revoke', grant };
    this.error = '';
  }
  openConfirm(grant: GarnetGrant): void {
    this.dialog = { kind: 'confirm', grant };
    this.error = '';
  }
  openRemoveBroker(broker: GarnetBroker): void {
    this.dialog = { kind: 'removeBroker', broker };
    this.error = '';
  }
  closeDialog(): void {
    this.dialog = null;
    this.error = '';
  }

  // --- Guardian actions (each = one passkey gesture) ------------------------

  /** Authorize a PRSN for Garnet: ONE passkey gesture mints the standing grant —
   *  the whole guardian act (bug084). No pairing code and nothing to hand over: the
   *  agent claims the grant by signing its pickup on its next Signet Drive use, which
   *  auto-confirms it. On success the dialog closes and the (hot) grant list shows
   *  the awaiting-pickup state. The cadence is platform-fixed (bug085) — no interval
   *  parameter. */
  async authorize(subjectAccountId: string): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await runCeremony<GarnetAuthorizeResult>(this.deps, 'garnet-authorize-grant', {
        subject_account_id: subjectAccountId,
      });
      await this.loadGrants();
      this.dialog = null;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Revoke a Garnet grant: one passkey gesture cuts account access instantly and
   *  SE access within the revocation lease (§5.3). Closes the dialog on success. */
  async revoke(grantId: string): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await runCeremony(this.deps, 'garnet-revoke-grant', { grant_id: grantId });
      await this.loadGrants();
      this.dialog = null;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.busy = false;
    }
  }

  /** bug108: discard a PRSN still in setup (never-authorized) — a session-authenticated
   *  wipe, NOT a passkey ceremony (D1, S154). The server refuses anything that has ever
   *  been authorized. On success the account is marked for purge; refresh the roster so it
   *  drops out of the panel/wizard. Returns true only when the wipe actually landed, so the
   *  caller navigates away on success and shows `store.error` on failure. */
  async discardInProgress(accountId: string): Promise<boolean> {
    this.busy = true;
    this.error = '';
    try {
      await this.deps.api.discardInProgressPrsn(accountId);
      const { prsns } = await this.deps.api.listPrsns();
      this.prsns = prsns;
      return true;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
      return false;
    } finally {
      this.busy = false;
    }
  }

  /** The bug085 one-tap RE-confirm: one passkey gesture re-stamps an eligible grant's
   *  cadence anchor (`last_confirmed_at`). No fingerprint entry — bug084 retired the
   *  match-gate (first-contact confirmation is stamped by the agent's own signed
   *  pickup); the server gates eligibility (window open, not contested) and re-checks
   *  it atomically. Closes on success. */
  async confirm(grantId: string): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await runCeremony(this.deps, 'garnet-confirm-enrollment', { grant_id: grantId });
      await this.loadGrants();
      this.dialog = null;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Mint a single-use broker-provisioning ("setup") code for the guardian to enter when they install
   *  `signet` on their Mac. Session-authenticated, NOT a passkey ceremony — a provisioned-but-
   *  unconfirmed broker holds no keys and can do nothing, so the server gates this on the session
   *  alone. On success the dialog becomes the code hand-off (the code is returned only once). */
  async mintProvisionCode(): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      const result = await this.deps.api.mintBrokerProvisionCode();
      this.dialog = { kind: 'provision', result };
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Remove ("deregister") the guardian's provisioned broker — the "remove this Mac" control. One
   *  passkey gesture deletes the registration so the guardian can re-provision a fresh Mac (or leave
   *  it removed). The PRSNs re-pickup against a new broker; files are unaffected. Closes on success. */
  async removeBroker(brokerId: string): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await runCeremony(this.deps, 'garnet-remove-broker', { broker_id: brokerId });
      const { brokers } = await this.deps.api.listGarnetBrokers();
      this.brokers = brokers;
      this.dialog = null;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.busy = false;
    }
  }
}
