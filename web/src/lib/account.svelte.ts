// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Reactive state for Account Settings (Platform Overview Views 5/5b). Holds the
// account summary (handle, paid_until, quota, key fingerprints, attestation), the
// guarded-PRSN list (Guardians only), and the audit history; owns the
// account-management actions, each of which runs an operation-bound ceremony (one
// passkey gesture) via the shared runner and then refreshes.
//
// Session-free by design: every C4 read rides the session cookie and every action
// rides a passkey assertion — none touches the KEM key. (Passkey rotation, which
// re-wraps the KEM key, is the one action that does; it lives apart in PR B.)

import {
  createApiClient,
  type AuditEvent,
  type GuardedPrsn,
  type MeResponse,
  type QuotaResponse,
  type TierAmount,
} from './api';
import { runCeremony } from './ceremony';
import type { KemPrivkeyWrap } from './crypto/kem_wrap';
import { friendlyBillingError, friendlyCeremonyError } from './errors';
import { rotatePasskey as runRotatePasskey } from './rotate';
import { browserGateway, type WebAuthnGateway } from './webauthn';

export interface AccountDeps {
  api: ReturnType<typeof createApiClient>;
  gateway: WebAuthnGateway;
}

export type SharingCapability = 'none' | 'read_only' | 'read_write';

export type AccountDialog =
  | { kind: 'setCapability'; prsn: GuardedPrsn }
  | { kind: 'deletePrsn'; prsn: GuardedPrsn }
  | { kind: 'deleteOwn' }
  | { kind: 'rotatePasskey' }
  | { kind: 'history' }
  | null;

/** What the route acts on after a Guardian self-deletion: the session is now
 *  invalid (the auth gate rejects a pending_deletion account), so the route clears
 *  it and shows the cascade count. */
export interface DeleteOwnOutcome {
  cascadedPrsnCount: number;
}

export class AccountStore {
  private readonly deps: AccountDeps;

  me = $state<MeResponse | null>(null);
  quota = $state<QuotaResponse | null>(null);
  /** The configured storage tiers (labels) for the subscribe-to-activate screen —
   *  loaded only for a human that still needs to activate; empty otherwise (or when
   *  billing is unconfigured on this deployment). */
  tiers = $state<string[]>([]);
  /** bug171: tier label → per-currency list amounts (absent = render labels
   *  without prices; the degrade contract). */
  tierPrices = $state<Record<string, TierAmount[]> | undefined>(undefined);
  /** PRSNs under the caller's guardianship (empty for a PRSN, or a human with none). */
  prsns = $state<GuardedPrsn[]>([]);
  audit = $state<AuditEvent[]>([]);
  auditDone = $state(false);
  auditLoading = $state(false);
  private auditCursor: string | null = null;

  loading = $state(true);
  busy = $state(false);
  /** Set while a checkout/portal redirect is being created (the button → Stripe). */
  billingBusy = $state(false);
  error = $state('');
  dialog = $state<AccountDialog>(null);
  /** True once a passkey rotation has succeeded (the rotate dialog shows its
   *  done state until closed). */
  rotateComplete = $state(false);

  /** Bound once so dispose() removes exactly the listener init() added (Bug033-1b). */
  readonly #onVisibilityChange = () => {
    if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
      // Refetch-on-return (the no-reload standard, Bug033 Tier-1b): the account cards
      // (plan/quota/PRSNs-in-care) may have moved while the tab was backgrounded — a
      // returning subscription, a lapsed one, an added PRSN. Quiet refresh, no spinner,
      // errors swallowed (a background refresh must never clobber the visible page).
      // Unlike the Garnet panel this does NOT poll — the account surface isn't "hot".
      void this.#quietRefresh();
    }
  };

  constructor(deps?: AccountDeps) {
    this.deps = deps ?? { api: createApiClient(), gateway: browserGateway };
  }

  get isPrsn(): boolean {
    return this.me?.account_type === 'prsn';
  }

  /** Re-read the card data without the loading spinner or error surface (Bug033-1b). */
  async #quietRefresh(): Promise<void> {
    try {
      const [me, quota] = await Promise.all([this.deps.api.getMe(), this.deps.api.getQuota()]);
      this.me = me;
      this.quota = quota;
      if (me.account_type === 'human') await this.loadPrsns();
    } catch {
      // background refresh — keep the current view on any failure
    }
  }

  /** Remove the visibilitychange listener init() armed. The account page calls this on
   *  unmount (without it a navigated-away store keeps a live listener). Idempotent. */
  dispose(): void {
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this.#onVisibilityChange);
    }
  }

  async init(): Promise<void> {
    this.loading = true;
    this.error = '';
    try {
      const [me, quota] = await Promise.all([this.deps.api.getMe(), this.deps.api.getQuota()]);
      this.me = me;
      this.quota = quota;
      // Only a human can guard PRSNs; skip the call entirely for a PRSN account.
      if (me.account_type === 'human') await this.loadPrsns();
      // The tiers are only rendered on the subscribe-to-activate screen — load them
      // only when a human still needs to activate (an activated/lapsed account uses
      // the Stripe portal, which needs no tier list).
      if (me.account_type === 'human' && me.needs_activation) await this.loadTiers();
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.loading = false;
    }
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', this.#onVisibilityChange);
    }
  }

  private async loadPrsns(): Promise<void> {
    const { prsns } = await this.deps.api.listPrsns();
    this.prsns = prsns;
  }

  private async loadTiers(): Promise<void> {
    const { tiers, prices } = await this.deps.api.getTiers();
    this.tiers = tiers;
    this.tierPrices = prices;
  }

  // --- billing (D2: subscribe-to-activate + manage) -------------------------
  // Both create a Stripe-hosted URL the route redirects the browser to. The store
  // stays DOM-free: it returns the URL (or null on failure, with `error` set) and
  // the route performs `window.location.href = url`. On success `billingBusy` stays
  // set — the page is leaving for Stripe.

  /** Start a subscription Checkout for a tier (the trial upgrade path); returns the Stripe URL. */
  async startCheckout(tier: string): Promise<string | null> {
    this.billingBusy = true;
    this.error = '';
    try {
      const { url } = await this.deps.api.createCheckout(tier);
      return url;
    } catch (e) {
      this.error = friendlyBillingError(e);
      this.billingBusy = false;
      return null;
    }
  }

  /** Start a setup-mode Checkout to save a card and extend the free trial's with-card
   *  window (never charged, S134); returns the Stripe URL. */
  async addCard(): Promise<string | null> {
    this.billingBusy = true;
    this.error = '';
    try {
      const { url } = await this.deps.api.addCard();
      return url;
    } catch (e) {
      this.error = friendlyBillingError(e);
      this.billingBusy = false;
      return null;
    }
  }

  /** Open the Stripe Billing Portal (update card / change tier / cancel / recover a
   *  lapsed subscription); returns the Stripe URL. */
  async openBillingPortal(): Promise<string | null> {
    this.billingBusy = true;
    this.error = '';
    try {
      const { url } = await this.deps.api.createBillingPortal();
      return url;
    } catch (e) {
      this.error = friendlyBillingError(e);
      this.billingBusy = false;
      return null;
    }
  }

  // --- audit history (lazy, keyset-paginated) -------------------------------

  async openHistory(): Promise<void> {
    this.dialog = { kind: 'history' };
    this.error = '';
    if (this.audit.length === 0 && !this.auditDone) await this.loadMoreAudit();
  }

  async loadMoreAudit(): Promise<void> {
    if (this.auditLoading || this.auditDone) return;
    this.auditLoading = true;
    try {
      const { events, next_cursor } = await this.deps.api.listAudit(this.auditCursor ?? undefined);
      this.audit = [...this.audit, ...events];
      this.auditCursor = next_cursor;
      this.auditDone = next_cursor === null;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.auditLoading = false;
    }
  }

  // --- dialog openers -------------------------------------------------------

  openSetCapability(prsn: GuardedPrsn): void {
    this.dialog = { kind: 'setCapability', prsn };
    this.error = '';
  }
  openDeletePrsn(prsn: GuardedPrsn): void {
    this.dialog = { kind: 'deletePrsn', prsn };
    this.error = '';
  }
  openDeleteOwn(): void {
    this.dialog = { kind: 'deleteOwn' };
    this.error = '';
  }
  openRotatePasskey(): void {
    this.dialog = { kind: 'rotatePasskey' };
    this.error = '';
    this.rotateComplete = false;
  }
  closeDialog(): void {
    this.dialog = null;
    this.error = '';
    this.rotateComplete = false;
  }

  // --- Guardian actions (each = one passkey gesture) ------------------------

  // (startEnrollment was removed in §1-62: the add-PRSN wizard names first and
  // mints on Continue — the step-1 page calls createEnrollment + confirmEnrollment
  // itself; see routes/account/add-prsn/+page.svelte and the design note §5.)

  async setCapability(prsn: GuardedPrsn, capability: SharingCapability): Promise<void> {
    await this.run(async () => {
      await runCeremony(this.deps, 'change-sharing-capability', {
        subject_account_id: prsn.account_id,
        prsn_sharing_capability: capability,
      });
      await this.loadPrsns();
    });
  }

  async deletePrsn(prsn: GuardedPrsn, confirmationHandle: string): Promise<void> {
    await this.run(async () => {
      await runCeremony(this.deps, 'delete-account', {
        subject_account_id: prsn.account_id,
        confirmation_handle: confirmationHandle.trim(),
      });
      await this.loadPrsns();
    });
  }

  /** Delete the Guardian's own account (cascades to every PRSN in their
   *  guardianship). On success the account is `pending_deletion`; the auth gate
   *  then rejects it, so the route clears the session. Returns the outcome (incl.
   *  the cascade count) or null on failure (with `error` set). Not routed through
   *  `run()` because it must NOT close the dialog on success — the route takes over. */
  async deleteOwn(confirmationHandle: string): Promise<DeleteOwnOutcome | null> {
    this.busy = true;
    this.error = '';
    try {
      const result = await runCeremony<{ cascaded_prsn_count: number }>(
        this.deps,
        'delete-account',
        { confirmation_handle: confirmationHandle.trim() },
      );
      return { cascadedPrsnCount: result.cascaded_prsn_count };
    } catch (e) {
      this.error = friendlyCeremonyError(e);
      return null;
    } finally {
      this.busy = false;
    }
  }

  /** Rotate the human's passkey: run the 3-gesture browser-side re-wrap and, on
   *  success, return the new wrapped KEM blob for the route to store in the session
   *  (the KEM keypair + its public key are unchanged). Not routed through `run()` —
   *  it must keep the dialog open to show its done state. */
  async rotatePasskey(currentBlob: KemPrivkeyWrap): Promise<KemPrivkeyWrap | null> {
    this.busy = true;
    this.error = '';
    try {
      const newBlob = await runRotatePasskey(this.deps, currentBlob);
      this.rotateComplete = true;
      return newBlob;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
      return null;
    } finally {
      this.busy = false;
    }
  }

  // --- helpers --------------------------------------------------------------

  /** Run a gesture-bearing action: set busy, run, close the dialog on success,
   *  map any failure to calm copy. Mirrors the file browser's `mutate`. */
  private async run(op: () => Promise<void>): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await op();
      this.dialog = null;
    } catch (e) {
      this.error = friendlyCeremonyError(e);
    } finally {
      this.busy = false;
    }
  }
}
