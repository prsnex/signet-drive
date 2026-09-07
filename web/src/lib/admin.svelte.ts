// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Reactive state for the View 6 Admin Dashboard (Platform Overview §8): the
// runtime System Config (§8.1, editable), the Transparency Log Status (§8.2,
// read-only), and account management with comped-account grants (§8 / list +
// grant / extend / revoke). Admin-only: init() reads /v1/me first and sets
// `forbidden` for a non-admin so the route can redirect. Every read + mutation
// rides the human session cookie — these are session-authed admin operations,
// not key-bearing ones, so (unlike the C4 account actions) none runs a ceremony.

import { fetchAllAccounts } from './admin-accounts';
import {
  createApiClient,
  type AdminAccount,
  type AdminConfigEntry,
  type MeResponse,
  type TransparencyStatusResponse,
  type SignupGateStatus,
} from './api';
import { friendlyAdminError } from './errors';

export interface AdminDeps {
  api: ReturnType<typeof createApiClient>;
}

export type AdminDialog =
  | { kind: 'editConfig'; entry: AdminConfigEntry }
  | { kind: 'grant'; account: AdminAccount }
  | { kind: 'extend'; account: AdminAccount }
  | { kind: 'revoke'; account: AdminAccount }
  | null;

export class AdminStore {
  private readonly deps: AdminDeps;

  me = $state<MeResponse | null>(null);
  /** Set when /v1/me reports a non-admin caller — the route redirects on it. */
  forbidden = $state(false);

  config = $state<AdminConfigEntry[]>([]);
  transparency = $state<TransparencyStatusResponse | null>(null);
  accounts = $state<AdminAccount[]>([]);
  accountsDone = $state(false);
  accountsLoading = $state(false);

  // --- the signup gate (S206) ----------------------------------------------
  gate = $state<SignupGateStatus | null>(null);
  gateBusy = $state(false);

  loading = $state(true);
  busy = $state(false);
  error = $state('');
  dialog = $state<AdminDialog>(null);

  constructor(deps?: AdminDeps) {
    this.deps = deps ?? { api: createApiClient() };
  }

  async init(): Promise<void> {
    this.loading = true;
    this.error = '';
    try {
      const me = await this.deps.api.getMe();
      this.me = me;
      if (!me.admin_role) {
        this.forbidden = true;
        return;
      }

      const [config, transparency, gate] = await Promise.all([
        this.deps.api.listConfig(),
        this.deps.api.getTransparencyStatus(),
        this.deps.api.getSignupGate(),
      ]);
      this.config = config.config;
      this.transparency = transparency;
      this.gate = gate;
      await this.loadAllAccounts();
    } catch (e) {
      this.error = friendlyAdminError(e);
    } finally {
      this.loading = false;
    }
  }

  // --- the signup gate ------------------------------------------------------
  //
  // ⭐ EVERY MUTATION RE-READS FROM THE SERVER rather than patching local state from
  // the response. The cohort's `used` is DERIVED server-side by counting accounts, so
  // a locally-patched figure would be a second copy of a number the server owns — the
  // drift shape this whole feature deliberately avoids.

  async setSignupMode(mode: 'open' | 'paused' | 'limited'): Promise<void> {
    this.gateBusy = true;
    this.error = '';
    try {
      this.gate = await this.deps.api.setSignupGateMode(mode);
    } catch (e) {
      this.error = friendlyAdminError(e);
    } finally {
      this.gateBusy = false;
    }
  }

  async openCohort(label: string, maxAccounts: number): Promise<void> {
    this.gateBusy = true;
    this.error = '';
    try {
      await this.deps.api.openSignupCohort(label, maxAccounts);
      this.gate = await this.deps.api.getSignupGate();
    } catch (e) {
      this.error = friendlyAdminError(e);
    } finally {
      this.gateBusy = false;
    }
  }

  async closeCohort(cohortId: string): Promise<void> {
    this.gateBusy = true;
    this.error = '';
    try {
      await this.deps.api.closeSignupCohort(cohortId);
      this.gate = await this.deps.api.getSignupGate();
    } catch (e) {
      this.error = friendlyAdminError(e);
    } finally {
      this.gateBusy = false;
    }
  }

  /** Invite one person past a closed gate. Returns true on success so the caller
   *  can clear its form only when the invite actually went out. */
  async inviteSignup(email: string, handle: string): Promise<boolean> {
    this.gateBusy = true;
    this.error = '';
    try {
      await this.deps.api.createSignupInvite(email, handle);
      return true;
    } catch (e) {
      this.error = friendlyAdminError(e);
      return false;
    } finally {
      this.gateBusy = false;
    }
  }

  // --- account list (keyset-paginated) --------------------------------------

  // Loads EVERY account. The cursor-following loop lives in `fetchAllAccounts`
  // (plain module, under test) because this file uses runes and vitest runs
  // without the Svelte plugin — so the correctness-critical part is the part
  // that can actually be exercised. See that function for why a partial list is
  // never acceptable here.
  //
  // ⚠ On failure the rows are DISCARDED and `accountsDone` stays false: the sort
  // headers are gated on it, so the table cannot rank a fragment. The retry in
  // the pane re-runs this.
  //
  // ⛔ `loadGen` is not ceremony (Gus, review of 35b83b5e). This used to bail on
  // `accountsLoading`, which SILENTLY DROPPED a refresh requested during an
  // in-flight drain — the pre-grant result then landed as "complete". That was
  // unreachable only because `reloadAccounts` blanked the table first and took
  // away the rows you would click; the blank was an accidental guard, and
  // removing it (P1) would have exposed the bug. The counter makes the newest
  // request win on its own terms instead.
  private loadGen = 0;

  async loadAllAccounts(): Promise<void> {
    if (this.accountsDone) return;
    const gen = ++this.loadGen;
    this.accountsLoading = true;
    try {
      const all = await fetchAllAccounts((cursor) => this.deps.api.listAdminAccounts(cursor));
      if (gen !== this.loadGen) return; // superseded — a newer load owns the state
      this.accounts = all;
      this.accountsDone = true;
    } catch (e) {
      if (gen !== this.loadGen) return;
      this.accounts = [];
      this.accountsDone = false;
      this.error = friendlyAdminError(e);
    } finally {
      if (gen === this.loadGen) this.accountsLoading = false;
    }
  }

  // After a grant mutation, re-fetch from the top so paid_until + active_grant
  // reflect the server (the response alone can't recompute paid_until under
  // overlapping grants). v1 resets to the first page; preserving scroll position
  // is a later polish.
  private async reloadAccounts(): Promise<void> {
    // ⚠ Rows stay on screen through the re-drain (Gus P1): clearing them first
    // blanked the table for the whole fetch and threw away scroll position after
    // every grant. `accountsDone` false is what matters — it disables the sort
    // headers and shows the loading note, so nothing stale is presented as
    // ranked. The rows are replaced on success and cleared only on failure.
    this.accountsDone = false;
    await this.loadAllAccounts();
  }

  // --- dialog openers -------------------------------------------------------

  openEditConfig(entry: AdminConfigEntry): void {
    this.dialog = { kind: 'editConfig', entry };
    this.error = '';
  }
  openGrant(account: AdminAccount): void {
    this.dialog = { kind: 'grant', account };
    this.error = '';
  }
  openExtend(account: AdminAccount): void {
    this.dialog = { kind: 'extend', account };
    this.error = '';
  }
  openRevoke(account: AdminAccount): void {
    this.dialog = { kind: 'revoke', account };
    this.error = '';
  }
  closeDialog(): void {
    this.dialog = null;
    this.error = '';
  }

  // --- actions --------------------------------------------------------------

  async updateConfig(key: string, value: string): Promise<void> {
    await this.run(async () => {
      const updated = await this.deps.api.updateConfig(key, value);
      this.config = this.config.map((c) => (c.key === key ? updated : c));
    });
  }

  /** Comp an account. `grantedBytesQuota` (bytes) is optional — omitted, the server
   *  applies its default tier quota; supplied, it sets the comp's storage pool. */
  async grant(
    account: AdminAccount,
    durationDays: number,
    note: string,
    grantedBytesQuota?: number,
  ): Promise<void> {
    await this.run(async () => {
      await this.deps.api.createGrant({
        granted_account_id: account.account_id,
        duration_days: durationDays,
        granted_bytes_quota: grantedBytesQuota,
        note: note.trim() || undefined,
      });
      await this.reloadAccounts();
    });
  }

  async extend(account: AdminAccount, durationDays: number): Promise<void> {
    const grant = account.active_grant;
    if (!grant) return;
    await this.run(async () => {
      await this.deps.api.extendGrant(grant.grant_id, durationDays);
      await this.reloadAccounts();
    });
  }

  async revoke(account: AdminAccount): Promise<void> {
    const grant = account.active_grant;
    if (!grant) return;
    await this.run(async () => {
      await this.deps.api.revokeGrant(grant.grant_id);
      await this.reloadAccounts();
    });
  }

  // --- helpers --------------------------------------------------------------

  /** Run a mutation: set busy, run, close the dialog on success, map any failure
   *  to calm copy. Mirrors the account store's `run`. */
  private async run(op: () => Promise<void>): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await op();
      this.dialog = null;
    } catch (e) {
      this.error = friendlyAdminError(e);
    } finally {
      this.busy = false;
    }
  }
}
