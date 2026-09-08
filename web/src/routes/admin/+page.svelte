<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import Wordmark from '$lib/components/Wordmark.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { AdminStore } from '$lib/admin.svelte';
  import { createApiClient } from '$lib/api';
  import { purgePersisted, restoreSession } from '$lib/persist';
  import { sessionStore } from '$lib/session.svelte';
  import { formatDate, formatDateTime } from '$lib/format';
  import type { AdminAccount } from '$lib/api';
  import { m } from '$lib/paraglide/messages.js';

  let leaving = $state(false);

  // --- signup gate pane (S206) ---------------------------------------------
  let roundName = $state('');
  let roundSize = $state('');
  let inviteEmail = $state('');
  let inviteHandle = $state('');
  let inviteSentTo = $state('');

  async function submitInvite(event: SubmitEvent) {
    event.preventDefault();
    const email = inviteEmail.trim();
    const ok = await store.inviteSignup(email, inviteHandle.trim());
    // ⭐ Clear ONLY on success. Wiping the fields on failure would lose what the
    // admin typed and leave them guessing whether it went out.
    if (ok) {
      inviteSentTo = email;
      inviteEmail = '';
      inviteHandle = '';
    }
  }

  async function submitRound(event: SubmitEvent) {
    event.preventDefault();
    const size = Number.parseInt(roundSize, 10);
    if (!Number.isFinite(size) || size < 1) return;
    await store.openCohort(roundName.trim(), size);
    if (!store.error) {
      roundName = '';
      roundSize = '';
    }
  }

  const store = untrack(() => new AdminStore());

  // --- accounts table sorting ------------------------------------------------
  //
  // Client-side, over the COMPLETE list the store drains — see `loadAllAccounts`.
  // ⚠ The headers are disabled while `accountsDone` is false, so this can never
  // rank a partial list. Three-state toggle (asc → desc → unsorted) and the
  // arrow/`.sort` markup follow FileList.svelte, the house precedent.
  type SortCol = 'name' | 'email' | 'type' | 'status' | 'paid' | 'setup' | 'comp';

  const sortCols: { key: SortCol; label: () => string }[] = [
    { key: 'name', label: () => m.admin_col_account() },
    { key: 'email', label: () => m.admin_col_email() },
    { key: 'type', label: () => m.admin_col_type() },
    { key: 'status', label: () => m.admin_col_status() },
    { key: 'paid', label: () => m.admin_col_paid_until() },
    { key: 'setup', label: () => m.admin_col_setup() },
    { key: 'comp', label: () => m.admin_col_comp() },
  ];

  let sort = $state<{ col: SortCol; dir: 'asc' | 'desc' } | null>(null);

  function toggleSort(col: SortCol) {
    if (!sort || sort.col !== col) sort = { col, dir: 'asc' };
    else if (sort.dir === 'asc') sort = { col, dir: 'desc' };
    else sort = null;
  }

  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  function acctCmp(a: AdminAccount, b: AdminAccount): number {
    if (!sort) return 0;
    const dir = sort.dir === 'asc' ? 1 : -1;
    let c: number;
    switch (sort.col) {
      // A null handle/email renders as '—'; sorting the empty string keeps those
      // rows together at one end rather than scattering them.
      case 'name':
        c = collator.compare(a.handle ?? '', b.handle ?? '');
        break;
      case 'email':
        c = collator.compare(a.email ?? '', b.email ?? '');
        break;
      case 'type':
        c = collator.compare(a.account_type, b.account_type);
        break;
      case 'status':
        c = collator.compare(a.status, b.status);
        break;
      case 'paid':
        c = a.paid_until - b.paid_until;
        break;
      // bug244: unfinished first under asc, so the rows an operator must act on
      // surface together.
      case 'setup':
        c = Number(a.keys_initialized) - Number(b.keys_initialized);
        break;
      case 'comp':
        c = Number(a.active_grant !== null) - Number(b.active_grant !== null);
        break;
    }
    // Ties keep the server's newest-first order, so a sort on a coarse column
    // (type, status, comp) stays stable instead of shuffling on each toggle.
    return c === 0 ? 0 : c * dir;
  }

  const sortedAccounts = $derived(sort ? [...store.accounts].sort(acctCmp) : store.accounts);
  void store.init();

  // /admin needs a session AND the admin role: no session → sign-in; a non-admin
  // (forbidden, set once /v1/me returns) → the file browser.
  // S116 unlock persistence: try the zero-gesture restore before bouncing a
  // reload to /signin (the no-reload standard); failure → today's redirect.
  let restoring = false;
  $effect(() => {
    if (leaving) return;
    if (!sessionStore.current) {
      if (restoring) return;
      restoring = true;
      void restoreSession()
        .then((restored) => {
          if (restored && !sessionStore.current) sessionStore.set(restored);
          else if (!restored && !leaving && !sessionStore.current) void goto('/signin');
        })
        .finally(() => {
          restoring = false;
        });
    } else if (store.forbidden) {
      void goto('/');
    }
  });

  // Per-dialog form state, reset as each dialog opens.
  let configValue = $state('');
  let grantDays = $state(365);
  let grantNote = $state('');
  let grantGb = $state<number | null>(null);
  let extendDays = $state(365);
  let deleteHandle = $state('');

  $effect(() => {
    const d = store.dialog;
    if (d?.kind === 'delete') deleteHandle = '';
    if (d?.kind === 'editConfig') configValue = d.entry.value;
    if (d?.kind === 'grant') {
      grantDays = 365;
      grantNote = '';
      grantGb = null;
    }
    if (d?.kind === 'extend') extendDays = 365;
  });

  // An empty storage field → omit `granted_bytes_quota` (server uses the default
  // tier quota); a positive value → that many GiB, matching the app's byte display.
  function grantBytes(): number | undefined {
    return grantGb && grantGb > 0 ? Math.round(grantGb * 1024 ** 3) : undefined;
  }
  function grantStorageValid(): boolean {
    return grantGb === null || (Number.isFinite(grantGb) && grantGb > 0);
  }

  // Light client-side validation mirroring the server (which is authoritative):
  // an integer in [min, max]; a boolean true/false; a non-empty string.
  function configValid(): boolean {
    const d = store.dialog;
    if (d?.kind !== 'editConfig') return false;
    const e = d.entry;
    if (e.value_type === 'integer') {
      if (!/^-?\d+$/.test(configValue.trim())) return false;
      const n = Number(configValue.trim());
      if (e.min_value !== null && n < Number(e.min_value)) return false;
      if (e.max_value !== null && n > Number(e.max_value)) return false;
      return true;
    }
    if (e.value_type === 'boolean') return configValue === 'true' || configValue === 'false';
    return configValue.trim().length > 0;
  }

  function durationValid(days: number): boolean {
    return Number.isInteger(days) && days >= 1;
  }

  async function signOut() {
    leaving = true;
    // Purge the persisted unlock BEFORE the logout POST (S116 unlock persistence).
    await purgePersisted();
    // End the server session FIRST (clears the cookie) so the landing's re-unlock
    // probe doesn't offer to re-unlock a just-signed-out account (Bug014).
    try {
      await createApiClient().logout();
    } catch {
      // ignore — fall through to the local clear
    }
    sessionStore.clear();
    void goto('/');
  }
</script>

<div class="page">
  <header class="bar">
    <Wordmark />
    <div class="acct">
      <a class="link" href="/">{m.admin_files_link()}</a>
      <a class="link" href="/account">{m.admin_account()}</a>
      <button class="signout" onclick={signOut}>{m.admin_sign_out()}</button>
    </div>
  </header>

  {#if store.loading}
    <div class="loading"><span class="spinner" aria-hidden="true"></span>{m.admin_loading()}</div>
  {:else if store.me?.admin_role}
    <main>
      <h1>{m.admin_title()}</h1>

      <!-- Account sign-ups: the gate, the current round, invites (S206) -->
      <section class="pane">
        <h2>{m.admin_gate_title()}</h2>
        <p class="pane-note">{m.admin_gate_note()}</p>

        {#if store.gate}
          <div class="gate-modes">
            {#each [['open', m.admin_gate_mode_open()], ['paused', m.admin_gate_mode_paused()], ['limited', m.admin_gate_mode_limited()]] as [value, label] (value)}
              <label class="gate-mode">
                <input
                  type="radio"
                  name="signup-mode"
                  checked={store.gate.mode === value}
                  disabled={store.gateBusy}
                  onchange={() => store.setSignupMode(value as 'open' | 'paused' | 'limited')}
                />
                <span>{label}</span>
              </label>
            {/each}
          </div>

          {#if store.gate.cohort}
            <p class="gate-round">
              <strong>{m.admin_gate_current_round()}:</strong>
              {store.gate.cohort.label} ({store.gate.cohort.cohort_ref}) —
              {m.admin_gate_used({
                used: store.gate.cohort.used,
                max: store.gate.cohort.max_accounts,
                remaining: store.gate.cohort.remaining,
              })}
              <button
                type="button"
                class="linkish"
                disabled={store.gateBusy}
                onclick={() => store.closeCohort(store.gate!.cohort!.cohort_id)}
                >{m.admin_gate_close_round()}</button
              >
            </p>
          {:else}
            <p class="pane-note">{m.admin_gate_no_round()}</p>
            <form class="gate-form" onsubmit={submitRound}>
              <input
                type="text"
                bind:value={roundName}
                placeholder={m.admin_gate_round_name()}
                disabled={store.gateBusy}
              />
              <input
                type="number"
                min="1"
                bind:value={roundSize}
                placeholder={m.admin_gate_round_size()}
                disabled={store.gateBusy}
              />
              <button type="submit" disabled={store.gateBusy || !roundName.trim() || !roundSize}
                >{m.admin_gate_open_round()}</button
              >
            </form>
          {/if}
        {/if}

        <h3>{m.admin_gate_invite_title()}</h3>
        <p class="pane-note">{m.admin_gate_invite_note()}</p>
        <form class="gate-form" onsubmit={submitInvite}>
          <input
            type="email"
            bind:value={inviteEmail}
            placeholder={m.admin_gate_invite_email()}
            disabled={store.gateBusy}
          />
          <input
            type="text"
            bind:value={inviteHandle}
            placeholder={m.admin_gate_invite_handle()}
            disabled={store.gateBusy}
          />
          <button
            type="submit"
            disabled={store.gateBusy || !inviteEmail.trim() || !inviteHandle.trim()}
            >{m.admin_gate_invite_send()}</button
          >
        </form>
        {#if inviteSentTo}
          <p class="pane-note">{m.admin_gate_invite_sent({ email: inviteSentTo })}</p>
        {/if}
      </section>

      <!-- §8.1 System Config -->
      <section class="pane">
        <h2>{m.admin_config_title()}</h2>
        <p class="pane-note">
          {m.admin_config_note()}
        </p>
        <div class="config-list">
          {#each store.config as entry (entry.key)}
            <div class="config-row">
              <div class="config-main">
                <span class="config-key">{entry.key}</span>
                <span class="config-desc">{entry.description}</span>
              </div>
              <span class="config-value">{entry.value}</span>
              <button class="ghost sm" onclick={() => store.openEditConfig(entry)}
                >{m.admin_edit()}</button
              >
            </div>
          {/each}
        </div>
      </section>

      <!-- §8.2 Transparency Log Status -->
      <section class="pane">
        <h2>{m.admin_transparency_title()}</h2>
        {#if store.transparency}
          {@const t = store.transparency}
          <div class="info">
            <div class="row">
              <span class="k">{m.admin_log_size()}</span>
              <span class="v">{m.admin_log_entries({ count: t.log_size.toLocaleString() })}</span>
            </div>
            <div class="row">
              <span class="k">{m.admin_last_computed_root()}</span>
              <span class="v mono small"
                >{t.last_computed
                  ? m.admin_root_size({
                      root: t.last_computed.merkle_root.slice(0, 16),
                      size: t.last_computed.log_size,
                    })
                  : '—'}</span
              >
            </div>
            <div class="row">
              <span class="k">{m.admin_last_committed()}</span>
              <span class="v"
                >{t.last_committed
                  ? formatDateTime(t.last_committed.committed_at ?? t.last_committed.computed_at)
                  : m.admin_committed_pending()}</span
              >
            </div>
            <div class="row">
              <span class="k">{m.admin_roots_24h()}</span>
              <span class="v">{t.recent_roots.length}</span>
            </div>
          </div>
        {/if}
      </section>

      <!-- §8 Account Management -->
      <section class="pane">
        <h2>{m.admin_accounts_title()}</h2>
        <p class="pane-note">
          {m.admin_accounts_note()}
        </p>
        <div class="acct-table">
          <div class="acct-head">
            {#each sortCols as c (c.key)}
              <button
                type="button"
                class="sort"
                class:active={sort?.col === c.key}
                disabled={!store.accountsDone}
                title={store.accountsDone ? m.admin_sort_by({ col: c.label() }) : undefined}
                onclick={() => toggleSort(c.key)}
              >
                {c.label()}<span class="arrow" class:idle={sort?.col !== c.key} aria-hidden="true"
                  >{sort?.col === c.key && sort.dir === 'desc' ? '▾' : '▴'}</span
                >
              </button>
            {/each}<span></span>
          </div>
          {#each sortedAccounts as a (a.account_id)}
            <div class="acct-row">
              <span class="who">
                <span class="handle-line">
                  <span class="handle">{a.handle ?? '—'}</span>
                  {#if a.admin_role}<span class="admin-badge" title={m.admin_badge_title()}
                      >{m.admin_badge()}</span
                    >{/if}
                </span>
              </span>
              <span class="email">{a.email ?? '—'}</span>
              <span>{a.account_type}</span>
              <span>{a.status}</span>
              <span>{formatDate(a.paid_until)}</span>
              <span class:unfinished={!a.keys_initialized}
                >{a.keys_initialized ? '—' : m.admin_setup_unfinished()}</span
              >
              <span>{a.active_grant ? m.admin_comped() : '—'}</span>
              <span class="acct-actions">
                {#if a.active_grant}
                  <button class="ghost sm" onclick={() => store.openExtend(a)}
                    >{m.admin_extend()}</button
                  >
                  <button class="danger-text sm" onclick={() => store.openRevoke(a)}
                    >{m.admin_revoke()}</button
                  >
                {:else}
                  <button class="ghost sm" onclick={() => store.openGrant(a)}
                    >{m.admin_grant_comp()}</button
                  >
                {/if}
                {#if a.account_type === 'human' && a.status === 'active' && !a.admin_role}
                  <button class="danger-text sm" onclick={() => store.openDelete(a)}
                    >{m.admin_delete()}</button
                  >
                {/if}
              </span>
            </div>
          {/each}
        </div>
        {#if store.accountsLoading}
          <p class="pane-note">{m.admin_loading()}</p>
        {:else if !store.accountsDone}
          <!-- The drain failed part-way. Say so: the sort headers are disabled and a
               silent partial list is exactly the state this feature must never present
               as complete. -->
          <p class="pane-note">{m.admin_accounts_partial()}</p>
          <button class="ghost" onclick={() => store.loadAllAccounts()}
            >{m.admin_accounts_retry()}</button
          >
        {/if}
      </section>

      {#if store.error && !store.dialog}<p class="page-error">{store.error}</p>{/if}
    </main>
  {/if}
</div>

<!-- Edit a config value -->
{#if store.dialog?.kind === 'editConfig'}
  {@const e = store.dialog.entry}
  <Modal title={m.admin_editconfig_title({ key: e.key })} onClose={() => store.closeDialog()}>
    <p class="hint">{e.description}</p>
    {#if e.value_type === 'boolean'}
      <select class="field" bind:value={configValue} disabled={store.busy}>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    {:else if e.value_type === 'integer'}
      <input class="field" type="number" bind:value={configValue} disabled={store.busy} />
      {#if e.min_value !== null || e.max_value !== null}
        <p class="bounds">
          {m.admin_allowed_range({ min: e.min_value ?? '−∞', max: e.max_value ?? '∞' })}
        </p>
      {/if}
    {:else}
      <input class="field" type="text" bind:value={configValue} disabled={store.busy} />
    {/if}
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.admin_cancel()}</button
      >
      <button
        class="confirm"
        onclick={() => store.updateConfig(e.key, configValue.trim())}
        disabled={store.busy || !configValid()}
      >
        {m.admin_save()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'grant'}
  {@const a = store.dialog.account}
  <Modal title={m.admin_grant_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.admin_grant_hint_before()} <strong>{a.handle ?? a.account_id}</strong>
      {m.admin_grant_hint_after()}
    </p>
    <label class="lbl" for="grant-days">{m.admin_grant_duration()}</label>
    <input
      id="grant-days"
      class="field"
      type="number"
      min="1"
      bind:value={grantDays}
      disabled={store.busy}
    />
    <label class="lbl" for="grant-gb">{m.admin_grant_storage()}</label>
    <input
      id="grant-gb"
      class="field"
      type="number"
      min="1"
      step="1"
      placeholder={m.admin_grant_storage_placeholder()}
      bind:value={grantGb}
      disabled={store.busy}
    />
    <p class="bounds">{m.admin_grant_storage_note()}</p>
    <label class="lbl" for="grant-note">{m.admin_grant_note_label()}</label>
    <input id="grant-note" class="field" type="text" bind:value={grantNote} disabled={store.busy} />
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.admin_cancel()}</button
      >
      <button
        class="confirm"
        onclick={() => store.grant(a, grantDays, grantNote, grantBytes())}
        disabled={store.busy || !durationValid(grantDays) || !grantStorageValid()}
      >
        {m.admin_grant_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'extend'}
  {@const a = store.dialog.account}
  <Modal title={m.admin_extend_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.admin_extend_hint_before()} <strong>{a.handle ?? a.account_id}</strong>{a.active_grant
        ? m.admin_extend_hint_with({ date: formatDate(a.active_grant.granted_until) })
        : m.admin_extend_hint_without()}
    </p>
    <label class="lbl" for="extend-days">{m.admin_extend_days()}</label>
    <input
      id="extend-days"
      class="field"
      type="number"
      min="1"
      bind:value={extendDays}
      disabled={store.busy}
    />
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.admin_cancel()}</button
      >
      <button
        class="confirm"
        onclick={() => store.extend(a, extendDays)}
        disabled={store.busy || !durationValid(extendDays)}
      >
        {m.admin_extend()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'revoke'}
  {@const a = store.dialog.account}
  <Modal title={m.admin_revoke_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.admin_revoke_hint_1()} <strong>{a.handle ?? a.account_id}</strong>
      {m.admin_revoke_hint_2()}
      <em>{m.admin_revoke_not()}</em>
      {m.admin_revoke_hint_3()}
    </p>
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.admin_cancel()}</button
      >
      <button class="danger" onclick={() => store.revoke(a)} disabled={store.busy}
        >{m.admin_revoke()}</button
      >
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'delete'}
  {@const a = store.dialog.account}
  {@const handle = a.handle ?? ''}
  <Modal title={m.admin_delete_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.admin_delete_hint_1()} <strong>{handle || a.account_id}</strong>
      {m.admin_delete_hint_2()}
    </p>
    <p class="hint">{m.admin_delete_hint_3()}</p>
    <label class="lbl" for="delete-handle">{m.admin_delete_confirm_label()}</label>
    <input
      id="delete-handle"
      class="field"
      type="text"
      autocomplete="off"
      bind:value={deleteHandle}
      disabled={store.busy}
    />
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.admin_cancel()}</button
      >
      <button
        class="danger"
        onclick={() => store.deleteAccount(a, deleteHandle.trim())}
        disabled={store.busy || !handle || deleteHandle.trim() !== handle}
        >{m.admin_delete_confirm()}</button
      >
    {/snippet}
  </Modal>
{/if}

<style>
  .page {
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  .acct {
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  .link {
    color: var(--ink-soft);
    font-size: 0.9rem;
    text-decoration: none;
  }
  .link:hover {
    color: var(--ink);
  }
  .signout {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.85rem;
    padding: 0.36rem 0.8rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .signout:hover {
    border-color: var(--muted);
  }
  main {
    max-width: 820px;
    width: 100%;
    margin: 0 auto;
    padding: 2rem 1.5rem 3rem;
  }
  h1 {
    font-size: 1.5rem;
    font-weight: 600;
    margin: 0 0 1.6rem;
  }
  .pane {
    margin-bottom: 2.4rem;
  }
  .pane h2 {
    font-size: 1.05rem;
    font-weight: 600;
    margin: 0 0 0.5rem;
  }
  .pane-note {
    margin: 0 0 1rem;
    color: var(--ink-soft);
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .config-list {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
  }
  .config-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.6rem 0.9rem;
    border-bottom: 1px solid var(--border);
  }
  .config-row:last-child {
    border-bottom: 0;
  }
  .config-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .config-key {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.85rem;
    color: var(--ink);
  }
  .config-desc {
    font-size: 0.8rem;
    color: var(--muted);
  }
  .config-value {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.85rem;
    color: var(--ink);
    text-align: right;
    word-break: break-all;
    max-width: 220px;
  }
  .info {
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }
  .row {
    display: flex;
    gap: 1rem;
    font-size: 0.95rem;
  }
  .k {
    width: 180px;
    flex: none;
    color: var(--muted);
  }
  .v {
    color: var(--ink);
  }
  .v.mono {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
  }
  .v.small {
    font-size: 0.82rem;
  }
  .acct-table {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin-bottom: 1rem;
    /* User-resizable height: drag the bottom edge to show more or fewer rows,
       scrolling within whatever height you pick. `resize` needs a non-visible
       overflow to take effect, so these belong together.
       ⛔ `height`, NOT `max-height` (Gus, review of 35b83b5e): `resize` RESPECTS
       max-height, so a max would let the pane shrink and never grow — the exact
       inverse of the ask, which is "show more rows". A definite start height is
       what makes dragging work in both directions. */
    height: 30rem;
    min-height: 8rem;
    overflow: auto;
    resize: vertical;
  }
  .acct-head,
  .acct-row {
    display: grid;
    grid-template-columns: 1.6fr 2fr 0.7fr 0.9fr 1fr 0.9fr 0.8fr 1.4fr;
    align-items: center;
    gap: 0.75rem;
    padding: 0.6rem 0.9rem;
    font-size: 0.88rem;
  }
  .acct-head {
    background: var(--bg);
    color: var(--muted);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    border-bottom: 1px solid var(--border);
    /* Stays put while the body scrolls inside the resized pane. */
    position: sticky;
    top: 0;
    z-index: 1;
  }
  .acct-head .sort {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0;
    border: 0;
    background: none;
    font: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    color: inherit;
    cursor: pointer;
    text-align: left;
  }
  .acct-head .sort:disabled {
    cursor: default;
  }
  .acct-head .sort.active {
    color: var(--ink);
  }
  .acct-head .arrow.idle {
    opacity: 0;
  }
  .acct-head .sort:hover:not(:disabled) .arrow.idle {
    opacity: 0.4;
  }
  .email {
    color: var(--muted);
    overflow-wrap: anywhere;
  }
  /* bug244: the one cell an operator must act on reads as a warning, not a dash. */
  .acct-row .unfinished {
    color: var(--danger, #b42318);
    font-weight: 500;
  }
  .acct-row {
    border-bottom: 1px solid var(--border);
  }
  .acct-row:last-child {
    border-bottom: 0;
  }
  .who {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .handle-line {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    min-width: 0;
  }
  .handle {
    color: var(--ink);
  }
  .admin-badge {
    flex: none;
    font-size: 0.62rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--ink);
    background: var(--surface);
    border: 1px solid var(--field-border);
    border-radius: 4px;
    padding: 0.05rem 0.32rem;
  }
  .email {
    font-size: 0.78rem;
    color: var(--muted);
    word-break: break-all;
  }
  .acct-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }
  .ghost {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-weight: 500;
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .ghost.sm {
    padding: 0.32rem 0.7rem;
    font-size: 0.82rem;
  }
  .ghost:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .ghost:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .danger-text {
    border: 0;
    background: none;
    color: var(--danger);
    font: inherit;
    cursor: pointer;
    padding: 0;
  }
  .danger-text.sm {
    font-size: 0.82rem;
  }
  .danger-text:hover {
    text-decoration: underline;
  }
  .loading {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.6rem;
    color: var(--muted);
  }
  .spinner {
    width: 1.1em;
    height: 1.1em;
    border: 2px solid var(--field-border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .page-error {
    margin-top: 1.2rem;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  .hint {
    margin: 0 0 0.4rem;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  .lbl {
    display: block;
    margin: 0.8rem 0 0.3rem;
    font-size: 0.82rem;
    color: var(--muted);
  }
  .field {
    width: 100%;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.6rem 0.75rem;
    font: inherit;
    color: var(--ink);
  }
  .field:focus {
    outline: 0;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--ring);
  }
  .bounds {
    margin: 0.4rem 0 0;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .dialog-error {
    margin: 0.6rem 0 0;
    padding: 0.55rem 0.7rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.86rem;
  }
  .confirm {
    border: 0;
    background: var(--accent);
    color: var(--on-accent);
    font: inherit;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .danger {
    border: 0;
    background: var(--danger);
    color: #fff;
    font: inherit;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm:disabled,
  .danger:disabled {
    opacity: 0.55;
    cursor: default;
  }
  /* --- signup gate pane (S206) --- */
  .gate-modes {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin: 0.75rem 0;
  }
  .gate-mode {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.92rem;
    cursor: pointer;
  }
  .gate-round {
    margin: 0.5rem 0;
    font-size: 0.92rem;
  }
  .gate-form {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0 0.75rem;
  }
  .gate-form input {
    flex: 1 1 12rem;
    min-width: 0;
  }
</style>
