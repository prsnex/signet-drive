<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { GarnetStore } from '$lib/garnet.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { m } from '$lib/paraglide/messages.js';

  // §1-64 (S166): the old "Signet Drive Account Access Management" card is DELETED —
  // its grant rows live inline in the consolidated PRSN Accounts card
  // (GuardianPrsns). What remains here, deliberately:
  //   1. The Mac/broker SETUP card — it is about the machine, not a PRSN (v02
  //      design ruling), so it stays its own surface. It renders only while no
  //      broker is registered, which is also exactly when the bug154 §2c gate
  //      routes here (the #garnet anchor).
  //   2. Every Garnet DIALOG (authorize / revoke / re-confirm / provision code /
  //      remove broker / connection instructions) — this component is the dialog
  //      host; triggers live wherever the shared store is in scope (the
  //      consolidated card, the page-bottom new-Mac card).
  //   3. The store LIFECYCLE: init + dispose + the hot-poll (Bug033) ride this
  //      mount, exactly as before.
  // bug095: the store is created + owned by the account page, so the relocated
  // "Moving to a new Mac?" card at the page bottom shares THIS exact instance.
  let { store }: { store: GarnetStore } = $props();
  onMount(() => {
    void store.init();
    return () => store.dispose();
  });

  // Authorize-dialog form state (reset each time the dialog opens).
  let selectedAccountId = $state('');
  // bug119: the deployment's own origin, so the modal's help-page links read as
  // absolute URLs a guardian can paste to their PRSN (correct on staging AND prod).
  // Safe unconditionally: the app is ssr=false (+layout.ts), so this only runs in
  // a browser. Deliberately explicit — never lean on the implicit `origin` global.
  const pageOrigin = window.location.origin;
  // Setup-code copy feedback. The code is shown ONCE, so a copy control de-risks an
  // accidental close-before-copy.
  let copied = $state(false);
  let copyTimer: ReturnType<typeof setTimeout> | null = null;
  $effect(() => {
    if (store.dialog?.kind === 'authorize') {
      // §1-64: an inline row Authorize preselects its own PRSN; the generic open
      // falls back to the first candidate (what the dropdown shows).
      selectedAccountId =
        store.dialog.account_id ?? store.neverAuthorizedPrsns[0]?.account_id ?? '';
    }
    if (store.dialog?.kind === 'provision') copied = false;
  });

  // The handle the authorize dialog is currently pointed at (for the bug086
  // allocation statement) — tracks the picker, falling back to the first candidate
  // exactly as submitAuthorize does.
  const selectedHandle = $derived(
    store.neverAuthorizedPrsns.find((p) => p.account_id === selectedAccountId)?.handle ??
      store.neverAuthorizedPrsns[0]?.handle ??
      '',
  );

  function submitAuthorize() {
    // Resolve the chosen PRSN defensively. A `<select>` shows its first <option> by default, but
    // Svelte does not write that default-selected value back into `selectedAccountId` — so on
    // dialog-open it can stay '' even though the dropdown displays a candidate. Fall back to the
    // first authorizable PRSN (exactly what the dropdown shows) so the action never silently no-ops.
    const accountId = selectedAccountId || store.neverAuthorizedPrsns[0]?.account_id;
    if (!accountId) return;
    void store.authorize(accountId);
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      copied = true;
      if (copyTimer) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => (copied = false), 2000);
    } catch {
      // Clipboard unavailable (e.g. an insecure context) — the code stays selectable in the
      // block below, so the guardian can still copy it by hand. No error surfaced.
    }
  }
</script>

{#if !store.loading && !store.hasBroker}
  <!-- One-time, per-Mac setup: a PRSN can only connect once signet is set up on the
       guardian's Mac (it provisions the local broker the PRSN delegates to). Shown
       until a broker registers; the hot-poll clears it by itself (Chris, S145 — no
       "check" button). id="garnet" is the bug154 §2c gate's routing target. -->
  <section class="garnet card" id="garnet">
    <div class="setup-card">
      <p class="setup-lead">{m.garnet_setup_lead()}</p>
      <p class="setup-body">{m.garnet_setup_body()}</p>
      <!-- Bug030(2): the card that tells the guardian to install must also offer the
           installer — the wizard's stable /cli link (302s to the latest notarized zip). -->
      <a class="setup-download" href="/cli/signet-macos.zip" download>
        {m.garnet_setup_download()}
      </a>
      <div class="setup-actions">
        <button class="add" onclick={() => store.mintProvisionCode()} disabled={store.busy}>
          {m.garnet_setup_get_code()}
        </button>
      </div>
      {#if store.error && !store.dialog}<p class="panel-error">{store.error}</p>{/if}
    </div>
  </section>
{/if}

{#if store.dialog?.kind === 'authorize'}
  <Modal title={m.garnet_authorize_title()} onClose={() => store.closeDialog()}>
    <p class="hint">{m.garnet_authorize_intro()}</p>
    {#if store.neverAuthorizedPrsns.length === 0}
      <p class="hint">
        {store.prsns.length === 0
          ? m.garnet_authorize_no_prsns()
          : m.garnet_authorize_no_candidates()}
      </p>
    {:else}
      <label class="field">
        <span>{m.garnet_authorize_prsn_label()}</span>
        <select bind:value={selectedAccountId} disabled={store.busy}>
          {#each store.neverAuthorizedPrsns as prsn (prsn.account_id)}
            <option value={prsn.account_id}>{prsn.handle}</option>
          {/each}
        </select>
      </label>
      <!-- bug086: what is being allocated, and that it is revocable — the inputs to
           the decision, before the confirm control. The revocability sentence is a
           shared key with the wizard (one home, never a second authored copy). -->
      {#if selectedHandle}
        <p class="hint">{m.garnet_authorize_allocation({ handle: selectedHandle })}</p>
      {/if}
      <p class="sub-hint">{m.garnet_authorize_revocable()}</p>
    {/if}
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}>
        {m.account_cancel()}
      </button>
      <button
        class="confirm"
        onclick={submitAuthorize}
        disabled={store.busy || store.neverAuthorizedPrsns.length === 0}
      >
        {store.busy ? m.garnet_authorizing() : m.garnet_authorize_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'revoke'}
  {@const grant = store.dialog.grant}
  <Modal title={m.garnet_revoke_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.garnet_revoke_hint_1()} <strong>{grant.prsn_handle}</strong>
      {m.garnet_revoke_hint_2()}
    </p>
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}>
        {m.account_cancel()}
      </button>
      <button class="danger" onclick={() => store.revoke(grant.grant_id)} disabled={store.busy}>
        {store.busy ? m.garnet_revoking() : m.garnet_revoke_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'removeBroker'}
  {@const broker = store.dialog.broker}
  <Modal title={m.garnet_remove_broker_title()} onClose={() => store.closeDialog()}>
    <p class="hint">{m.garnet_remove_broker_hint()}</p>
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}>
        {m.account_cancel()}
      </button>
      <button
        class="danger"
        onclick={() => store.removeBroker(broker.broker_id)}
        disabled={store.busy}
      >
        {store.busy ? m.garnet_removing() : m.garnet_remove_broker_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'confirm'}
  {@const grant = store.dialog.grant}
  <!-- The bug085 one-tap RE-confirm: no fingerprint entry (bug084 retired the
       match-gate — the agent's signed pickup is the identity proof); one passkey
       gesture re-stamps the cadence anchor. -->
  <Modal
    title={m.garnet_reconfirm_title({ handle: grant.prsn_handle })}
    onClose={() => store.closeDialog()}
  >
    <p class="hint">{m.garnet_reconfirm_body({ handle: grant.prsn_handle })}</p>
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}>
        {m.account_cancel()}
      </button>
      <button class="confirm" onclick={() => store.confirm(grant.grant_id)} disabled={store.busy}>
        {store.busy ? m.garnet_reconfirming() : m.garnet_reconfirm_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'provision'}
  {@const result = store.dialog.result}
  <Modal title={m.garnet_setup_title()} onClose={() => store.closeDialog()}>
    <p class="hint">{m.garnet_setup_intro()}</p>
    <div class="cmd">
      <span class="cmd-label">{m.garnet_setup_code_label()}</span>
      <div class="code-row">
        <code>{result.provision_code}</code>
        <button type="button" class="copy" onclick={() => copyCode(result.provision_code)}>
          {copied ? m.garnet_code_copied() : m.garnet_code_copy()}
        </button>
      </div>
      <span class="visually-hidden" role="status" aria-live="polite"
        >{copied ? m.garnet_code_copied() : ''}</span
      >
    </div>
    <p class="sub-hint">
      {m.garnet_code_expires({
        minutes: Math.max(1, Math.round(result.expires_in_seconds / 60)),
      })}
    </p>
    {#snippet footer()}
      <button class="confirm" onclick={() => store.closeDialog()}>{m.garnet_code_done()}</button>
    {/snippet}
  </Modal>
{/if}

{#if store.instructionsFor !== null}
  <!-- bug119 (supersedes the bug114 Part-E content): four plain lines FOR the normie
       guardian — reassurance first, the app check second, then two linked help pages,
       each written for its own reader (PRSN-facing /help/prsn-connect; human-facing
       /help/prsn-access — both public + prerendered so a PRSN can FETCH its page, and
       both updatable without a client release). The link text is the absolute URL on
       purpose: a guardian pastes it straight into a conversation with their PRSN.
       §1-64: the trigger moved to the consolidated card; the open-state rides the
       shared store. -->
  <Modal title={m.garnet_instructions_title()} onClose={() => (store.instructionsFor = null)}>
    <ol class="instructions-steps">
      <li>{m.garnet_instructions_step1()}</li>
      <li>{m.garnet_instructions_step2()}</li>
      <li>
        {m.garnet_instructions_step3()}
        <a href="/help/prsn-connect" target="_blank" rel="noopener"
          >{pageOrigin}/help/prsn-connect</a
        >
      </li>
      <li>
        {m.garnet_instructions_step4_before()}
        <strong>{m.garnet_instructions_step4_you()}</strong>
        {m.garnet_instructions_step4_after()}
        <a href="/help/prsn-access" target="_blank" rel="noopener">{pageOrigin}/help/prsn-access</a>
      </li>
    </ol>
    {#snippet footer()}
      <button class="confirm" onclick={() => (store.instructionsFor = null)}>
        {m.garnet_code_done()}
      </button>
    {/snippet}
  </Modal>
{/if}

<style>
  .garnet {
    margin-top: 1.6rem;
  }
  .setup-card {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.85rem 0.95rem;
  }
  .setup-lead {
    margin: 0 0 0.35rem;
    font-weight: 600;
    font-size: 0.9rem;
  }
  .setup-body {
    margin: 0 0 0.7rem;
    color: var(--muted);
    font-size: 0.86rem;
  }
  .setup-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .setup-download {
    display: inline-block;
    margin: 0 0 0.7rem;
    font-size: 0.86rem;
    color: var(--accent);
    text-decoration: underline;
  }
  .add {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--accent);
    font: inherit;
    font-size: 0.85rem;
    font-weight: 600;
    padding: 0.4rem 0.8rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .add:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .add:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .panel-error {
    margin: 0.8rem 0 0;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  .hint {
    margin: 0;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.32rem;
  }
  .field span {
    font-size: 0.86rem;
    font-weight: 500;
    color: var(--ink-soft);
  }
  .sub-hint {
    color: var(--muted);
    font-size: 0.8rem;
  }
  select {
    width: 100%;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.6rem 0.75rem;
    font: inherit;
    color: var(--ink);
  }
  select:focus {
    outline: 0;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--ring);
  }
  .cmd {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .cmd-label {
    font-size: 0.8rem;
    color: var(--muted);
  }
  .code-row {
    display: flex;
    align-items: stretch;
    gap: 0.5rem;
  }
  .code-row code {
    flex: 1;
  }
  .cmd code {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.9rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.5rem 0.65rem;
    word-break: break-all;
    color: var(--ink);
  }
  .copy {
    flex: none;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--accent);
    font: inherit;
    font-size: 0.82rem;
    font-weight: 600;
    padding: 0 0.8rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
    white-space: nowrap;
  }
  .copy:hover {
    border-color: var(--accent);
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  .instructions-steps {
    margin: 0.4rem 0 0;
    padding-left: 1.2rem;
    font-size: 0.86rem;
    display: grid;
    gap: 0.45rem;
  }
  .dialog-error {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  .ghost,
  .confirm,
  .danger {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.88rem;
    padding: 0.5rem 0.9rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--on-accent);
    font-weight: 600;
  }
  .danger {
    border-color: var(--danger);
    color: var(--danger);
    font-weight: 600;
  }
  .ghost:disabled,
  .confirm:disabled,
  .danger:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
