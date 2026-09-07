<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { createApiClient, SignetApiError } from '$lib/api';
  import { friendlyCeremonyError } from '$lib/errors';
  import { appendAiSuffix, normalizeHandle, validatePrsnHandle } from '$lib/handle';
  import { sessionStore } from '$lib/session.svelte';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import Button from '$lib/components/Button.svelte';
  import WizardSteps, { wizardStepLabels } from '$lib/components/WizardSteps.svelte';
  import { m } from '$lib/paraglide/messages.js';

  // Step 1 of the add-PRSN wizard (§1-62, design note §3/§5): NAME FIRST, MINT ON
  // CONTINUE. The enrollment row (and its single-use code + TTL) is created only
  // when the guardian submits this form — so the clock starts when the hand-off is
  // imminent, not while the user is still reading (the S141 timed-handoff lesson).
  // On success this navigates to the confirm route, whose Bug028 resume() derives
  // the next step from the server row — the wizard stores no step of its own.
  const api = createApiClient();
  const hasSession = $derived(!!sessionStore.current);

  // bug098: the STRUCTURAL cap gate. Direct nav / bookmark / deep-link to this
  // route must never reach the Step-1 form when the guardian is at their effective
  // PRSN cap (the S148 dead-end: the form only failed on Continue, with no clean
  // exit). Probe /v1/me once on mount; at the cap, render a message + a way back
  // instead of the form. The cap is the EFFECTIVE one (2 for an un-upgraded trial,
  // 8 for a paid guardian — prsn_cap carries the right value), never a hardcoded 8.
  // A failed probe falls through to the form: the server `confirm` gate stays the
  // authoritative check and rejects at the cap regardless.
  let capChecked = $state(false);
  let atCap = $state(false);
  let capLimit = $state(0);
  // bug154 §2c: the STRUCTURAL broker gate, same shape as the cap gate above.
  // Block entry ONLY on the certain case — the guardian has NO broker at all
  // (the common first-run case), where the hand-off packet's `signet` command
  // can only fail. With a broker present we proceed asserting NOTHING about
  // this Mac: `hasBroker` is per-guardian, not per-Mac (S164 §E), and a browser
  // cannot verify a property of a different machine (ROOTS B-3.6) — the Step-2
  // menu-bar sentence stands in for the claim we are not entitled to make.
  // A failed probe falls through to the form: the in-flow broker_setup step
  // (driveSetupStep) remains the authoritative backstop after attest.
  let noBroker = $state(false);
  onMount(async () => {
    try {
      const me = await api.getMe();
      if (me.prsn_cap != null && me.prsn_count != null && me.prsn_count >= me.prsn_cap) {
        atCap = true;
        capLimit = me.prsn_cap;
      }
    } catch {
      // Probe failed (e.g. no valid session) — don't block; the !hasSession branch
      // handles sign-in, and the server confirm gate is authoritative at the cap.
    }
    try {
      const { brokers } = await api.listGarnetBrokers();
      noBroker = brokers.length === 0;
    } catch {
      // Probe failed — assert nothing (gate only the certain case).
    } finally {
      capChecked = true;
    }
  });

  let base = $state('');
  let sharing = $state('read_only');
  let busy = $state(false);
  let error = $state('');
  // Autofill hardening (bug084 rider): autofill memory keys on a STABLE field
  // `name` — a fresh random one per render gives a stored value no key to attach
  // to, and the non-matching `autocomplete` hint covers browsers that ignore
  // "off". Paste stays allowed; only silent stored-value restore is defeated.
  const antiAutofillName = 'f-' + Math.random().toString(36).slice(2, 10);
  /** Set once a code has been minted but its /confirm failed (e.g. the name is
   *  taken): retries then re-confirm the SAME pending row instead of minting
   *  again — a rename is a retry, not a fresh enrollment. */
  let mintedCode = $state<string | null>(null);
  let mintedExp = $state(0);

  const suffixed = $derived(appendAiSuffix(normalizeHandle(base)));

  async function continueToHandoff(): Promise<void> {
    if (validatePrsnHandle(suffixed) != null) {
      error = m.enrollwizard_name_invalid();
      return;
    }
    busy = true;
    error = '';
    try {
      if (mintedCode == null) {
        const res = await api.createEnrollment();
        mintedCode = res.code;
        mintedExp = Math.floor(Date.now() / 1000) + res.expires_in_seconds;
      }
      await api.confirmEnrollment(mintedCode, suffixed, sharing);
      await goto(
        `/account/add-prsn/confirm?code=${encodeURIComponent(mintedCode)}&exp=${mintedExp}`,
      );
    } catch (e) {
      // A stale pending row (TTL hit between mint and retry) → drop the code so
      // the next attempt mints fresh; anything else → show and let them retry.
      if (e instanceof SignetApiError && e.code === 'not_found') mintedCode = null;
      error = friendlyCeremonyError(e);
    } finally {
      busy = false;
    }
  }

  // bug108: Cancel out of setup at Step 1. Usually nothing has been minted yet (just
  // navigate away); if a code WAS minted (a prior Continue whose confirm failed), remove
  // that pre-account record too. No confirm modal here — the very start of setup has
  // nothing permanent to lose; the modal guards the later steps where an account exists.
  let cancelling = $state(false);
  async function cancelSetup(): Promise<void> {
    cancelling = true;
    try {
      if (mintedCode != null) await api.cancelPendingEnrollment(mintedCode);
    } catch {
      // Best-effort: an already-expired code cleans itself up; exit to Settings regardless.
    }
    await goto('/account');
  }
</script>

<!-- bug154 §2a: the subtitle is per-step; this page IS step 1 (Name). -->
<AuthCard title={m.enrollconfirm_title()} subtitle={m.enrollconfirm_subtitle_1()}>
  {#if !hasSession}
    <p>{m.enrollconfirm_signin_prompt()}</p>
    <Button onclick={() => goto('/signin?returnTo=' + encodeURIComponent('/account/add-prsn'))}
      >{m.enrollconfirm_signin_btn()}</Button
    >
  {:else if !capChecked}
    <p class="intro">{m.account_loading()}</p>
  {:else if atCap}
    <!-- bug098: at the cap, this route renders the effective-cap message + a way
         back instead of the Step-1 form — so a direct nav / bookmark can never
         reach the dead-end form (the button fast-path handles the common case). -->
    <p class="intro">{m.addprsn_cap_body({ n: capLimit })}</p>
    <Button onclick={() => goto('/account')}>{m.enrollwizard_back_account()}</Button>
  {:else if noBroker}
    <!-- bug154 §2c: no broker at all ⇒ the wizard cannot end well — route to the
         setup card instead of the dead-end form (same structural-gate shape as
         the cap branch above; the button fast-path lives in GuardianPrsns). -->
    <p class="intro"><strong>{m.addprsn_broker_gate_title()}</strong></p>
    <p class="intro">{m.addprsn_broker_gate_body()}</p>
    <Button onclick={() => goto('/account#garnet')}>{m.addprsn_broker_gate_go()}</Button>
  {:else}
    <!-- The canonical 6-step list (ONE home — WizardSteps exports it), so this page
         and the confirm page can never disagree about the flow's length (bug080's
         4-vs-7 inconsistency). -->
    <WizardSteps steps={wizardStepLabels()} current={0} />
    <!-- bug161 §1: the intro paragraph duplicated the subtitle byte-for-byte on the
         same screen — removed; the subtitle carries the sentence. -->
    <!-- bug154 §1d (Chris's Step-4 ruling relocated here): ONE plain sentence
         saying what a PRSN is, on the first screen a guardian meets the word.
         "PRSN" stays product-wide — the education is the strategy. Vocabulary is
         deliberately hedged (Chris, S167, bug160 §4): the wizard says "AI entity",
         the sidebar tooltip says "AI agents" — two glosses for an unsettled market;
         do not collapse them to one term without a ruling. -->
    <p class="intro">{m.enrollconfirm_prsn_what()}</p>

    <label class="field">
      <span>{m.enrollconfirm_name_label()}</span>
      <span class="suffix-wrap" class:disabled={busy}>
        <input
          bind:value={base}
          onblur={() => {
            // A habit-pasted full handle ("hlin-ai") would render doubled against
            // the fixed adornment; normalize on blur (never on input — that would
            // mutate a name like "my-ai-helper" mid-typing). The submit path is
            // idempotent regardless (appendAiSuffix).
            const b = base.trim();
            if (b.endsWith('-ai')) base = b.slice(0, -3);
          }}
          placeholder="your-prsn"
          name={antiAutofillName}
          autocomplete="one-time-code"
          spellcheck="false"
          disabled={busy}
        />
        <span class="suffix" aria-hidden="true">-ai</span>
      </span>
      <small class="hint">{m.enrollconfirm_name_hint()}</small>
    </label>

    <label class="field">
      <span>{m.enrollconfirm_sharing_label()}</span>
      <select bind:value={sharing} disabled={busy}>
        <option value="none">{m.account_cap_none()}</option>
        <option value="read_only">{m.account_cap_read_only()}</option>
        <option value="read_write">{m.account_cap_read_write()}</option>
      </select>
      <small class="hint">{m.enrollwizard_sharing_hint()}</small>
    </label>

    <p class="custody">{m.enrollconfirm_custody_note()}</p>

    {#if error}<p class="form-error">{error}</p>{/if}
    <div class="wizard-actions">
      <Button loading={busy} onclick={continueToHandoff}>
        {busy ? m.enrollconfirm_confirming() : m.enrollwizard_continue_btn()}
      </Button>
      <button
        type="button"
        class="cancel-setup"
        onclick={cancelSetup}
        disabled={busy || cancelling}
      >
        {m.enrollwizard_cancel_btn()}
      </button>
    </div>
  {/if}
</AuthCard>

<style>
  .intro {
    margin: 0;
    color: var(--ink-soft);
    line-height: 1.5;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.32rem;
  }
  .field > span:first-child {
    font-size: 0.86rem;
    font-weight: 500;
    color: var(--ink-soft);
  }
  .hint {
    color: var(--muted);
    font-size: 0.8rem;
  }
  /* The base-name input with the fixed `-ai` adornment (design note §4): the full
     handle stays visible, only the base is typeable. */
  .suffix-wrap {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    overflow: hidden;
  }
  .suffix-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--ring);
  }
  .suffix-wrap input {
    flex: 1;
    min-width: 0;
    border: 0;
    background: transparent;
    padding: 0.6rem 0.15rem 0.6rem 0.75rem;
    font: inherit;
    color: var(--ink);
  }
  .suffix-wrap input:focus {
    outline: 0;
  }
  .suffix {
    display: flex;
    align-items: center;
    padding: 0 0.75rem 0 0.1rem;
    color: var(--muted);
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.9rem;
    user-select: none;
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
  .custody {
    margin: 0;
    padding: 0.7rem 0.8rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--ink-soft);
    font-size: 0.86rem;
    line-height: 1.5;
  }
  .form-error {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  /* bug108: the primary action (Continue) with a secondary Cancel beneath it. */
  .wizard-actions {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .cancel-setup {
    width: 100%;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.9rem;
    padding: 0.6rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .cancel-setup:hover:not(:disabled) {
    border-color: var(--ink-soft);
  }
  .cancel-setup:disabled {
    opacity: 0.55;
    cursor: default;
  }
</style>
