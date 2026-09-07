<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { EnrollmentStore } from '$lib/enrollment.svelte';
  import { GarnetStore } from '$lib/garnet.svelte';
  import { driveSetupStep } from '$lib/garnet';
  import { createApiClient } from '$lib/api';
  import { friendlyCeremonyError } from '$lib/errors';
  import { sessionStore } from '$lib/session.svelte';
  import { formatDateTime } from '$lib/format';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import Button from '$lib/components/Button.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import WizardSteps, { wizardStepLabels } from '$lib/components/WizardSteps.svelte';
  import SetupDeadlineWarning from '$lib/components/SetupDeadlineWarning.svelte';
  import { m } from '$lib/paraglide/messages.js';

  // The wizard's post-mint steps (§1-62). Browser-first lands here from the step-1
  // naming page (which minted + confirmed on Continue); the agent's `signet enroll`
  // can also open this URL directly. The `exp` param is display-only (the code's
  // TTL, epoch seconds, carried from the mint response) — the server's own expiry
  // stays authoritative; without it (agent-first) no countdown is shown.
  const code = $derived(page.url.searchParams.get('code') ?? '');
  const exp = $derived(Number(page.url.searchParams.get('exp') ?? '') || 0);
  // §1-62 PR-C: the Drive-access phase keys on the HANDLE (the enrollment code is
  // consumed at attest). `?handle=` is the resume identity for that phase; the
  // `enrolled` flag is display-only (the "✓ set up" banner right after attest).
  const handleParam = $derived(page.url.searchParams.get('handle') ?? '');
  const justEnrolled = $derived(page.url.searchParams.get('enrolled') === '1');
  const hasSession = $derived(!!sessionStore.current);

  // Autofill hardening (bug084 rider): the browser's autofill memory keys on a
  // STABLE field `name`, so the name input gets a fresh random one per render —
  // there is never a stable key for a stored value to attach to. The `autocomplete`
  // hint is deliberately non-matching ("off" alone is advisory and inconsistently
  // honored). Paste stays allowed; only silent stored-value restore is defeated.
  const antiAutofillName = 'f-' + Math.random().toString(36).slice(2, 10);

  // One store per code. (A fresh code → a fresh flow; the page isn't reused across
  // enrollments.) resume() derives the starting phase from the server row (Bug028) —
  // a reopened tab / sign-in bounce lands on the step the enrollment is actually at,
  // instead of restarting at naming with a dead Confirm.
  let store = $state<EnrollmentStore | null>(null);
  $effect(() => {
    if (!code) {
      store = null;
      return;
    }
    const next = new EnrollmentStore(code);
    store = next;
    void next.resume();
    return () => next.dispose();
  });

  // Attest done → hand the URL over to the handle identity (replaceState — the code
  // is consumed; a reload must resume into the Drive-access phase, not the
  // enrollment machine). The Drive-access phase then derives its step from the
  // server's Garnet state — the wizard stores no step of its own.
  $effect(() => {
    if (code && store?.phase === 'done' && store.handle) {
      void goto(`/account/add-prsn/confirm?handle=${encodeURIComponent(store.handle)}&enrolled=1`, {
        replaceState: true,
        noScroll: true,
        keepFocus: true,
      });
    }
  });

  // The Drive-access phase: live whenever the page is keyed by handle. Its step is
  // DERIVED from the guardian's Garnet state (driveSetupStep — unit-tested): after
  // the ONE authorize gesture there is nothing left for the guardian to do — the
  // agent claims the grant by signing its pickup on its next Signet Drive use, which
  // auto-confirms it (bug084; no pairing code, no match-gate).
  const driveMode = $derived(!code && !!handleParam);
  let gs = $state<GarnetStore | null>(null);
  $effect(() => {
    if (!driveMode || !hasSession) {
      gs = null;
      return;
    }
    const next = new GarnetStore();
    gs = next;
    void next.init();
    return () => next.dispose();
  });
  const driveStep = $derived(
    gs && !gs.loading ? driveSetupStep(handleParam, gs.hasBroker, gs.grants, gs.prsns) : null,
  );
  const drivePrsnAccountId = $derived(
    gs?.prsns.find((p) => p.handle === handleParam)?.account_id ?? null,
  );
  // The broker-setup provisioning code minted THIS session (single-use, shown once) —
  // the store surfaces it via its dialog state; the wizard renders it inline.
  const provision = $derived(gs?.dialog?.kind === 'provision' ? gs.dialog.result : null);

  function doAuthorize(): void {
    if (!gs || !drivePrsnAccountId) return;
    void gs.authorize(drivePrsnAccountId);
  }

  // bug108: Cancel out of setup at any step BEFORE the agent connects (Step 6). The
  // affordance shows on every in-progress step; confirming removes whatever exists — the
  // pre-account enrollment record (by code) OR the attested-but-not-yet-connected account —
  // then returns to Settings. It is hidden once the agent has connected (driveStep
  // 'authorized' = Step 6 / live) and in the pure loading/error states.
  const api = createApiClient();
  const cancelable = $derived.by(() => {
    if (!hasSession) return false;
    if (!code && !handleParam) return false;
    if (driveMode) {
      return driveStep != null && driveStep.kind !== 'not_found' && driveStep.kind !== 'authorized';
    }
    return (
      store != null &&
      (store.phase === 'confirm' || store.phase === 'waiting' || store.phase === 'approve')
    );
  });
  // The handle to name in the confirm modal — the drive phase knows it as the URL handle,
  // the enrollment phase from the store (empty until the guardian has named it).
  const cancelHandle = $derived(driveMode ? handleParam : (store?.handle ?? ''));

  let showCancelConfirm = $state(false);
  let cancelling = $state(false);
  let cancelError = $state('');

  async function confirmCancel(): Promise<void> {
    cancelling = true;
    cancelError = '';
    try {
      if (driveMode && gs && drivePrsnAccountId) {
        // Post-attest: wipe the account (never-authorized or authorized-but-not-connected).
        const ok = await gs.discardInProgress(drivePrsnAccountId);
        if (!ok) {
          cancelError = gs.error || m.enrollwizard_cancel_error();
          cancelling = false;
          return;
        }
      } else if (code) {
        // Pre-attest: remove the pending-enrollment record (a no-op if already gone).
        await api.cancelPendingEnrollment(code);
      }
      await goto('/account');
    } catch (e) {
      cancelError = friendlyCeremonyError(e);
      cancelling = false;
    }
  }

  // The visible TTL countdown (design note §5): ticks only while the hand-off step
  // is live and an `exp` was carried. Display-only; expiry truth is the server's.
  let nowSec = $state(Math.floor(Date.now() / 1000));
  $effect(() => {
    if (!exp || store?.phase !== 'waiting') return;
    const t = setInterval(() => (nowSec = Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  });
  const remaining = $derived(exp > 0 ? Math.max(0, exp - nowSec) : -1);
  const countdown = $derived(
    remaining >= 0
      ? `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')}`
      : '',
  );

  // The canonical 6-step list (ONE home — WizardSteps exports it; bug080/bug084):
  // Name · Hand off · Approve · Authorize · Connect · Done.
  const STEP_LABELS = $derived(wizardStepLabels());
  // bug154 §2a: the subtitle is PER-STEP (the old static line described three
  // things while the wizard has six steps, setting a wrong expectation from
  // screen one). Indexed by the same stepIndex the step rail renders from, so the
  // two can never disagree about which step this is.
  const SUBTITLES = [
    m.enrollconfirm_subtitle_1,
    m.enrollconfirm_subtitle_2,
    m.enrollconfirm_subtitle_3,
    m.enrollconfirm_subtitle_4,
    m.enrollconfirm_subtitle_5,
    m.enrollconfirm_subtitle_6,
  ];
  const stepIndex = $derived.by(() => {
    if (driveMode) {
      switch (driveStep?.kind) {
        case 'pickup_wait':
          return 4;
        case 'authorized':
          return 5;
        default:
          return 3; // broker_setup / authorize / loading
      }
    }
    switch (store?.phase) {
      case 'waiting':
        return 1;
      case 'approve':
        return 2;
      case 'done':
        return 3;
      default:
        return 0;
    }
  });

  // §1-62 PR-D (design note §6.1–6.2): the hand-off is an agent-addressed
  // instruction PACKET, not a bare command — what to run, what will happen, what
  // success looks like, what to do on failure, and the always-safe recovery move —
  // forked by runtime (native / Docker / Apple container), since containerized
  // PRSNs need harness wiring the packet must name. Deliberately token-light: it
  // lands in someone's context window.
  let runtime = $state<'native' | 'docker' | 'apple'>('native');
  const packetText = $derived(
    store
      ? [
          m.enrollwizard_packet_core({ cmd: store.enrollCommand }),
          runtime === 'docker'
            ? m.enrollwizard_packet_docker()
            : runtime === 'apple'
              ? m.enrollwizard_packet_apple()
              : '',
        ]
          .filter(Boolean)
          .join('\n\n')
      : '',
  );

  let copied = $state(false);
  async function copyText(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      // Clipboard denied — the value is on screen to copy by hand.
    }
  }
</script>

<AuthCard title={m.enrollconfirm_title()} subtitle={SUBTITLES[stepIndex]()}>
  {#if !code && !handleParam}
    <p class="form-error">{m.enrollconfirm_no_code()}</p>
  {:else if !hasSession}
    <p>{m.enrollconfirm_signin_prompt()}</p>
    <Button
      onclick={() =>
        goto('/signin?returnTo=' + encodeURIComponent(page.url.pathname + page.url.search))}
      >{m.enrollconfirm_signin_btn()}</Button
    >
  {:else if driveMode}
    <!-- The Drive-access phase (§1-62 PR-C, narrowed by bug084), keyed by handle;
         the step is DERIVED from the guardian's Garnet state (driveSetupStep —
         unit-tested), so a reload / lost tab resumes exactly where the server says
         this PRSN is. -->
    <WizardSteps steps={STEP_LABELS} current={stepIndex} />
    {#if !gs || gs.loading}
      <div class="status"><span class="spinner" aria-hidden="true"></span></div>
    {:else if driveStep?.kind === 'not_found'}
      <p class="form-error">{m.enrollwizard_prsn_not_found({ handle: handleParam })}</p>
      <Button onclick={() => goto('/account')}>{m.enrollconfirm_done_btn()}</Button>
    {:else if driveStep?.kind === 'broker_setup'}
      {#if justEnrolled}<p class="done">
          {m.enrollconfirm_done_title({ handle: handleParam })}
        </p>{/if}
      <p class="intro">{m.garnet_setup_body()}</p>
      <a class="helper-link" href="/cli/signet-macos.zip" download>{m.garnet_setup_download()}</a>
      {#if provision}
        <div class="cmd">
          <span class="cmd-label">{m.garnet_setup_intro()}</span>
          <code>{provision.provision_code}</code>
          <div class="cmd-row">
            <button class="copy" onclick={() => copyText(provision.provision_code)}>
              {copied ? m.enrollwizard_copied() : m.garnet_code_copy()}
            </button>
            <span class="countdown"
              >{m.garnet_code_expires({
                minutes: Math.max(1, Math.round(provision.expires_in_seconds / 60)),
              })}</span
            >
          </div>
        </div>
      {/if}
      {#if !provision}
        <Button loading={gs.busy} onclick={() => gs?.mintProvisionCode()}>
          {m.garnet_setup_get_code()}
        </Button>
      {/if}
      <!-- No "check" button (Chris, S145): the broker-less state is a hot-poll
           condition (garnet.svelte.ts #schedulePoll), so this card advances by
           itself the moment the connection registers. -->
      {#if gs.error}<p class="form-error">{gs.error}</p>{/if}
      <!-- The one sub-state that genuinely needs an exit (Chris, S145): the guardian
           may have to install the app and come back — the wizard resumes from server
           state via the account page's continue-setup link. -->
      <a class="helper-link" href="/account">{m.enrollwizard_back_account()}</a>
    {:else if driveStep?.kind === 'authorize'}
      {#if justEnrolled}<p class="done">
          {m.enrollconfirm_done_title({ handle: handleParam })}
        </p>{/if}
      <!-- bug154 §4a: the old intro line is DELETED (Chris) — pure repetition once
           the per-step subtitle carries the instruction. -->
      <!-- bug086: the two facts that most affect the authorization decision, placed
           BEFORE the confirm control — what is being allocated, and that it is
           revocable (the revocability sentence is a shared key with the account-page
           dialog, never a second authored copy). -->
      <p class="allocation">{m.garnet_authorize_allocation({ handle: handleParam })}</p>
      <p class="muted">{m.garnet_authorize_revocable()}</p>
      <!-- bug154 §4b: this screen's verb is Authorize — the note previously said
           "Approving", which is Step 3's verb — plus the §3d "Sign In" priming. -->
      <p class="muted">{m.enrollwizard_gesture_note_authorize()}</p>
      {#if gs.error}<p class="form-error">{gs.error}</p>{/if}
      <!-- No exit link here (Chris, S145): authorize is ONE tap — offering "later"
           at a one-tap step only manufactures abandoned states. Closing the tab
           still resumes safely (the step derives from server state). -->
      <Button loading={gs.busy} onclick={doAuthorize}>{m.garnet_authorize_confirm()}</Button>
    {:else if driveStep?.kind === 'pickup_wait'}
      {#if driveStep.grant.contested}
        <!-- The §5 collision alarm (re-pointed by bug084 to the F2 CSR binding):
             recovery is revoke-and-re-authorize, never waiting it out. -->
        <p class="form-error">{m.garnet_contested_note()}</p>
        <Button onclick={() => goto('/account')}>{m.enrollconfirm_done_btn()}</Button>
      {:else}
        <div class="status"><span class="spinner" aria-hidden="true"></span></div>
        <p>{m.enrollwizard_pickup_waiting({ handle: handleParam })}</p>
        <!-- bug154 §5 (verbatim approved copy): the six-line paragraph becomes
             three bullets — the guardian's action, how connection happens AND its
             fallback, permission to leave. §5b: the old "connects on first use"
             promise was FALSE for a host-native PRSN (auto_pickup has one call
             site, inside the broker branch — bug151 §2b); naming the fallback
             makes the bullet true in every case regardless of how the mechanism
             question is ruled. ⛔ §5b: "This page updates by itself" is DELETED,
             not softened — watched failing under instruments at S165. -->
        <ul class="pickup-steps">
          <li>{m.enrollwizard_pickup_bullet_tell()}</li>
          <!-- `signet connect` is the public verb (Chris, S168 — no internal jargon on
               public surfaces); it aliases `garnet pickup` in the same release. -->
          <li>{m.enrollwizard_pickup_bullet_connect({ cmd: 'signet connect' })}</li>
          <li>{m.enrollwizard_pickup_bullet_leave()}</li>
        </ul>
        {#if gs.error}<p class="form-error">{gs.error}</p>{/if}
        <!-- NOT the skip link: authorization already happened — "you can authorize
             later" would describe a state this step is past (caught on the render). -->
        <a class="helper-link" href="/account">{m.enrollwizard_wait_leave()}</a>
      {/if}
    {:else if driveStep?.kind === 'authorized'}
      <p class="done">{m.enrollwizard_authorized_done({ handle: handleParam })}</p>
      {#if driveStep.grant.reconfirm_deadline_at != null}
        <p class="muted">
          <!-- bug154 §6a: the consequence stated TRUE — missing the deadline opens a
               read-only grace (auth.rs: reads and downloads still work), not a
               cut-off; the guardian's screen and the agent's error now describe one
               reality. Chris's first draft ("to extend access") was checked at
               source and overstated it. -->
          {m.enrollwizard_reconfirm_by({
            handle: handleParam,
            date: formatDateTime(driveStep.grant.reconfirm_deadline_at),
          })}
          <!-- bug161 §step-6: bound the read-only claim — after the grace window the
               grant goes Dead and access stops entirely (grant.rs). The figure is the
               `garnet_reconfirm_grace_days` runtime knob, interpolated (never a literal
               "7" — ROOTS §B-3.5); omitted only when an older server sent no figure. -->
          {#if gs != null && gs.graceDays != null}
            {m.enrollwizard_reconfirm_grace({ days: gs.graceDays })}
          {/if}
          {m.enrollwizard_reconfirm_reminder()}
        </p>
      {/if}
      <Button onclick={() => goto('/account')}>{m.enrollconfirm_done_btn()}</Button>
    {/if}
  {:else if store}
    {@const s = store}
    {#if s.phase === 'resolving'}
      <!-- Bug028: one status poll decides where this enrollment actually is. -->
      <div class="status"><span class="spinner" aria-hidden="true"></span></div>
    {:else}
      <WizardSteps steps={STEP_LABELS} current={stepIndex} />
    {/if}
    {#if s.phase === 'confirm'}
      <!-- Reached with a code only when the row is still pending — e.g. the step-1
           mint's /confirm failed (name taken) or an agent-first open before naming.
           Same form as step 1, submitting confirm-only against the existing row.
           (bug161 §1: the intro paragraph duplicated the phase subtitle — removed.) -->

      <label class="field">
        <span>{m.enrollconfirm_name_label()}</span>
        <span class="suffix-wrap">
          <input
            bind:value={s.handle}
            onblur={() => {
              // Same blur-normalization as step 1: a habit-pasted "hlin-ai" would
              // render doubled against the fixed adornment. Submit is idempotent.
              const b = s.handle.trim();
              if (b.endsWith('-ai')) s.handle = b.slice(0, -3);
            }}
            placeholder="your-prsn"
            name={antiAutofillName}
            autocomplete="one-time-code"
            spellcheck="false"
            disabled={s.busy}
          />
          <span class="suffix" aria-hidden="true">-ai</span>
        </span>
        <small class="hint">{m.enrollconfirm_name_hint()}</small>
      </label>

      <label class="field">
        <span>{m.enrollconfirm_sharing_label()}</span>
        <select bind:value={s.sharing} disabled={s.busy}>
          <option value="none">{m.account_cap_none()}</option>
          <option value="read_only">{m.account_cap_read_only()}</option>
          <option value="read_write">{m.account_cap_read_write()}</option>
        </select>
        <small class="hint">{m.enrollwizard_sharing_hint()}</small>
      </label>

      <p class="custody">{m.enrollconfirm_custody_note()}</p>

      {#if s.error}<p class="form-error">{s.error}</p>{/if}
      <Button loading={s.busy} onclick={() => s.confirm()}>
        {s.busy ? m.enrollconfirm_confirming() : m.enrollconfirm_confirm_btn()}
      </Button>
    {:else if s.phase === 'waiting'}
      <!-- The hand-off step: install guidance + the command + the visible TTL
           countdown live HERE, at the moment there is a code to hand over — not on
           the naming step (design note §3/§5). -->
      <div class="status"><span class="spinner" aria-hidden="true"></span></div>
      <p>{m.enrollconfirm_waiting_title()}</p>
      <p class="muted">{m.enrollconfirm_waiting_note()}</p>

      <!-- bug154 §2b (Chris): the install-helper block is DELETED — the wizard's
           §2c entry gate now guarantees a broker exists before this screen, so the
           mid-flow hedge is unnecessary. Its replacement is ONE sentence: the
           menu-bar icon is the only thing that attests installed + on THIS Mac +
           running + current all at once (a browser cannot verify a property of a
           different machine — ROOTS B-3.6), and a human confirms it at a glance.
           The installer download stays reachable on the broker-setup step. -->
      <p class="muted">{m.enrollconfirm_menubar_check()}</p>

      <div class="cmd">
        <label class="field">
          <span>{m.enrollwizard_runtime_label()}</span>
          <select bind:value={runtime}>
            <!-- bug154 §2d: "Natively" is jargon and native is the common case for
                 an unsophisticated guardian — the tooltip carries the default
                 guidance (Chris). -->
            <option value="native" title={m.enrollwizard_runtime_native_tip()}
              >{m.enrollwizard_runtime_native()}</option
            >
            <option value="docker">{m.enrollwizard_runtime_docker()}</option>
            <option value="apple">{m.enrollwizard_runtime_apple()}</option>
          </select>
        </label>
        <span class="cmd-label">{m.enrollwizard_packet_label()}</span>
        <pre class="packet">{packetText}</pre>
        <div class="cmd-row">
          <button class="copy" onclick={() => copyText(packetText)}>
            {copied ? m.enrollwizard_copied() : m.enrollwizard_copy_packet()}
          </button>
          {#if remaining > 0}
            <span class="countdown">{m.enrollwizard_expires_in({ time: countdown })}</span>
          {:else if remaining === 0}
            <span class="countdown expired">{m.enrollwizard_code_expired()}</span>
          {/if}
        </div>
        {#if remaining === 0}
          <a class="helper-link" href="/account/add-prsn">{m.enrollwizard_start_over()}</a>
        {/if}
      </div>
      {#if s.slow}<p class="muted slow-hint">{m.enrollconfirm_waiting_slow()}</p>{/if}
      {#if s.error}<p class="form-error">{s.error}</p>{/if}
    {:else if s.phase === 'approve'}
      <!-- bug154 §3 (verbatim approved copy): the three verified facts justify the
           approval — SE key generation, proof-of-possession, and the server's
           re-validation — where the old copy asked for approval on faith. And
           "creation" was imprecise: what the passkey signs is the ATTESTATION
           binding keys to account (§3b). Revocability is deliberately omitted
           here (§3c): Step 4's "revoke" means the Drive authorization, a
           different revocation — two meanings on adjacent screens teach a wrong
           lesson. s.handle is full (-ai) by this phase: confirm() normalizes. -->
      <p>{m.enrollconfirm_approve_title({ handle: s.handle })}</p>
      <p class="muted">{m.enrollconfirm_approve_note()}</p>
      <!-- bug154 §3d: macOS's own passkey dialog says "Sign In" for every WebAuthn
           assertion — not ours to relabel (the only strings we supply are rp_name
           and the account identifier), so our copy primes the expectation
           immediately before the gesture. -->
      <p class="muted">{m.enrollwizard_gesture_note()}</p>
      {#if s.error}<p class="form-error">{s.error}</p>{/if}
      <Button loading={s.busy} onclick={() => s.approve()}>
        {s.busy ? m.enrollconfirm_approving() : m.enrollconfirm_approve_btn()}
      </Button>
    {:else if s.phase === 'done'}
      <!-- Transient: the replaceState effect immediately re-keys the URL to
           ?handle=…&enrolled=1 and the Drive-access phase takes over. -->
      <div class="status"><span class="spinner" aria-hidden="true"></span></div>
    {/if}
  {/if}

  <!-- bug108: the Cancel-out-of-setup affordance — present on every in-progress step
       (hidden once the agent connects, Step 6). One confirm modal wipes whatever exists. -->
  {#if cancelable}
    <button
      type="button"
      class="cancel-setup"
      onclick={() => (showCancelConfirm = true)}
      disabled={cancelling}
    >
      {m.enrollwizard_cancel_btn()}
    </button>
  {/if}
</AuthCard>

{#if showCancelConfirm}
  <Modal title={m.enrollwizard_cancel_title()} onClose={() => (showCancelConfirm = false)}>
    <p class="cancel-hint">
      {m.enrollwizard_cancel_body({ handle: cancelHandle || m.enrollwizard_cancel_generic() })}
    </p>
    {#if cancelError}<p class="form-error">{cancelError}</p>{/if}
    {#snippet footer()}
      <button class="modal-keep" onclick={() => (showCancelConfirm = false)} disabled={cancelling}>
        {m.enrollwizard_cancel_keep()}
      </button>
      <button class="modal-cancel" onclick={confirmCancel} disabled={cancelling}>
        {cancelling ? m.enrollwizard_cancelling() : m.enrollwizard_cancel_confirm()}
      </button>
    {/snippet}
  </Modal>
{/if}

{#if gs}
  <!-- bug114 Part B: the 5-min setup-deadline warning rides the wizard's own store too,
       so a guardian mid-setup is warned in place ("OK" keeps them in the setup flow). -->
  <SetupDeadlineWarning store={gs} />
{/if}

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
  .field span {
    font-size: 0.86rem;
    font-weight: 500;
    color: var(--ink-soft);
  }
  .hint {
    color: var(--muted);
    font-size: 0.8rem;
  }
  input,
  select {
    width: 100%;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.6rem 0.75rem;
    font: inherit;
    color: var(--ink);
  }
  input:focus,
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
  /* bug086: the allocation statement — the weightiest sentence on the authorize
     step, styled as a quiet callout rather than shouted. */
  .allocation {
    margin: 0;
    padding: 0.7rem 0.8rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--ink);
    font-size: 0.9rem;
    line-height: 1.5;
  }
  /* (.helper / .helper-title / .helper-body removed with the bug154 §2b
     install-helper block; .helper-link is still used by the broker-setup and
     exit links.) */
  .helper-link {
    font-size: 0.86rem;
    font-weight: 500;
    color: var(--accent);
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
  .cmd code {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.85rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.5rem 0.65rem;
    word-break: break-all;
    color: var(--ink);
  }
  .cmd-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }
  .copy {
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.3rem 0.7rem;
    font: inherit;
    font-size: 0.8rem;
    color: var(--ink-soft);
    cursor: pointer;
  }
  .copy:hover {
    border-color: var(--accent);
    color: var(--accent);
  }
  .countdown {
    font-size: 0.8rem;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .countdown.expired {
    color: var(--danger);
  }
  /* The base-name input with the fixed `-ai` adornment (design note §4). */
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
  }
  .suffix-wrap input:focus {
    outline: 0;
    box-shadow: none;
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
  /* The agent-addressed hand-off packet (§6.1) */
  .packet {
    margin: 0;
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.82rem;
    line-height: 1.5;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.6rem 0.75rem;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--ink);
  }
  .muted {
    color: var(--muted);
    margin: 0;
  }
  /* bug154 §5a: the step-5 guidance as short bullets rather than a paragraph. */
  .pickup-steps {
    margin: 0;
    padding-left: 1.2rem;
    color: var(--muted);
    font-size: 0.92rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    text-align: left;
  }
  .slow-hint {
    margin-top: 0.85rem;
    font-size: 0.88rem;
  }
  .done {
    margin: 0;
    font-weight: 600;
    color: var(--ink);
  }
  .status {
    display: flex;
    justify-content: center;
    padding: 0.5rem 0;
  }
  .spinner {
    width: 1.6em;
    height: 1.6em;
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
  .form-error {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  /* bug108: the Cancel-out-of-setup affordance (a quiet secondary, below the step
     content) + its confirm-modal footer buttons. */
  .cancel-setup {
    display: block;
    width: 100%;
    margin-top: 0.75rem;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.9rem;
    padding: 0.55rem 1rem;
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
  .cancel-hint {
    margin: 0;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  .modal-keep,
  .modal-cancel {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.88rem;
    padding: 0.5rem 0.9rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .modal-cancel {
    border-color: var(--danger);
    color: var(--danger);
    font-weight: 600;
  }
  .modal-keep:disabled,
  .modal-cancel:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
