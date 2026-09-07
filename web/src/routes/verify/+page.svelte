<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import Button from '$lib/components/Button.svelte';
  import { authDeps } from '$lib/deps';
  import { registerSignupPasskey, verifySignupEmail } from '$lib/auth';
  import { detectReturningUser } from '$lib/reauth';
  import { persistSession } from '$lib/persist';
  import { sessionStore } from '$lib/session.svelte';
  import { friendlyAuthError } from '$lib/errors';
  import { m } from '$lib/paraglide/messages.js';

  // bug062: the passkey ceremony no longer fires cold on page load. The emailed
  // token is verified first (fast, no dialog), then the user is TOLD what the OS
  // credential dialog is — and triggers it with their own click. An unexplained
  // system credential prompt reads as a scam and users (rightly) cancel it; a
  // security product that teaches distrust of such prompts has to earn the one
  // it needs. Cancelling is then a first-class, recoverable state, not a dead end.
  let status = $state<'verifying' | 'ready' | 'registering' | 'cancelled' | 'error'>('verifying');
  let error = $state('');
  let accountId = $state('');

  /** A cancelled, timed-out, or unavailable-authenticator credential ceremony —
   *  the WebAuthn `NotAllowedError`. Deliberately narrow: every other failure
   *  keeps the generic error path. */
  function isCancellation(err: unknown): boolean {
    return (err as { name?: string } | null)?.name === 'NotAllowedError';
  }

  async function verify() {
    const token = new URLSearchParams(window.location.search).get('token') ?? '';
    if (!token) {
      // bug065: no token → treat this as a RESUME of an abandoned signup. A valid
      // session cookie belonging to an account that never finished (no KEM key
      // yet) picks registration back up right here — the same prep screen + retry,
      // with no second verification email. Anything else falls through: an
      // already-complete signed-in account goes home; no session at all is the
      // genuine missing-token error.
      const me = await detectReturningUser();
      if (me && me.kem_pubkey_fingerprint == null) {
        accountId = me.account_id;
        status = 'ready';
      } else if (me) {
        await goto('/');
      } else {
        status = 'error';
        error = m.verify_missing_token();
      }
      return;
    }
    try {
      accountId = (await verifySignupEmail(authDeps(), token)).accountId;
      status = 'ready';
    } catch (err) {
      status = 'error';
      error = friendlyAuthError(err);
    }
  }

  async function register() {
    status = 'registering';
    try {
      // Registers the passkey, harvests its PRF, and wraps a fresh KEM key — so
      // the device prompts to confirm, possibly more than once (create + the PRF
      // assertion), which is why the prep copy says so.
      const session = await registerSignupPasskey(authDeps(), accountId);
      sessionStore.set(session);
      void persistSession(session); // fresh gesture → persist (S116; fire-and-forget)
      await goto('/');
    } catch (err) {
      // Retry-safe by construction: registerSignupPasskey needs only the
      // accountId, so "Try again" re-runs the ceremony without re-consuming the
      // single-use verification token.
      if (isCancellation(err)) {
        status = 'cancelled';
      } else {
        status = 'error';
        error = friendlyAuthError(err);
      }
    }
  }

  onMount(() => {
    verify();
  });
</script>

{#if status === 'verifying'}
  <AuthCard title={m.verify_title()} subtitle={m.verify_subtitle()}>
    <div class="center"><span class="spinner-lg" aria-hidden="true"></span></div>
  </AuthCard>
{:else if status === 'ready'}
  <AuthCard title={m.verify_prep_title()}>
    <div class="prep">
      <p class="lead">{m.verify_prep_lead()}</p>
      <p class="stakes">
        {m.verify_prep_stakes()} <strong>{m.verify_prep_stakes_emphasis()}</strong>.
      </p>
      <p class="note">{m.verify_prep_deadline()}</p>
    </div>
    <Button onclick={register}>{m.verify_prep_continue()}</Button>
  </AuthCard>
{:else if status === 'registering'}
  <AuthCard title={m.verify_prep_title()} subtitle={m.verify_registering_subtitle()}>
    <div class="center"><span class="spinner-lg" aria-hidden="true"></span></div>
  </AuthCard>
{:else if status === 'cancelled'}
  <AuthCard title={m.verify_cancelled_title()} subtitle={m.verify_cancelled_body()}>
    <div class="prep">
      <p class="note">{m.verify_cancelled_recovery()}</p>
    </div>
    <Button onclick={register}>{m.verify_try_again()}</Button>
    <p class="alt"><a href="/signup">{m.verify_back_to_signup()}</a></p>
  </AuthCard>
{:else}
  <AuthCard title={m.verify_error_title()} subtitle={error}>
    <Button onclick={() => goto('/signup')}>{m.verify_back_to_signup()}</Button>
  </AuthCard>
{/if}

<style>
  .center {
    display: flex;
    justify-content: center;
    padding: 0.5rem 0 0.25rem;
  }
  /* The prep text is the fix, so it reads as a callout rather than fine print. */
  .prep {
    background: var(--accent-soft);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.85rem 0.95rem;
    margin: 0 0 1rem;
  }
  .prep p {
    margin: 0;
  }
  .prep .lead {
    font-weight: 500;
  }
  /* The stakes paragraph is substantive, not fine print: body weight and size,
     spaced off the lead. Only the deadline below it is de-emphasised (.note) —
     trust first, logistics last. */
  .prep .stakes {
    margin-top: 0.6rem;
  }
  .prep .note {
    margin-top: 0.6rem;
    font-size: 0.9em;
    color: var(--muted);
  }
  .alt {
    margin: 0.85rem 0 0;
    text-align: center;
    font-size: 0.9em;
  }
  .spinner-lg {
    display: inline-block;
    width: 1.7rem;
    height: 1.7rem;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
