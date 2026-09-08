<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import Button from '$lib/components/Button.svelte';
  import { authDeps } from '$lib/deps';
  import {
    registerSignupCredential,
    signIn,
    unlockSignupKeys,
    verifySignupEmail,
    type Session,
    type SignupCredential,
  } from '$lib/auth';
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
  //
  // bug244: signup makes TWO prompts — create the passkey, then assert it once to
  // harvest the PRF that unlocks the drive. Back to back, the second read as a
  // repeat of the first and the first real user dismissed it; every recovery door
  // then refused an account with a passkey and no keys. So the two prompts are now
  // two screens: 'registered' is an interstitial the user leaves by their own click,
  // and cancelling the second prompt ('unlock_cancelled') retries ONLY the unlock —
  // never registration, which the server refuses once a passkey is stored.
  type Status =
    | 'verifying'
    | 'ready'
    | 'registering'
    | 'registered'
    | 'unlocking'
    | 'cancelled'
    | 'unlock_cancelled'
    | 'finish_by_signin'
    | 'signing_in'
    | 'error';
  let status = $state<Status>('verifying');
  let error = $state('');
  let note = $state('');
  let accountId = $state('');
  let email = $state('');
  let credential = $state<SignupCredential | null>(null);

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
      // yet) picks up right here with no second verification email. Anything else
      // falls through: an already-complete signed-in account goes home; no session
      // at all is the genuine missing-token error.
      // bug244: WHICH unfinished state decides where it resumes. No passkey yet →
      // the registration prep screen. A passkey and no keys → sign-in, whose
      // safety net initialises the keys; re-registering would be refused.
      const me = await detectReturningUser();
      if (me && me.kem_pubkey_fingerprint == null) {
        accountId = me.account_id;
        email = me.email ?? '';
        // A passkey exists → never re-register (the server refuses a second
        // active one); finish at sign-in, whatever else the row holds.
        status = me.has_passkey ? 'finish_by_signin' : 'ready';
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

  async function land(session: Session) {
    sessionStore.set(session);
    void persistSession(session); // fresh gesture → persist (S116; fire-and-forget)
    await goto('/');
  }

  /** Step one: create the passkey (one prompt). Lands on the interstitial. */
  async function register() {
    status = 'registering';
    try {
      credential = await registerSignupCredential(authDeps(), accountId);
      status = 'registered';
    } catch (err) {
      // Retry-safe by construction: registerSignupCredential needs only the
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

  /** Step two: assert the passkey once to unlock the drive (one prompt), then
   *  initialise the key material. Retries alone — no registration request. */
  async function unlock() {
    if (!credential) return;
    status = 'unlocking';
    try {
      await land(await unlockSignupKeys(authDeps(), accountId, credential));
    } catch (err) {
      if (isCancellation(err)) {
        status = 'unlock_cancelled';
      } else {
        status = 'error';
        error = friendlyAuthError(err);
      }
    }
  }

  /** The resume path for a passkey-and-no-keys account: sign in; the sign-in
   *  flow finishes the setup (bug244's safety net). */
  async function finishBySignIn() {
    if (!email) {
      status = 'error';
      error = m.verify_missing_token();
      return;
    }
    status = 'signing_in';
    note = '';
    try {
      await land(await signIn(authDeps(), email));
    } catch (err) {
      if (isCancellation(err)) {
        status = 'finish_by_signin';
        note = m.verify_finish_signin_cancelled();
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
{:else if status === 'registered'}
  <AuthCard title={m.verify_registered_title()}>
    <div class="prep">
      <p class="lead">{m.verify_registered_lead()}</p>
      <p class="stakes">{m.verify_registered_note()}</p>
    </div>
    <Button onclick={unlock}>{m.verify_registered_continue()}</Button>
  </AuthCard>
{:else if status === 'unlocking'}
  <AuthCard title={m.verify_registered_title()} subtitle={m.verify_unlocking_subtitle()}>
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
{:else if status === 'unlock_cancelled'}
  <AuthCard title={m.verify_unlock_cancelled_title()} subtitle={m.verify_unlock_cancelled_body()}>
    <div class="prep">
      <p class="note">{m.verify_unlock_cancelled_recovery()}</p>
    </div>
    <Button onclick={unlock}>{m.verify_try_again()}</Button>
  </AuthCard>
{:else if status === 'finish_by_signin' || status === 'signing_in'}
  <AuthCard title={m.verify_finish_signin_title()} subtitle={m.verify_finish_signin_body()}>
    {#if note}
      <div class="prep">
        <p class="note">{note}</p>
      </div>
    {/if}
    {#if status === 'signing_in'}
      <div class="center"><span class="spinner-lg" aria-hidden="true"></span></div>
    {:else}
      <Button onclick={finishBySignIn}>{m.verify_finish_signin_continue()}</Button>
    {/if}
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
