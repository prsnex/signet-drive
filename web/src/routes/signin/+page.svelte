<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { safeReturnPath } from '$lib/nav';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import TextField from '$lib/components/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import ReunlockCard from '$lib/components/ReunlockCard.svelte';
  import { authDeps } from '$lib/deps';
  import { signIn } from '$lib/auth';
  import { persistSession } from '$lib/persist';
  import { detectReturningUser } from '$lib/reauth';
  import type { MeResponse } from '$lib/api';
  import { sessionStore } from '$lib/session.svelte';
  import { friendlyAuthError } from '$lib/errors';
  import { m } from '$lib/paraglide/messages.js';

  let email = $state('');
  let busy = $state(false);
  let error = $state('');

  // Bug014: a refresh on an authed page redirects here; if the session cookie is
  // still valid, offer the one-Touch-ID re-unlock instead of re-typing the email.
  // `undefined` = probing; `null` = no session (the email form); MeResponse = re-unlock.
  let returning = $state<MeResponse | null | undefined>(undefined);

  // Where to land after sign-in: a requested same-origin path (e.g. the PRSN
  // confirm-and-approve page opened by `signet enroll`) or the drive.
  const target = () => safeReturnPath(page.url.searchParams.get('returnTo'));

  onMount(async () => {
    if (sessionStore.current) {
      await goto(target());
      return;
    }
    returning = await detectReturningUser();
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    error = '';
    busy = true;
    try {
      // One Touch ID tap happens inside signIn (the passkey assertion); the KEM
      // key is unwrapped into memory and the session is established.
      const session = await signIn(authDeps(), email.trim());
      sessionStore.set(session);
      void persistSession(session); // fresh gesture → persist (S116; fire-and-forget)
      await goto(target());
    } catch (err) {
      error = friendlyAuthError(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if returning === undefined}
  <AuthCard title={m.signin_title()}>
    <p class="checking">{m.reunlock_checking()}</p>
  </AuthCard>
{:else if returning}
  <ReunlockCard
    email={returning.email ?? ''}
    onUnlocked={() => goto(target())}
    onSwitchAccount={() => (returning = null)}
  />
{:else}
  <AuthCard title={m.signin_title()} subtitle={m.signin_subtitle()}>
    <form onsubmit={submit}>
      <TextField
        label={m.signin_email_label()}
        type="email"
        bind:value={email}
        autocomplete="email"
        placeholder={m.signin_email_placeholder()}
        disabled={busy}
      />
      {#if error}<p class="form-error">{error}</p>{/if}
      <Button type="submit" loading={busy}
        >{busy ? m.signin_signing_in() : m.signin_continue()}</Button
      >
    </form>
    {#snippet footer()}
      {m.signin_footer_new()} <a href="/signup">{m.signin_footer_create()}</a>
    {/snippet}
  </AuthCard>
{/if}

<style>
  .checking {
    margin: 0;
    color: var(--muted);
    font-size: 0.95rem;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 1.05rem;
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
</style>
