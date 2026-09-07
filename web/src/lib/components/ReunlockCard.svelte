<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // Bug014 — the post-refresh re-unlock card. Shown when the session cookie is still
  // valid but the session capability is gone: the persisted-unlock restore (S116)
  // didn't apply — expired lifetime, a Lock, a restore-gate failure, or persistence
  // unavailable. "Unlock" runs the EXISTING identified sign-in for the known email
  // (one Touch ID → the wrapped KEM blob is recovered + imported non-extractable) —
  // no email typing. "Sign in to a different account" ends the server session.
  import AuthCard from './AuthCard.svelte';
  import Button from './Button.svelte';
  import { authDeps } from '$lib/deps';
  import { signIn } from '$lib/auth';
  import { persistSession, purgePersisted } from '$lib/persist';
  import { createApiClient } from '$lib/api';
  import { sessionStore } from '$lib/session.svelte';
  import { friendlyAuthError } from '$lib/errors';
  import { m } from '$lib/paraglide/messages.js';

  let {
    email,
    onUnlocked,
    onSwitchAccount,
  }: {
    email: string;
    onUnlocked?: () => void;
    onSwitchAccount?: () => void;
  } = $props();

  let busy = $state(false);
  let error = $state('');

  async function unlock() {
    if (busy) return;
    error = '';
    busy = true;
    try {
      const session = await signIn(authDeps(), email);
      sessionStore.set(session);
      void persistSession(session); // fresh gesture → persist (S116; fire-and-forget)
      onUnlocked?.();
    } catch (err) {
      error = friendlyAuthError(err);
    } finally {
      busy = false;
    }
  }

  async function switchAccount() {
    if (busy) return;
    busy = true;
    // Purge the persisted capability BEFORE the logout POST — the local purge
    // must never depend on the network call landing (S116 unlock persistence).
    await purgePersisted();
    try {
      // End the server session so the cookie can't silently re-unlock this account.
      await createApiClient().logout();
    } catch {
      // Best-effort: clear locally regardless (the cookie removal is the server's job;
      // a failed logout still drops the in-memory session).
    } finally {
      sessionStore.clear();
      busy = false;
      onSwitchAccount?.();
    }
  }
</script>

<AuthCard title={m.reunlock_title()} subtitle={m.reunlock_subtitle()}>
  <p class="email">{email}</p>
  {#if error}<p class="form-error">{error}</p>{/if}
  <Button onclick={unlock} loading={busy}>
    {busy ? m.reunlock_unlocking() : m.reunlock_unlock()}
  </Button>
  {#snippet footer()}
    <button type="button" class="switch" onclick={switchAccount} disabled={busy}>
      {m.reunlock_switch()}
    </button>
  {/snippet}
</AuthCard>

<style>
  .email {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: var(--surface-muted, var(--surface));
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--ink, var(--ink-soft));
    font-size: 0.95rem;
    font-weight: 500;
    text-align: center;
    overflow-wrap: anywhere;
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
  .switch {
    background: none;
    border: none;
    padding: 0;
    color: var(--ink-soft, var(--muted));
    font: inherit;
    font-size: 0.9rem;
    text-decoration: underline;
    cursor: pointer;
  }
  .switch:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
