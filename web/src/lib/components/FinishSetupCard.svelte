<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // bug065 — the landing card shown when a valid session cookie belongs to an
  // account that never finished signup (no KEM key → `kem_pubkey_fingerprint`
  // null). "Unlock" (ReunlockCard) is a dead end for this account — there is no
  // passkey to sign in with — so route the user to FINISH registration via the
  // /verify resume path (which reuses the bug062 prep screen + graceful retry, no
  // second email). "Not you? Sign out" ends the session — the escape for someone
  // who wants out, labelled for a brand-new user (bug067: the old "sign in to a
  // different account" wording read wrong to someone with no other account).
  import AuthCard from './AuthCard.svelte';
  import Button from './Button.svelte';
  import { goto } from '$app/navigation';
  import { purgePersisted } from '$lib/persist';
  import { createApiClient } from '$lib/api';
  import { sessionStore } from '$lib/session.svelte';
  import { m } from '$lib/paraglide/messages.js';

  let {
    email,
    onSwitchAccount,
  }: {
    email: string;
    onSwitchAccount?: () => void;
  } = $props();

  let busy = $state(false);

  async function switchAccount() {
    if (busy) return;
    busy = true;
    // Purge the persisted capability BEFORE the logout POST — the local purge must
    // never depend on the network call landing (mirrors ReunlockCard, S116).
    await purgePersisted();
    try {
      await createApiClient().logout();
    } catch {
      // Best-effort: clear locally regardless (cookie removal is the server's job;
      // a failed logout still drops the in-memory session).
    } finally {
      sessionStore.clear();
      busy = false;
      onSwitchAccount?.();
    }
  }
</script>

<AuthCard title={m.finish_setup_title()} subtitle={m.finish_setup_subtitle()}>
  <p class="email">{email}</p>
  <Button onclick={() => goto('/verify')}>{m.finish_setup_continue()}</Button>
  {#snippet footer()}
    <button type="button" class="switch" onclick={switchAccount} disabled={busy}>
      {m.finish_setup_switch()}
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
