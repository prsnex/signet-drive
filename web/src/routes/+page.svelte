<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { goto } from '$app/navigation';
  import Wordmark from '$lib/components/Wordmark.svelte';
  import Button from '$lib/components/Button.svelte';
  import FileBrowser from '$lib/components/FileBrowser.svelte';
  import ReunlockCard from '$lib/components/ReunlockCard.svelte';
  import FinishSetupCard from '$lib/components/FinishSetupCard.svelte';
  import { sessionStore } from '$lib/session.svelte';
  import { detectReturningUser } from '$lib/reauth';
  import { restoreSession } from '$lib/persist';
  import type { MeResponse } from '$lib/api';
  import { m } from '$lib/paraglide/messages.js';

  // Bug014: after a refresh the in-memory key is gone but the session cookie may
  // still be valid. `undefined` = still probing; `null` = no session (show landing);
  // a MeResponse = a valid cookie → offer the one-Touch-ID re-unlock.
  //
  // Bug021: this detection is REACTIVE to sessionStore.current, not a one-shot
  // onMount. An in-place sign-out (FileBrowser.signOut → sessionStore.clear() with
  // no navigation, since FileBrowser already renders at '/') clears the session
  // without remounting this page. A one-shot onMount had already early-returned
  // while signed in, leaving `returning` stuck at `undefined`, so the page hung
  // forever on "Checking your session…". Re-probing whenever the session clears
  // resolves it: sign-out clears the cookie first, so the probe returns null →
  // landing; a fresh load with a still-valid cookie still resolves to the re-unlock
  // card. (The admin/account sign-outs goto('/') from another route, so they always
  // remounted fresh — only the at-'/' FileBrowser sign-out exposed the one-shot bug.)
  let returning = $state<MeResponse | null | undefined>(undefined);

  $effect(() => {
    if (sessionStore.current) return; // signed in → FileBrowser; nothing to detect
    let cancelled = false;
    returning = undefined; // show "Checking…" while we probe the cookie
    // S116 unlock persistence: try the zero-gesture restore FIRST (its four
    // gates include the same /v1/me probe). Success → the session populates and
    // FileBrowser renders — no card. Any failure → null, and the flow below is
    // exactly the pre-persistence behavior (cookie probe → re-unlock / landing).
    void restoreSession().then((restored) => {
      if (cancelled) return;
      if (restored) {
        sessionStore.set(restored);
        return;
      }
      void detectReturningUser().then((result) => {
        if (!cancelled) returning = result;
      });
    });
    return () => {
      cancelled = true;
    };
  });
</script>

{#if sessionStore.current}
  {@const session = sessionStore.current}
  <FileBrowser {session} />
{:else if returning === undefined}
  <main class="landing"><p class="tagline">{m.reunlock_checking()}</p></main>
{:else if returning && returning.kem_pubkey_fingerprint}
  <ReunlockCard email={returning.email ?? ''} onSwitchAccount={() => (returning = null)} />
{:else if returning}
  <!-- bug065: a valid session for an account that never finished signup (no KEM
       key → kem_pubkey_fingerprint null). Offering "Unlock" is a dead end — there
       is no passkey to sign in with. Route the user to FINISH registration. -->
  <FinishSetupCard email={returning.email ?? ''} onSwitchAccount={() => (returning = null)} />
{:else}
  <main class="landing">
    <div class="hero">
      <Wordmark size="lg" />
      <p class="tagline">{m.landing_tagline()}</p>
      <div class="actions">
        <Button onclick={() => goto('/signin')}>{m.landing_sign_in()}</Button>
        <a class="secondary" href="/signup">{m.landing_create_account()}</a>
      </div>
    </div>
  </main>
{/if}

<style>
  .landing {
    min-height: 100dvh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1.25rem;
  }
  .hero {
    max-width: 420px;
    text-align: center;
  }
  .tagline {
    margin: 1.4rem 0 2rem;
    color: var(--ink-soft);
    font-size: 1.08rem;
    line-height: 1.6;
  }
  .actions {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    max-width: 280px;
    margin: 0 auto;
  }
  .actions :global(button) {
    width: 100%;
  }
  .secondary {
    font-size: 0.95rem;
    color: var(--ink-soft);
  }
</style>
