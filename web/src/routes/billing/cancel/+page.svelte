<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // Stripe Checkout cancel return (server sets cancel_url to /billing/cancel). No
  // charge was made; route the user back to sign in to choose a plan when ready.
  import { goto } from '$app/navigation';
  import Wordmark from '$lib/components/Wordmark.svelte';
  import Button from '$lib/components/Button.svelte';
  import { m } from '$lib/paraglide/messages.js';
</script>

<main class="landing">
  <div class="hero">
    <Wordmark size="lg" />
    <h1>{m.billingcancel_title()}</h1>
    <p class="body">
      {m.billingcancel_body()}
    </p>
    <div class="actions">
      <Button onclick={() => goto('/')}>{m.billingcancel_return()}</Button>
    </div>
  </div>
</main>

<style>
  .landing {
    min-height: 100dvh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1.25rem;
  }
  .hero {
    max-width: 440px;
    text-align: center;
  }
  h1 {
    font-size: 1.4rem;
    font-weight: 600;
    margin: 1.4rem 0 0.8rem;
  }
  .body {
    margin: 0 0 2rem;
    color: var(--ink-soft);
    font-size: 1.02rem;
    line-height: 1.6;
  }
  .actions {
    display: flex;
    justify-content: center;
    max-width: 280px;
    margin: 0 auto;
  }
  .actions :global(button) {
    width: 100%;
  }
</style>
