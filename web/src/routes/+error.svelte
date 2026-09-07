<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // Root error boundary. Without this, SvelteKit falls back to its built-in
  // UNSTYLED error page (bare "404 / Not Found", flush to the top-left) — which
  // is what a guardian saw on a bad/incomplete link (e.g. a bare
  // `/account/add-prsn` with no `?code=`). This renders any 404/error as a
  // branded, centred Signet card with a way back (graceful-404, Chris S119).
  import { page } from '$app/state';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import { m } from '$lib/paraglide/messages.js';

  const isNotFound = $derived(page.status === 404);
  const title = $derived(isNotFound ? m.error_notfound_title() : m.error_generic_title());
  const subtitle = $derived(isNotFound ? m.error_notfound_subtitle() : m.error_generic_subtitle());
</script>

<AuthCard {title} {subtitle}>
  <p class="status">{m.error_status({ status: String(page.status) })}</p>
  <a class="back" href="/">{m.error_back()}</a>
</AuthCard>

<style>
  .status {
    margin: 0;
    color: var(--muted);
    font-size: 0.85rem;
    font-variant-numeric: tabular-nums;
  }
  /* A button-styled link (the Button component is button-only, no href), matching
     the primary-action look so "back" is the obvious next step. */
  .back {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: var(--on-accent);
    font-weight: 600;
    padding: 0.72rem 1rem;
    text-decoration: none;
    transition: background 0.15s;
  }
  .back:hover {
    background: var(--accent-hover);
    text-decoration: none;
  }
  .back:focus-visible {
    outline: 3px solid var(--ring);
    outline-offset: 2px;
  }
</style>
