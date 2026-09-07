<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Wordmark from './Wordmark.svelte';

  let {
    title,
    subtitle,
    children,
    footer,
  }: {
    title: string;
    subtitle?: string;
    /** ⭐ OPTIONAL (S206): a card may legitimately have no body. The paused-signup
     *  notice is a title and a subtitle and nothing else — the alternative was
     *  inventing a third sentence purely to fill a required slot. */
    children?: Snippet;
    footer?: Snippet;
  } = $props();
</script>

<main class="wrap">
  <section class="card">
    <div class="brand"><Wordmark /></div>
    <h1>{title}</h1>
    {#if subtitle}<p class="subtitle">{subtitle}</p>{/if}
    {#if children}
      <div class="body">
        {@render children()}
      </div>
    {/if}
  </section>
  {#if footer}
    <p class="footer">{@render footer()}</p>
  {/if}
</main>

<style>
  .wrap {
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1.1rem;
    padding: 2rem 1.25rem;
  }
  .card {
    width: 100%;
    max-width: 384px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 2.1rem 1.85rem;
  }
  .brand {
    margin-bottom: 1.6rem;
  }
  h1 {
    font-size: 1.4rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    margin: 0 0 0.35rem;
  }
  .subtitle {
    margin: 0 0 1.5rem;
    color: var(--muted);
    font-size: 0.95rem;
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 1.05rem;
  }
  .footer {
    margin: 0;
    color: var(--muted);
    font-size: 0.9rem;
    text-align: center;
  }
</style>
