<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { m } from '$lib/paraglide/messages.js';

  let {
    title,
    onClose,
    children,
    footer,
  }: {
    title: string;
    onClose: () => void;
    children: Snippet;
    footer?: Snippet;
  } = $props();

  function onKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') onClose();
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="overlay">
  <!-- A real button as the scrim keeps click-to-dismiss accessible. -->
  <button class="scrim" aria-label={m.modal_close_dialog()} onclick={onClose}></button>
  <div class="modal" role="dialog" aria-modal="true" aria-label={title}>
    <header>
      <h2>{title}</h2>
      <button class="close" aria-label={m.modal_close()} onclick={onClose}>×</button>
    </header>
    <div class="body">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.25rem;
    z-index: 50;
  }
  .scrim {
    position: absolute;
    inset: 0;
    border: 0;
    padding: 0;
    background: rgba(20, 20, 35, 0.42);
    cursor: default;
  }
  .modal {
    position: relative;
    width: 100%;
    max-width: 420px;
    /* A tall dialog (e.g. the Add-PRSN wizard) scrolls within the viewport
       instead of pushing its footer actions off-screen. */
    max-height: calc(100dvh - 2.5rem);
    overflow-y: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1.5rem 1.6rem 1.4rem;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.1rem;
  }
  h2 {
    font-size: 1.18rem;
    font-weight: 600;
    margin: 0;
  }
  .close {
    border: 0;
    background: none;
    font-size: 1.5rem;
    line-height: 1;
    color: var(--muted);
    cursor: pointer;
    padding: 0 0.2rem;
  }
  .close:hover {
    color: var(--ink);
  }
  .body {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
    margin-top: 1.3rem;
  }
</style>
