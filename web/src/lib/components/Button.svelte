<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    type = 'button',
    loading = false,
    disabled = false,
    children,
    onclick,
  }: {
    type?: 'button' | 'submit';
    loading?: boolean;
    disabled?: boolean;
    children: Snippet;
    onclick?: () => void;
  } = $props();
</script>

<button {type} {onclick} disabled={disabled || loading}>
  {#if loading}<span class="spinner" aria-hidden="true"></span>{/if}
  <span class="label">{@render children()}</span>
</button>

<style>
  button {
    width: 100%;
    border: 0;
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: var(--on-accent);
    font: inherit;
    font-weight: 600;
    padding: 0.72rem 1rem;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.55rem;
    transition:
      background 0.15s,
      opacity 0.15s;
  }
  button:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  button:focus-visible {
    outline: 3px solid var(--ring);
    outline-offset: 2px;
  }
  button:disabled {
    opacity: 0.62;
    cursor: default;
  }
  .spinner {
    width: 1em;
    height: 1em;
    border: 2px solid rgba(255, 255, 255, 0.45);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
