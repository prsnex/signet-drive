<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  let {
    label,
    value = $bindable(''),
    type = 'text',
    name,
    placeholder = '',
    autocomplete,
    disabled = false,
    error = '',
  }: {
    label: string;
    value?: string;
    type?: 'text' | 'email';
    name?: string;
    placeholder?: string;
    autocomplete?: HTMLInputAttributes['autocomplete'];
    disabled?: boolean;
    error?: string;
  } = $props();
</script>

<label class="field">
  <span class="label">{label}</span>
  <!-- Static type per branch: Svelte forbids a dynamic `type` together with
       bind:value, so each input variant is its own element. -->
  {#if type === 'email'}
    <input
      class="control"
      class:invalid={error}
      type="email"
      {name}
      {placeholder}
      {autocomplete}
      {disabled}
      bind:value
      aria-invalid={error ? 'true' : undefined}
    />
  {:else}
    <input
      class="control"
      class:invalid={error}
      type="text"
      {name}
      {placeholder}
      {autocomplete}
      {disabled}
      bind:value
      aria-invalid={error ? 'true' : undefined}
    />
  {/if}
  {#if error}<span class="error">{error}</span>{/if}
</label>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .label {
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--ink-soft);
  }
  .control {
    width: 100%;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.66rem 0.78rem;
    font: inherit;
    color: var(--ink);
    transition:
      border-color 0.15s,
      box-shadow 0.15s;
  }
  .control::placeholder {
    color: #a9a7a0;
  }
  .control:focus {
    outline: 0;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--ring);
  }
  .control:disabled {
    background: #faf9f6;
    color: var(--muted);
  }
  .control.invalid {
    border-color: var(--danger);
  }
  .error {
    font-size: 0.82rem;
    color: var(--danger);
  }
</style>
