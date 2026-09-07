<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { AccountStore } from '$lib/account.svelte';
  import Modal from './Modal.svelte';
  import { formatDateTime, formatEventType } from '$lib/format';
  import { m } from '$lib/paraglide/messages.js';

  let { store }: { store: AccountStore } = $props();

  const open = $derived(store.dialog?.kind === 'history');
</script>

{#if open}
  <Modal title={m.accounthistory_title()} onClose={() => store.closeDialog()}>
    {#if store.audit.length === 0 && !store.auditLoading}
      <p class="empty">{m.accounthistory_empty()}</p>
    {:else}
      <ul class="events">
        {#each store.audit as event (event.event_id)}
          <li>
            <span class="type">{formatEventType(event.event_type)}</span>
            <span class="when">{formatDateTime(event.event_time)}</span>
          </li>
        {/each}
      </ul>
    {/if}
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#if !store.auditDone}
      <button class="more" onclick={() => store.loadMoreAudit()} disabled={store.auditLoading}>
        {store.auditLoading ? m.accounthistory_loading() : m.accounthistory_load_more()}
      </button>
    {/if}
  </Modal>
{/if}

<style>
  .empty {
    color: var(--muted);
    font-size: 0.92rem;
    margin: 0;
  }
  .events {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
    max-height: 380px;
    overflow-y: auto;
  }
  .events li {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
    font-size: 0.9rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
  }
  .type {
    font-weight: 500;
  }
  .when {
    color: var(--muted);
    font-size: 0.82rem;
    white-space: nowrap;
  }
  .dialog-error {
    margin: 0.4rem 0 0;
    padding: 0.55rem 0.7rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.86rem;
  }
  .more {
    margin-top: 0.9rem;
    width: 100%;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-weight: 500;
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .more:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .more:disabled {
    opacity: 0.55;
    cursor: default;
  }
</style>
