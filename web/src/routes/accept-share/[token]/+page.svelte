<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { createApiClient, SignetApiError, type InvitationPreview } from '$lib/api';
  import { friendlyDriveError } from '$lib/errors';
  import { formatDateTime } from '$lib/format';
  import AuthCard from '$lib/components/AuthCard.svelte';
  import Button from '$lib/components/Button.svelte';
  import { m } from '$lib/paraglide/messages.js';

  const token = $derived(page.params.token ?? '');
  // Preview + accept are cookie-authed and need no crypto, so this works on a
  // fresh load as long as the recipient has a valid session cookie.
  const api = createApiClient();

  let preview = $state<InvitationPreview | null>(null);
  let loading = $state(true);
  let needsSignin = $state(false);
  let accepted = $state(false);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    void load(token);
  });

  async function load(value: string) {
    loading = true;
    error = '';
    needsSignin = false;
    try {
      preview = await api.previewInvitation(value);
    } catch (err) {
      if (err instanceof SignetApiError && err.status === 401) needsSignin = true;
      // A dead token (canceled, expired, or never valid) deserves the
      // invitation-specific copy — the generic drive mapping's "refreshing
      // your view" is nonsense on this page (S121, W6).
      else if (err instanceof SignetApiError && err.code === 'not_found')
        error = m.acceptshare_gone();
      else error = friendlyDriveError(err);
    } finally {
      loading = false;
    }
  }

  async function accept() {
    busy = true;
    error = '';
    try {
      await api.acceptInvitation(token);
      accepted = true;
    } catch (err) {
      error = friendlyDriveError(err);
    } finally {
      busy = false;
    }
  }

  function whenIso(unixSeconds: number): string {
    // The app-wide date convention ("Jul 16, 2026, 10:19 AM"), not the raw
    // locale default with seconds (S121 review, W9).
    return formatDateTime(unixSeconds);
  }
</script>

<AuthCard title={m.acceptshare_title()} subtitle={m.acceptshare_subtitle()}>
  {#if loading}
    <p class="muted">{m.acceptshare_loading()}</p>
  {:else if accepted}
    <p>{m.acceptshare_accepted()}</p>
    <Button onclick={() => goto('/')}>{m.acceptshare_go_to_files()}</Button>
  {:else if needsSignin}
    <p>{m.acceptshare_needs_signin()}</p>
    <Button onclick={() => goto('/signin')}>{m.acceptshare_signin()}</Button>
  {:else if preview}
    <dl class="detail">
      <div>
        <dt>{m.acceptshare_from()}</dt>
        <dd>{preview.inviter_handle ?? '—'}</dd>
      </div>
      <div>
        <dt>{m.acceptshare_permission()}</dt>
        <dd>
          {preview.permission === 'read_write'
            ? m.acceptshare_perm_read_write()
            : m.acceptshare_perm_read_only()}
        </dd>
      </div>
      <div>
        <dt>{m.acceptshare_files()}</dt>
        <dd>{preview.file_count}</dd>
      </div>
      <div>
        <dt>{m.acceptshare_expires()}</dt>
        <dd>{whenIso(preview.expires_at)}</dd>
      </div>
    </dl>
    <p class="muted">
      {m.acceptshare_accept_note()}
    </p>
    {#if error}<p class="form-error">{error}</p>{/if}
    <div class="actions">
      <button class="ghost" onclick={() => goto('/')} disabled={busy}
        >{m.acceptshare_decline()}</button
      >
      <Button loading={busy} onclick={accept}
        >{busy ? m.acceptshare_accepting() : m.acceptshare_accept()}</Button
      >
    </div>
  {:else}
    <p class="form-error">{error || m.acceptshare_load_failed()}</p>
  {/if}
</AuthCard>

<style>
  .muted {
    color: var(--muted);
  }
  .detail {
    margin: 0 0 0.4rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .detail div {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
  }
  .detail dt {
    color: var(--muted);
    font-size: 0.9rem;
  }
  .detail dd {
    margin: 0;
    font-weight: 500;
  }
  .actions {
    display: flex;
    gap: 0.6rem;
    align-items: center;
  }
  .actions :global(button[type='button']) {
    flex: 1;
  }
  .ghost {
    flex: none;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-weight: 500;
    padding: 0.72rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .ghost:hover:not(:disabled) {
    border-color: var(--muted);
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
</style>
