<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { Browser } from '$lib/browser.svelte';
  import Modal from './Modal.svelte';
  import TextField from './TextField.svelte';
  import { m } from '$lib/paraglide/messages.js';
  import { formatDateTime } from '$lib/format';

  let { browser }: { browser: Browser } = $props();

  // FileBrowser only renders this when the dialog is the share panel; the derived
  // narrows the union so `rootFolderId` / `role` are available.
  const dialog = $derived(browser.dialog?.kind === 'sharePanel' ? browser.dialog : null);

  let inviteHandle = $state('');
  let permission = $state<'read_only' | 'read_write'>('read_write');
  let inviteLink = $state('');
  /** Who the shown link was generated FOR (S121, W7) — a single-use link with no
   *  visible recipient was ambiguous the moment the field cleared. */
  let inviteLinkFor = $state('');
  let linkCopied = $state(false);

  // The link is single-use and per-recipient: never carry one across a
  // close/re-open of the panel (S121, W7 — a consumed link kept re-appearing).
  $effect(() => {
    if (!dialog) {
      inviteLink = '';
      inviteLinkFor = '';
      linkCopied = false;
    }
  });

  async function submitInvite(event: Event) {
    event.preventDefault();
    if (!dialog) return;
    inviteLink = '';
    inviteLinkFor = '';
    linkCopied = false;
    const invitee = inviteHandle.trim();
    const token = await browser.invite(dialog.rootFolderId, invitee, permission);
    if (token) {
      inviteLink = `${window.location.origin}/accept-share/${token}`;
      inviteLinkFor = invitee;
      inviteHandle = '';
    }
  }

  // Bug005(a): the link is the whole point of the flow — make it one-tap copyable
  // (the same clipboard idiom as the Garnet code hand-off).
  async function copyLink() {
    try {
      await navigator.clipboard.writeText(inviteLink);
      linkCopied = true;
      setTimeout(() => (linkCopied = false), 2000);
    } catch {
      // Clipboard denied (permissions): the link stays selectable by hand.
    }
  }
</script>

{#if dialog}
  {@const current = dialog}
  <Modal title={m.sharepanel_title()} onClose={() => browser.closeDialog()}>
    <section>
      <h3>{m.sharepanel_people()}</h3>
      {#if browser.recipients.length === 0}
        <p class="muted">{m.sharepanel_no_one()}</p>
      {:else}
        <ul class="recipients">
          {#each browser.recipients as recipient (recipient.recipient_account_id)}
            <li>
              <span class="who">{recipient.handle ?? '—'}</span>
              <span class="perm">
                {recipient.permission === 'read_write'
                  ? m.sharepanel_perm_read_write()
                  : m.sharepanel_perm_read_only()}
                {recipient.is_mandatory_guardian ? m.sharepanel_guardian_tag() : ''}
              </span>
              {#if current.role === 'owner' && !recipient.is_mandatory_guardian}
                <button
                  class="remove"
                  disabled={browser.busy}
                  onclick={() =>
                    browser.removeRecipient(current.rootFolderId, recipient.recipient_account_id)}
                >
                  {m.sharepanel_remove()}
                </button>
              {:else if recipient.is_mandatory_guardian}
                <span class="cannot">{m.sharepanel_cannot_remove()}</span>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    {#if current.role === 'owner' && browser.pendingInvitations.length > 0}
      <section>
        <h3>{m.sharepanel_pending_title()}</h3>
        <ul class="recipients">
          {#each browser.pendingInvitations as invitation (invitation.invitation_id)}
            <li>
              <span class="who">{invitation.recipient_handle}</span>
              <span class="perm">
                {invitation.permission === 'read_write'
                  ? m.sharepanel_perm_read_write()
                  : m.sharepanel_perm_read_only()}
                · {m.sharepanel_pending_expires({ when: formatDateTime(invitation.expires_at) })}
              </span>
              <button
                class="remove"
                disabled={browser.busy}
                onclick={() =>
                  browser.cancelInvitation(current.rootFolderId, invitation.invitation_id)}
              >
                {m.sharepanel_cancel_invite()}
              </button>
            </li>
          {/each}
        </ul>
        <p class="muted">{m.sharepanel_pending_note()}</p>
      </section>
    {/if}

    {#if current.role === 'owner'}
      <section>
        <h3>{m.sharepanel_invite()}</h3>
        <form onsubmit={submitInvite}>
          <TextField
            label={m.sharepanel_their_username()}
            bind:value={inviteHandle}
            disabled={browser.busy}
          />
          <div class="perm-choice">
            <label
              ><input type="radio" value="read_only" bind:group={permission} />
              {m.sharepanel_perm_read_only()}</label
            >
            <label>
              <input type="radio" value="read_write" bind:group={permission} />
              {m.sharepanel_perm_read_write()}
            </label>
          </div>
          <button class="confirm" type="submit" disabled={browser.busy}>
            {m.sharepanel_generate_link()}
          </button>
        </form>
        {#if inviteLink}
          <div class="link">
            <p class="muted">
              {inviteLinkFor
                ? m.sharepanel_link_for({ handle: inviteLinkFor })
                : m.sharepanel_link_note()}
            </p>
            <code>{inviteLink}</code>
            <button type="button" class="copy" onclick={copyLink}>
              {linkCopied ? m.sharepanel_copied() : m.sharepanel_copy_link()}
            </button>
          </div>
        {/if}
      </section>
    {/if}

    {#if browser.error}<p class="dialog-error">{browser.error}</p>{/if}

    {#snippet footer()}
      {#if current.role === 'recipient'}
        <button
          class="ghost"
          disabled={browser.busy}
          onclick={() => browser.leave(current.rootFolderId)}
        >
          {m.sharepanel_leave()}
        </button>
      {/if}
      <button class="ghost" onclick={() => browser.closeDialog()}>{m.sharepanel_close()}</button>
    {/snippet}
  </Modal>
{/if}

<style>
  h3 {
    font-size: 0.82rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin: 0 0 0.6rem;
  }
  .muted {
    color: var(--muted);
    font-size: 0.9rem;
    margin: 0;
  }
  .recipients {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .recipients li {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.92rem;
  }
  .who {
    font-weight: 500;
  }
  .perm {
    color: var(--muted);
    font-size: 0.82rem;
  }
  .remove {
    margin-left: auto;
    border: 0;
    background: none;
    color: var(--danger);
    font: inherit;
    font-size: 0.82rem;
    cursor: pointer;
    padding: 0;
  }
  .remove:hover:not(:disabled) {
    text-decoration: underline;
  }
  .cannot {
    margin-left: auto;
    color: var(--muted);
    font-size: 0.78rem;
    font-style: italic;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .perm-choice {
    display: flex;
    gap: 1.1rem;
    font-size: 0.9rem;
    color: var(--ink-soft);
  }
  .perm-choice label {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    cursor: pointer;
  }
  .confirm {
    border: 0;
    background: var(--accent);
    color: var(--on-accent);
    font: inherit;
    font-weight: 600;
    padding: 0.55rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .confirm:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .link {
    margin-top: 0.7rem;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .link .copy {
    align-self: flex-start;
    font-size: 0.82rem;
    padding: 0.35rem 0.7rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    cursor: pointer;
  }
  .link .copy:hover {
    border-color: var(--accent);
  }
  .link code {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.8rem;
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 0.5rem 0.6rem;
    border-radius: var(--radius-sm);
    color: var(--ink-soft);
    word-break: break-all;
  }
  .dialog-error {
    margin: 0;
    padding: 0.55rem 0.7rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.86rem;
  }
  .ghost {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-weight: 500;
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .ghost:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .ghost:disabled {
    opacity: 0.55;
    cursor: default;
  }
</style>
