<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import type { Session } from '$lib/auth';
  import { Browser } from '$lib/browser.svelte';
  import { createApiClient } from '$lib/api';
  import { purgePersisted } from '$lib/persist';
  import { tooltip } from '$lib/tooltip';
  import { sessionStore } from '$lib/session.svelte';
  import Wordmark from './Wordmark.svelte';
  import Sidebar from './Sidebar.svelte';
  import FileList from './FileList.svelte';
  import Modal from './Modal.svelte';
  import SharePanel from './SharePanel.svelte';
  import ActionMenu from './ActionMenu.svelte';
  import TextField from './TextField.svelte';
  import BillingBanner from './BillingBanner.svelte';
  import SealImpression from '$lib/seal/SealImpression.svelte';
  import { meSeed } from '$lib/seal/seed';
  import { m } from '$lib/paraglide/messages.js';

  let { session }: { session: Session } = $props();

  // The session is fixed for this component's life — sign-out unmounts the
  // browser (the `{#if}` in +page.svelte), so capturing the initial value is
  // intended; untrack documents that and silences the reactivity hint.
  const browser = untrack(() => new Browser(session));

  // The signed-in identity's own seal — its key fingerprint per type (a PRSN's
  // signing fp, a human's KEM fp; falls back to the handle). Decorative.
  const accountSeed = $derived(meSeed(browser.me));
  void browser.init();
  onDestroy(() => browser.dispose());

  let newFolderName = $state('');
  let shareFolderName = $state('');
  let renameValue = $state('');

  // Mobile: the sidebar collapses to an overlay drawer (row 21).
  let sidebarOpen = $state(false);

  // Prefill the dialog inputs when a dialog opens (dialog identity is stable while
  // it's open, so this doesn't clobber what the user is typing).
  $effect(() => {
    const dialog = browser.dialog;
    if (dialog?.kind === 'newFolder') newFolderName = '';
    if (dialog?.kind === 'newShareFolder') shareFolderName = '';
    if (dialog?.kind === 'rename') renameValue = dialog.file?.name ?? dialog.folder?.name ?? '';
  });

  function submitNewFolder(event?: Event) {
    event?.preventDefault();
    void browser.createFolder(newFolderName);
  }

  function submitNewShareFolder(event?: Event) {
    event?.preventDefault();
    void browser.createShareFolder(shareFolderName);
  }

  function submitRename(event?: Event) {
    event?.preventDefault();
    void browser.rename(renameValue);
  }

  async function signOut() {
    // Purge the persisted unlock BEFORE the logout POST — the local purge must
    // never depend on the network call landing (S116 unlock persistence).
    await purgePersisted();
    // End the server session FIRST (clears the cookie), then drop the in-memory
    // session. Order matters: clearing first would route to the landing, whose
    // re-unlock probe could see the still-valid cookie and flash the re-unlock card
    // (Bug014). Best-effort — a failed logout still clears locally.
    try {
      await createApiClient().logout();
    } catch {
      // ignore — fall through to the local clear
    }
    sessionStore.clear();
  }

  async function lock() {
    // The explicit "I'm walking away" move (S116 unlock persistence): purge the
    // persisted capability + drop the in-memory session, but KEEP the server
    // session — the landing shows the one-tap re-unlock, not a full sign-in.
    await purgePersisted();
    sessionStore.clear();
  }

  // ── Resizable left-nav ────────────────────────────────────────────────────
  // A draggable splitter sets the sidebar width via the `--nav-width` CSS var on
  // `.body` (read by Sidebar's `.sidebar`); the choice persists to localStorage.
  // Front-end only — no crypto/server/schema.
  const NAV_MIN = 180;
  const NAV_MAX = 480;
  const NAV_DEFAULT = 240;
  const NAV_KEY = 'signet:nav-width';

  const clampNav = (px: number) => Math.min(NAV_MAX, Math.max(NAV_MIN, Math.round(px)));

  function loadNavWidth(): number {
    if (typeof localStorage === 'undefined') return NAV_DEFAULT;
    const raw = Number(localStorage.getItem(NAV_KEY));
    return Number.isFinite(raw) && raw > 0 ? clampNav(raw) : NAV_DEFAULT;
  }

  let navWidth = $state(loadNavWidth());
  let bodyEl = $state<HTMLDivElement>();
  let resizing = $state(false);

  function persistNavWidth() {
    if (typeof localStorage !== 'undefined') localStorage.setItem(NAV_KEY, String(navWidth));
  }
  function onPointerMove(event: PointerEvent) {
    if (!bodyEl) return;
    navWidth = clampNav(event.clientX - bodyEl.getBoundingClientRect().left);
  }
  function endResize() {
    if (!resizing) return;
    resizing = false;
    window.removeEventListener('pointermove', onPointerMove);
    window.removeEventListener('pointerup', endResize);
    persistNavWidth();
  }
  function startResize(event: PointerEvent) {
    event.preventDefault();
    resizing = true;
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', endResize);
  }
  function onResizerKey(event: KeyboardEvent) {
    const step = event.shiftKey ? 32 : 8;
    if (event.key === 'ArrowLeft') navWidth = clampNav(navWidth - step);
    else if (event.key === 'ArrowRight') navWidth = clampNav(navWidth + step);
    else return;
    event.preventDefault();
    persistNavWidth();
  }

  onDestroy(() => {
    // Defensive: drop the window listeners if we unmount mid-drag.
    window.removeEventListener('pointermove', onPointerMove);
    window.removeEventListener('pointerup', endResize);
  });
</script>

<div class="app">
  <header class="bar">
    <span class="bar-left">
      <button
        class="burger"
        onclick={() => (sidebarOpen = true)}
        aria-label={m.filebrowser_open_nav()}
      >
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.6"
          stroke-linecap="round"
          aria-hidden="true"
        >
          <path d="M4 7h16M4 12h16M4 17h16" />
        </svg>
      </button>
      <Wordmark />
    </span>
    <div class="acct">
      {#if browser.me?.admin_role}<a class="handle" href="/admin">{m.filebrowser_admin()}</a>{/if}
      <a class="handle account" href="/account">
        <SealImpression seed={accountSeed} size={20} /><span class="handle-text"
          >{browser.me?.handle ?? m.filebrowser_account_fallback()}</span
        >
      </a>
      <button class="signout" onclick={lock} use:tooltip={m.filebrowser_lock_title()}>
        {m.filebrowser_lock()}
      </button>
      <button class="signout" onclick={signOut} use:tooltip={m.account_sign_out_title()}
        >{m.filebrowser_sign_out()}</button
      >
    </div>
  </header>

  <BillingBanner me={browser.me} quota={browser.quota} />

  {#if browser.loading}
    <div class="loading">
      <span class="spinner" aria-hidden="true"></span>{m.filebrowser_loading()}
    </div>
  {:else}
    <div class="body" bind:this={bodyEl} style="--nav-width: {navWidth}px" class:resizing>
      <div class="nav-wrap" class:open={sidebarOpen}>
        <Sidebar {browser} />
      </div>
      <button
        class="scrim"
        class:open={sidebarOpen}
        onclick={() => (sidebarOpen = false)}
        aria-label={m.filebrowser_close_nav()}
        tabindex={sidebarOpen ? 0 : -1}
      ></button>
      <!-- Drag handle for the sidebar width. role=slider — an interactive,
           keyboard-operable value control (aria-valuenow = px; arrow keys adjust) —
           is the lint-clean ARIA fit for a resize grip. -->
      <div
        class="resizer"
        role="slider"
        aria-label={m.filebrowser_resize_nav()}
        aria-valuemin={NAV_MIN}
        aria-valuemax={NAV_MAX}
        aria-valuenow={navWidth}
        tabindex="0"
        onpointerdown={startResize}
        onkeydown={onResizerKey}
      ></div>
      <FileList {browser} />
    </div>
  {/if}
</div>

{#if browser.dialog?.kind === 'newFolder'}
  <Modal title={m.filebrowser_new_folder_title()} onClose={() => browser.closeDialog()}>
    <form onsubmit={submitNewFolder}>
      <TextField
        label={m.filebrowser_folder_name_label()}
        bind:value={newFolderName}
        disabled={browser.busy}
      />
      {#if browser.error}<p class="dialog-error">{browser.error}</p>{/if}
    </form>
    {#snippet footer()}
      <button class="ghost" onclick={() => browser.closeDialog()} disabled={browser.busy}>
        {m.filebrowser_cancel()}
      </button>
      <button class="confirm" onclick={submitNewFolder} disabled={browser.busy}
        >{m.filebrowser_create()}</button
      >
    {/snippet}
  </Modal>
{:else if browser.dialog?.kind === 'newShareFolder'}
  <Modal title={m.filebrowser_new_share_folder_title()} onClose={() => browser.closeDialog()}>
    <form onsubmit={submitNewShareFolder}>
      <TextField
        label={m.filebrowser_folder_name_label()}
        bind:value={shareFolderName}
        disabled={browser.busy}
      />
      {#if browser.error}<p class="dialog-error">{browser.error}</p>{/if}
    </form>
    {#snippet footer()}
      <button class="ghost" onclick={() => browser.closeDialog()} disabled={browser.busy}>
        {m.filebrowser_cancel()}
      </button>
      <button class="confirm" onclick={submitNewShareFolder} disabled={browser.busy}
        >{m.filebrowser_create()}</button
      >
    {/snippet}
  </Modal>
{:else if browser.dialog?.kind === 'rename'}
  <Modal title={m.filebrowser_rename_title()} onClose={() => browser.closeDialog()}>
    <form onsubmit={submitRename}>
      <TextField
        label={m.filebrowser_new_name_label()}
        bind:value={renameValue}
        disabled={browser.busy}
      />
      {#if browser.error}<p class="dialog-error">{browser.error}</p>{/if}
    </form>
    {#snippet footer()}
      <button class="ghost" onclick={() => browser.closeDialog()} disabled={browser.busy}>
        {m.filebrowser_cancel()}
      </button>
      <button class="confirm" onclick={submitRename} disabled={browser.busy}
        >{m.filebrowser_save()}</button
      >
    {/snippet}
  </Modal>
{:else if browser.dialog?.kind === 'move'}
  <Modal
    title={browser.selectionCount === 1
      ? m.filebrowser_move_title_one()
      : m.filebrowser_move_title_many({ count: browser.selectionCount })}
    onClose={() => browser.closeDialog()}
  >
    {#if browser.moveTargets.length}
      <p class="hint">{m.filebrowser_move_choose()}</p>
      <ul class="targets">
        {#each browser.moveTargets as target (target.folderId)}
          <li>
            <button onclick={() => browser.moveTo(target.folderId)} disabled={browser.busy}>
              {target.label}
            </button>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="hint">{m.filebrowser_move_none()}</p>
    {/if}
    {#if browser.error}<p class="dialog-error">{browser.error}</p>{/if}
  </Modal>
{:else if browser.dialog?.kind === 'confirmDelete'}
  {@const dlg = browser.dialog}
  {@const targeted = !!(dlg.file || dlg.folder)}
  {@const count = targeted ? 1 : browser.selectionCount}
  {@const hasFolder = targeted ? !!dlg.folder : browser.selectedFolders.size > 0}
  <Modal
    title={count === 1
      ? m.filebrowser_delete_title_one()
      : m.filebrowser_delete_title_many({ count })}
    onClose={() => browser.closeDialog()}
  >
    <p class="hint">
      {hasFolder
        ? m.filebrowser_delete_confirm_folders()
        : count === 1
          ? m.filebrowser_delete_confirm_one()
          : m.filebrowser_delete_confirm_many()}
    </p>
    {#if browser.error}<p class="dialog-error">{browser.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => browser.closeDialog()} disabled={browser.busy}>
        {m.filebrowser_cancel()}
      </button>
      <button class="danger" onclick={() => browser.confirmDelete()} disabled={browser.busy}>
        {m.filebrowser_delete()}
      </button>
    {/snippet}
  </Modal>
{/if}

<SharePanel {browser} />

<!-- bug101 + bug223: the single top-level ⋯ / right-click actions menu — opened by
     the file panel and the left-nav tree via browser.contextMenu. RENAME is owner-gated
     (owner-only server-side). DELETE is per-item: a file yields to a `read_write`
     recipient, a folder is owner-only. A blocked action shows disabled with the reason
     that actually applies. -->
{#if browser.contextMenu}
  {@const cm = browser.contextMenu}
  <ActionMenu
    x={cm.x}
    y={cm.y}
    onClose={() => browser.closeContextMenu()}
    items={[
      {
        label: m.filelist_rename(),
        disabled: !cm.owned,
        tip: m.filelist_action_not_owner(),
        onSelect: () => browser.openRenameItem({ file: cm.file, folder: cm.folder }),
      },
      {
        label: m.filelist_delete(),
        danger: true,
        // bug223: NOT `!cm.owned`. A read_write recipient may delete a FILE
        // (folder_authority, bug208 §3b) but not a FOLDER (folders.rs is
        // owner-only), so the answer is per-item and computed at open time.
        disabled: !cm.deletable,
        tip: cm.folder ? m.filelist_delete_folder_not_owner() : m.filelist_action_read_only(),
        onSelect: () => browser.openConfirmDeleteItem({ file: cm.file, folder: cm.folder }),
      },
    ]}
  />
{/if}

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100dvh;
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    flex: none;
  }
  .acct {
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  .handle {
    color: var(--ink-soft);
    font-size: 0.9rem;
    font-weight: 500;
    text-decoration: none;
  }
  .handle.account {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }
  .handle:hover {
    color: var(--ink);
    text-decoration: underline;
  }
  .signout {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.85rem;
    padding: 0.36rem 0.8rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .signout:hover {
    border-color: var(--muted);
  }
  .body {
    flex: 1;
    display: flex;
    min-height: 0;
  }
  /* The drag handle straddles the sidebar's right edge (negative margin → adds no
     layout width); its centred line accents on hover/focus/drag. */
  .resizer {
    flex: 0 0 8px;
    margin-left: -8px;
    position: relative;
    z-index: 1;
    cursor: col-resize;
    align-self: stretch;
    background: none;
    border: 0;
    padding: 0;
  }
  .resizer::after {
    content: '';
    position: absolute;
    top: 0;
    bottom: 0;
    right: 0;
    width: 2px;
    background: transparent;
    transition: background 0.15s;
  }
  .resizer:hover::after,
  .resizer:focus-visible::after,
  .body.resizing .resizer::after {
    background: var(--accent);
  }
  .resizer:focus-visible {
    outline: none;
  }
  .body.resizing {
    cursor: col-resize;
    user-select: none;
  }
  .loading {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.6rem;
    color: var(--muted);
  }
  .spinner {
    width: 1.1em;
    height: 1.1em;
    border: 2px solid var(--field-border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .hint {
    margin: 0;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  .targets {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    max-height: 240px;
    overflow-y: auto;
  }
  .targets button {
    width: 100%;
    text-align: left;
    border: 1px solid var(--field-border);
    background: var(--surface);
    font: inherit;
    color: var(--ink);
    padding: 0.5rem 0.7rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .targets button:hover:not(:disabled) {
    border-color: var(--accent);
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
  .confirm {
    border: 0;
    background: var(--accent);
    color: var(--on-accent);
    font: inherit;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .danger {
    border: 0;
    background: var(--danger);
    color: #fff;
    font: inherit;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .danger:disabled,
  .confirm:disabled,
  .ghost:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .bar-left {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
  }
  .burger {
    display: none;
    align-items: center;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    border-radius: var(--radius-sm);
    padding: 0.3rem 0.45rem;
    cursor: pointer;
  }
  .burger:hover {
    border-color: var(--muted);
  }
  /* Desktop: the wrap is transparent, so the sidebar stays a direct flex child
     (its width + the resizer behave as before). Mobile: it becomes the drawer. */
  .nav-wrap {
    display: contents;
  }
  .scrim {
    display: none;
  }
  @media (min-width: 721px) and (max-width: 1024px) {
    /* Tablet: touch-tuned desktop layout — targets are already ≥44px. */
    .bar {
      padding: 0.85rem 1rem;
    }
  }
  @media (max-width: 720px) {
    .burger {
      display: inline-flex;
    }
    /* The bar must never widen the page (S121 review, W4: at 375px its
       min-content width forced a ~560px body → sideways scroll). Truncate the
       handle, and let the account cluster wrap to a second line as the
       structural guarantee — vertical growth, never horizontal overflow. */
    .bar {
      padding: 0.85rem 1rem;
      gap: 0.35rem 0.75rem;
      min-width: 0;
      flex-wrap: wrap;
    }
    .bar-left {
      flex: none;
    }
    .acct {
      gap: 0.5rem;
      min-width: 0;
      flex: 0 1 auto;
    }
    .handle.account {
      min-width: 0;
    }
    .handle-text {
      min-width: 0;
      max-width: 34vw;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .signout {
      white-space: nowrap;
    }
    .nav-wrap {
      display: block;
      position: fixed;
      top: 0;
      bottom: 0;
      left: 0;
      z-index: 40;
      width: min(280px, 82vw);
      transform: translateX(-102%);
      transition: transform 0.2s ease;
      box-shadow: var(--shadow);
      overflow-y: auto;
    }
    .nav-wrap.open {
      transform: translateX(0);
    }
    .scrim.open {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 30;
      border: 0;
      background: rgba(0, 0, 0, 0.35);
    }
    .resizer {
      display: none;
    }
  }
</style>
