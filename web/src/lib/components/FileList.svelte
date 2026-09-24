<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import type { Browser, NamedFile, NamedFolder } from '$lib/browser.svelte';
  // bug196 item 3: the Modified column carries date AND time. Date alone made
  // every file uploaded today read identically, so sorting by Modified showed no
  // visible justification for its own order — the column could not explain its
  // sort. ⚠ formatDate itself is deliberately NOT changed: format.test.ts guards
  // it against exactly that refactor, protecting bug072's rule that a DEADLINE is
  // never a bare date. A modified time is not a deadline, so the caller moves and
  // the helper stays.
  import { formatBytes, formatDateTime, formatElapsed } from '$lib/format';
  import { uploadPhase, showUploadBar, uploadInFlightNote } from '$lib/upload-phase';
  import { tooltip } from '$lib/tooltip';
  import { m } from '$lib/paraglide/messages.js';
  import { IconFolder } from '$lib/components/icons';
  import { iconForFile } from '$lib/components/icons/iconForFile';
  import SealImpression from '$lib/seal/SealImpression.svelte';
  import { identitySeed, meSeed } from '$lib/seal/seed';

  let { browser }: { browser: Browser } = $props();

  let fileInput = $state<HTMLInputElement | null>(null);

  // bug075 item 1 — the honest first-part signal.
  //
  // ⛔ THE TRAP THIS IS BUILT AROUND: the obvious "fix" for 30 s of dead UI is a
  // moving bar, and a moving bar with nothing behind it is bug060 REBORN on the
  // exact surface a person stares at. So the rule here is that every element
  // rendered is a FACT: elapsed time is true, a completed-part count is true, and
  // a percentage is true only once parts have actually acknowledged. During the
  // silent stretch we therefore show NO BAR AND NO PERCENTAGE at all -- not a bar
  // sitting at zero, which is still a bar, and still unreadable as healthy or
  // broken.
  //
  // ⚠ The discriminator is already in the data and we did not have to invent it:
  // bug060 made `sentBytes` count COMPLETED PARTS ONLY, so `completedParts === 0`
  // means "nothing has acknowledged" by construction.
  let nowTick = $state(Date.now());
  $effect(() => {
    // Depends on the upload existing, so the interval lives exactly as long as the
    // readout it feeds and never ticks against an idle screen.
    if (!browser.uploadProgress) return;
    const id = setInterval(() => (nowTick = Date.now()), 1000);
    return () => clearInterval(id);
  });

  const single = $derived(browser.selectionCount === 1);
  const hasSelection = $derived(browser.selectionCount > 0);
  const hasFileSelection = $derived(browser.selectedFiles.size > 0);
  const folderInSelection = $derived(browser.selectedFolders.size > 0);
  const inFolder = $derived(browser.current !== null);

  // bug101: open the ⋯ / right-click actions menu (Rename + Delete) for a row's item.
  // Panel items live in the current root, so ownership is `browser.ownsCurrentRoot`.
  type RowItem = { file?: NamedFile; folder?: NamedFolder };
  function openRowMenuAt(e: MouseEvent, item: RowItem) {
    e.preventDefault();
    browser.openContextMenu(e.clientX, e.clientY, item, browser.ownsCurrentRoot);
  }
  function openRowMenuButton(e: MouseEvent, item: RowItem) {
    e.stopPropagation();
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    browser.openContextMenu(r.left, r.bottom + 2, item, browser.ownsCurrentRoot);
  }

  // A TEXT-ENTRY field (not every <input> — a focused row checkbox is an <input>
  // too, and ⌘A there should still select the listing, not be swallowed). Only
  // types where ⌘A means "select this field's text" should block the shortcut.
  const TEXT_INPUT_TYPES = new Set([
    'text',
    'search',
    'url',
    'email',
    'tel',
    'password',
    'number',
    'date',
    'datetime-local',
    'month',
    'week',
    'time',
  ]);
  function isTextEntry(el: HTMLElement): boolean {
    if (el.tagName === 'TEXTAREA' || el.isContentEditable) return true;
    if (el.tagName !== 'INPUT') return false;
    return TEXT_INPUT_TYPES.has((el.getAttribute('type') ?? 'text').toLowerCase());
  }

  /** bug055 — ⌘A/Ctrl+A selects the listing. Scoped: never while typing in a
   *  text field (its own text-selection wins), and never under an open dialog
   *  (a modal's own ⌘A wins). A focused row checkbox does NOT block it. */
  function onSelectAllKey(e: KeyboardEvent) {
    if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'a') return;
    const t = e.target as HTMLElement | null;
    if (t && isTextEntry(t)) return;
    if (browser.dialog) return;
    if (!inFolder) return;
    e.preventDefault();
    browser.selectAll();
  }
  // The signed-in identity's own seal (the empty-state hero is their drive).
  const ownSeed = $derived(meSeed(browser.me));

  function onPick(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    if (input.files && input.files.length) {
      void browser.uploadFiles(input.files);
    }
    input.value = '';
  }

  // ── Column sorting (row 18) ───────────────────────────────────────────────
  // Client-side, tri-state (asc → desc → none), persisted like the nav width.
  type SortCol = 'name' | 'size' | 'mod';
  const SORT_KEY = 'signet:file-sort';

  function loadSort(): { col: SortCol; dir: 'asc' | 'desc' } | null {
    if (typeof localStorage === 'undefined') return null;
    try {
      const s = JSON.parse(localStorage.getItem(SORT_KEY) ?? 'null');
      if (
        s &&
        (s.col === 'name' || s.col === 'size' || s.col === 'mod') &&
        (s.dir === 'asc' || s.dir === 'desc')
      ) {
        return s;
      }
    } catch {
      /* ignore malformed */
    }
    return null;
  }

  let sort = $state<{ col: SortCol; dir: 'asc' | 'desc' } | null>(loadSort());

  function toggleSort(col: SortCol) {
    if (!sort || sort.col !== col) sort = { col, dir: 'asc' };
    else if (sort.dir === 'asc') sort = { col, dir: 'desc' };
    else sort = null;
    if (typeof localStorage !== 'undefined') {
      if (sort) localStorage.setItem(SORT_KEY, JSON.stringify(sort));
      else localStorage.removeItem(SORT_KEY);
    }
  }

  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  function cmp(a: { name: string; mod: number; size: number }, b: typeof a): number {
    if (!sort) return 0;
    const dir = sort.dir === 'asc' ? 1 : -1;
    const c =
      sort.col === 'name'
        ? collator.compare(a.name, b.name)
        : sort.col === 'size'
          ? a.size - b.size
          : a.mod - b.mod;
    return c * dir;
  }

  const sortedFolders = $derived(
    sort
      ? [...browser.childFolders].sort((x, y) =>
          cmp(
            { name: x.name, mod: x.view.modified_at, size: 0 },
            { name: y.name, mod: y.view.modified_at, size: 0 },
          ),
        )
      : browser.childFolders,
  );
  const sortedFiles = $derived(
    sort
      ? [...browser.files].sort((x, y) =>
          cmp(
            {
              name: x.name,
              mod: x.view.modified_at,
              size: x.view.plaintext_bytes ?? x.view.size_bytes,
            },
            {
              name: y.name,
              mod: y.view.modified_at,
              size: y.view.plaintext_bytes ?? y.view.size_bytes,
            },
          ),
        )
      : browser.files,
  );

  const ariaSort = (col: SortCol): 'ascending' | 'descending' | 'none' =>
    sort?.col === col ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none';

  // ── Drag-and-drop upload (row 17; desktop/tablet) ─────────────────────────
  let dragOver = $state(false);
  const hasFiles = (e: DragEvent) =>
    !!e.dataTransfer && [...e.dataTransfer.types].includes('Files');

  function onDragOver(e: DragEvent) {
    if (!inFolder || browser.busy || !hasFiles(e)) return;
    e.preventDefault();
    dragOver = true;
  }
  function onDragLeave(e: DragEvent) {
    // Ignore leave events fired while moving over a child element.
    const to = e.relatedTarget as Node | null;
    if (!to || !(e.currentTarget as HTMLElement).contains(to)) dragOver = false;
  }
  function onDrop(e: DragEvent) {
    dragOver = false;
    // bug223 F1 (Gus): the DROP TARGET is the second upload surface and carried
    // the identical guard. `multipart::initiate` refuses a non-`read_write`
    // recipient with 404 "folder not found", so a read_only recipient could drop
    // files and be told the folder does not exist. Gating the button alone would
    // have fixed one of two surfaces — the per-surface lesson, again.
    if (!inFolder || browser.busy || !browser.canWriteCurrentRoot) return;
    e.preventDefault();
    const files = e.dataTransfer?.files;
    if (files && files.length) void browser.uploadFiles(files);
  }

  // ── bug196 item 1: the toolbar stays, the list scrolls ────────────────────
  // The whole top block used to scroll away, taking the breadcrumb, the actions
  // AND the column headers with it — so a long folder left you with unlabelled
  // columns and no way to act without scrolling back.
  //
  // ⚠ Not everything is pinned, deliberately. The full block is ~260 px: about a
  // fifth of a large display but roughly a THIRD of a 13" laptop viewport, gone
  // permanently. Pinned: breadcrumb, actions, column row. Scrolling: the transient
  // notices and progress banners — pinning those would shove the list down and pop
  // it back on every download.
  //
  // The Guardian context banner is the deliberate middle case: it stays visible
  // because "you're in someone else's folder, read-write as Guardian" is exactly
  // the context you least want scrolled away while deleting files — but it
  // COMPACTS once you scroll, so it costs a line rather than a block.
  let listingEl = $state<HTMLElement | null>(null);
  let scrolled = $state(false);
  function onListingScroll() {
    if (listingEl) scrolled = listingEl.scrollTop > 8;
  }
</script>

<svelte:window onkeydown={onSelectAllKey} />

<!-- The whole file pane is an upload drop target. Drag-and-drop has no keyboard
     equivalent; the accessible upload path is the Upload button + the file input,
     so the static-interaction rule is intentionally waived here. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<section class="main" ondragover={onDragOver} ondragleave={onDragLeave} ondrop={onDrop}>
  {#if dragOver}
    <div class="drop-overlay" aria-hidden="true">{m.filelist_drop_hint()}</div>
  {/if}
  <nav class="crumbs" aria-label={m.filelist_breadcrumb()}>
    <button class="crumb" onclick={() => browser.goHome()}>{m.filelist_home()}</button>
    {#each browser.path as crumb, i (crumb.folderId)}
      <span class="sep">/</span>
      <button class="crumb" onclick={() => browser.navigateTo(i)}>{crumb.name}</button>
    {/each}
  </nav>

  {#if browser.currentPrsnOwner}
    <p class="prsn-context" class:compact={scrolled}>
      <SealImpression seed={identitySeed(null, browser.currentPrsnOwner.handle)} size={20} />
      {m.filebrowser_prsn_folder_context({ handle: browser.currentPrsnOwner.handle ?? '—' })}
    </p>
  {/if}

  <div class="toolbar">
    <!-- Standing actions: always present, never disabled-gray as a group. -->
    <!-- bug223 F1: upload gates on WRITE authority, not on ownership and not on
         nothing. `multipart::initiate` allows a `read_write` recipient (bug038) and
         refuses a `read_only` one with 404 "folder not found" — offered, always
         failing, lying about existence: the bug223 shape exactly. -->
    <span
      class="tipwrap"
      use:tooltip={!browser.canWriteCurrentRoot ? m.filelist_upload_read_only() : ''}
    >
      <button
        class="primary"
        disabled={!inFolder || browser.busy || !browser.canWriteCurrentRoot}
        onclick={() => fileInput?.click()}
      >
        {m.filelist_upload()}
      </button>
    </span>
    <!-- bug223: the server refuses a non-owner's folder-create (folders.rs resolves
         the parent with `account_id = you`, so a recipient gets 404 "parent folder
         not found"). Offering the button anyway produced a dialog that always failed,
         under a banner promising read-write.
         ⚠⚠ An earlier version of this comment read "Upload stays enabled: that one
         the server really does allow a read_write recipient" — TRUE of the
         `read_write` column and false of the `read_only` one, which is the whole
         bug223 class committed inside bug223's own fix (Gus, F1). Upload now gates
         on `canWriteCurrentRoot` too; see the Upload button below. -->
    <span
      class="tipwrap"
      use:tooltip={!browser.ownsCurrentRoot ? m.filelist_new_folder_not_owner() : ''}
    >
      <button
        disabled={!inFolder || browser.busy || !browser.ownsCurrentRoot}
        onclick={() => browser.openNewFolder(false)}
      >
        {m.filelist_new_folder()}
      </button>
    </span>
    {#if browser.currentShareRole}
      <button disabled={browser.busy} onclick={() => browser.openSharePanel()}>
        {browser.currentShareRole === 'owner' ? m.filelist_share() : m.filelist_sharing()}
      </button>
    {/if}
    <!-- Selection actions: exist only when a selection does, led by a count chip —
         so the disabled-row cluster disappears (buttons keep their per-action rules). -->
    {#if hasSelection}
      <span class="sel-actions">
        <span class="sel-chip">{m.filelist_selected_count({ count: browser.selectionCount })}</span>
        <!-- bug055 (the decided mixed-selection rule): Download DISABLES when the
             selection includes folders rather than silently downloading only the
             files — a storage product that quietly does part of what you asked
             erodes trust. The wrapper span carries the explanation (bug056),
             because a disabled button swallows hover events. -->
        <span
          class="tipwrap"
          use:tooltip={folderInSelection && hasFileSelection
            ? m.filelist_download_folders_hint()
            : ''}
        >
          <button
            disabled={!hasFileSelection || folderInSelection || browser.busy}
            onclick={() => browser.downloadSelected()}
          >
            {m.filelist_download()}
          </button>
        </span>
        <!-- bug101 + bug223: Rename and Move are owner-only (server-enforced,
             account_id = you) and disable for any recipient. DELETE IS NOT: the
             server grants a `read_write` recipient delete authority
             (sharing::folder_authority, bug208 §3b), so it gates on
             `canWriteCurrentRoot` and stays enabled for a Guardian inside a PRSN's
             folder. The reason goes on the wrapper (a disabled button swallows
             hover). Download stays — a recipient can read. -->
        <span
          class="tipwrap"
          use:tooltip={!browser.ownsCurrentRoot ? m.filelist_action_not_owner() : ''}
        >
          <button
            disabled={!single || browser.busy || !browser.ownsCurrentRoot}
            onclick={() => browser.openRename()}>{m.filelist_rename()}</button
          >
        </span>
        <span
          class="tipwrap"
          use:tooltip={!browser.ownsCurrentRoot ? m.filelist_action_not_owner() : ''}
        >
          <button
            disabled={browser.moveTargets.length === 0 || browser.busy || !browser.ownsCurrentRoot}
            onclick={() => browser.openMove()}
          >
            {m.filelist_move()}
          </button>
        </span>
        <span
          class="tipwrap"
          use:tooltip={!browser.canDeleteSelection
            ? browser.selectedFolders.size > 0
              ? m.filelist_delete_folder_not_owner()
              : m.filelist_action_read_only()
            : ''}
        >
          <button
            class="danger"
            disabled={browser.busy || !browser.canDeleteSelection}
            onclick={() => browser.openConfirmDelete()}
          >
            {m.filelist_delete()}
          </button>
        </span>
      </span>
    {/if}
  </div>

  <!-- bug196 item 1: the LIST scrolls, the toolbar above it does not. Making the
       toolbar a sticky child of one big scroller would need its height threaded
       into the header offset; moving it OUT of the scroller removes the offset
       problem entirely and lets the column row stick at top:0 of its own box. -->
  <div class="listing" bind:this={listingEl} onscroll={onListingScroll}>
    <input
      bind:this={fileInput}
      type="file"
      multiple
      class="hidden-input"
      onchange={onPick}
      aria-hidden="true"
      tabindex="-1"
    />

    {#if browser.error && !browser.dialog}
      <p class="error">{browser.error}</p>
    {/if}

    {#if browser.downloaded && !browser.dialog}
      <p class="notice" role="status" aria-live="polite">
        <!-- bug187 §2: name the LOCATION only on the fallback path, which genuinely
           files into the browser's download directory. On the streaming path the
           user chose the destination, so we name the file and nothing else. -->
        {#if browser.downloaded.count > 1}
          {browser.downloaded.chose
            ? m.filelist_downloaded_many_chosen({ count: String(browser.downloaded.count) })
            : m.filelist_downloaded_many({ count: String(browser.downloaded.count) })}
        {:else}
          {browser.downloaded.chose
            ? m.filelist_downloaded_one_chosen({ fileName: browser.downloaded.fileName })
            : m.filelist_downloaded_one({ fileName: browser.downloaded.fileName })}
        {/if}
      </p>
    {/if}

    {#if browser.uploadProgress}
      {@const p = browser.uploadProgress}
      {@const pct = p.totalBytes > 0 ? Math.round((p.sentBytes / p.totalBytes) * 100) : 0}
      {@const phase = uploadPhase(p)}
      <!-- ⛔ THE BAR EXISTS IF AND ONLY IF A PART HAS ACKNOWLEDGED, and the decision
         lives in `$lib/upload-phase` so it is testable against records the real
         transfer path emits rather than against fixtures. There is exactly ONE bar
         element below and exactly ONE guard on it; `upload-phase.test.ts` asserts
         both statically, because the render-level promise ("no bar, no percent")
         cannot be proven by a unit test of the decision alone. -->
      {@const showBar = showUploadBar(p)}
      <!-- F3: the in-flight note is a pure function of transfer state too: nothing,
         a neutral count, or count + MEASURED rate + "about N left" — the rate only
         once a part has completed on this Drive (the bootstrap seed never shows). -->
      {@const inflight = uploadInFlightNote(p)}
      <div class="transfer-progress" role="status" aria-live="polite">
        <div class="transfer-progress-label">
          {#if p.paused}
            {m.filelist_upload_paused({ fileName: p.pausedFiles[0]?.fileName ?? p.fileName })}
          {:else}
            {#if phase === 'encrypting'}
              {m.filelist_upload_encrypting({ fileName: p.fileName })}
            {:else if phase === 'starting'}
              <!-- The silent stretch: a phase label and a CLOCK, and no percentage
                 anywhere -- `showBar` above suppresses the bar for the same reason. -->
              {m.filelist_upload_starting({ elapsed: formatElapsed(nowTick - p.startedAt) })}
            {:else if phase === 'completing'}
              {m.filelist_upload_completing({ fileName: p.fileName })}
            {:else if p.filesOpen > 1}
              <!-- F2: several files are open on the shared slots; the per-file rows
                 collapse to the range. F3-d: the COUNT leads, because files finish
                 out of order and "12–16" alone reads as five when four are open
                 ("Uploading 4 files (12–16 of 30)"). -->
              {m.filelist_uploading_batch({
                open: p.filesOpen,
                first: p.firstOpenIndex + 1,
                last: p.lastOpenIndex + 1,
                count: p.fileCount,
                pct,
              })}
            {:else}
              {p.fileCount > 1
                ? m.filelist_uploading_multi({
                    index: p.firstOpenIndex + 1,
                    count: p.fileCount,
                    fileName: p.fileName,
                    pct,
                  })
                : m.filelist_uploading({ fileName: p.fileName, pct })}
            {/if}
            <!-- ⚠ THE THREE NOTES BELOW SIT OUTSIDE THE PHASE BRANCHES, DELIBERATELY.
               An earlier draft of this change nested them inside the "uploading"
               branch and thereby dropped the capacity note during the SILENT
               STRETCH -- which is the single state where it matters most: a first
               part refused with `503 relay-at-capacity` is exactly the case a user
               cannot otherwise distinguish from a hang. That is bug075's own defect,
               reintroduced by the change meant to fix it. -->
            {#if inflight.kind === 'neutral'}
              <!-- F3: parts are being sent and nothing has completed yet on this Drive
                 (or a rate is not yet a fact): the COUNT is true, so say only that.
                 This is the two-minute silence of a single 16 MiB first part, made
                 legible without inventing a rate. -->
              <span class="part-note"
                >{m.filelist_upload_inflight({
                  count: inflight.inFlight,
                  total: inflight.total,
                })}</span
              >
            {:else if inflight.kind === 'measured'}
              <span class="part-note"
                >{m.filelist_upload_inflight_measured({
                  count: inflight.inFlight,
                  total: inflight.total,
                  mbps: inflight.mbps,
                  eta: formatElapsed(inflight.etaSeconds * 1000),
                })}</span
              >
            {/if}
            {#if p.suspensions > 0}
              <!-- F4: the page was suspended with parts in flight (display sleep, a
                 hidden tab) and the transfer resumed on wake — a fact, stated. -->
              <span class="part-note"
                >{m.filelist_upload_suspended_resumed({ count: p.suspensions })}</span
              >
            {/if}
            {#if p.totalParts > 1 && p.completedParts > 0}
              <!-- bug075 §5.1: honest DETERMINATE progress at part granularity — on a
                 slow link the byte bar can sit at 0% for a whole first part while
                 the transfer is genuinely working; the part counter is the truthful
                 signal (real state, never fabricated byte-progress — bug060). -->
              <span class="part-note"
                >{m.filelist_upload_part_progress({
                  done: p.completedParts,
                  total: p.totalParts,
                })}</span
              >
            {/if}
            {#if p.waitingForCapacitySeconds !== null}
              <!-- Coverage row 18 (bug075): the server refused a part with
                 `503 relay-at-capacity` and named a Retry-After. Without this
                 the bar simply freezes, and a frozen bar is unreadable: a
                 person cannot tell "waiting, healthy, resumes itself" from
                 "broken, do something". That indistinguishability IS bug075.
                 ⚠ Deliberately NOT the `paused` branch — paused owes the user a
                 decision (press Resume); this owes them nothing but the truth,
                 so it rides alongside live progress rather than replacing it. -->
              <span class="waiting-note"
                >{m.filelist_upload_waiting_capacity({
                  seconds: p.waitingForCapacitySeconds,
                })}</span
              >
            {/if}
            {#if p.retries > 0}
              <span class="retry-note">{m.filelist_upload_retrying({ count: p.retries })}</span>
            {/if}
          {/if}
        </div>
        {#if showBar}
          <div class="bar" aria-hidden="true">
            <div class="fill" class:paused={p.paused} style="width: {pct}%"></div>
          </div>
        {/if}
        {#each p.pausedFiles as pf (pf.fileIndex)}
          <!-- F2 §2.7: a file paused on a bad window owes the user a decision for
             THAT file; the batch's other files keep the slots meanwhile. When the
             batch is one file this is the pre-F2 Resume row exactly. -->
          <div class="paused-actions">
            {#if !p.paused || p.pausedFiles.length > 1}
              <!-- The row carries its file's name whenever the label above cannot
                 stand for it alone: the batch still moving, or two files paused
                 at once (Gus, review). -->
              <span class="part-note">{m.filelist_upload_paused({ fileName: pf.fileName })}</span>
            {/if}
            <button class="primary" onclick={() => browser.resumeUpload(pf.fileIndex)}>
              {m.filelist_upload_resume()}
            </button>
            {#if p.fileCount > 1}
              <button onclick={() => browser.cancelUploadFile(pf.fileIndex)}>
                {m.filelist_upload_cancel_file()}
              </button>
            {/if}
          </div>
        {/each}
        <!-- bug076: Cancel must exist DURING the active transfer — the prior UI
           offered it only when paused, so on exactly the slow link where a user
           reaches for Cancel there was no button at all. Cancel-only, no Pause
           (Chris, S142). Under F2 it cancels the whole batch (§2.6). -->
        <div class="paused-actions">
          <button onclick={() => browser.cancelUpload()}>
            {m.filelist_upload_cancel()}
          </button>
        </div>
      </div>
    {/if}

    {#if browser.downloadProgress}
      {@const d = browser.downloadProgress}
      {@const pct = d.totalBytes > 0 ? Math.round((d.receivedBytes / d.totalBytes) * 100) : 0}
      <div class="transfer-progress" role="status" aria-live="polite">
        <div class="transfer-progress-label">
          {m.filelist_downloading({ fileName: d.fileName, pct })}
        </div>
        <div class="bar" aria-hidden="true">
          <div class="fill" style="width: {pct}%"></div>
        </div>
      </div>
    {/if}

    {#if !inFolder}
      <div class="empty-hero">
        <SealImpression seed={ownSeed} size={44} />
        <p class="empty-title">{m.filelist_empty_title()}</p>
        <p class="empty-zeroaccess">{m.filelist_empty_zeroaccess()}</p>
        <p class="empty-guide">{browser.isPrsn ? m.filelist_empty_prsn() : m.filelist_empty()}</p>
      </div>
    {:else if browser.childFolders.length === 0 && browser.files.length === 0}
      <div class="empty-folder">
        <p class="empty-folder-title">{m.filelist_folder_empty()}</p>
        <p class="empty-folder-hint">{m.filelist_folder_empty_hint()}</p>
        <button class="empty-upload" disabled={browser.busy} onclick={() => fileInput?.click()}>
          {m.filelist_upload()}
        </button>
      </div>
    {:else}
      <table>
        <thead>
          <tr>
            <th class="check" aria-label={m.filelist_select_col()}>
              <!-- bug055: tri-state select-all — indeterminate on a partial
                 selection; checked → clears. Deselect-all comes free. -->
              <input
                type="checkbox"
                checked={browser.allSelected}
                indeterminate={hasSelection && !browser.allSelected}
                onchange={() =>
                  browser.allSelected ? browser.clearSelection() : browser.selectAll()}
                aria-label={m.filelist_select_all()}
              />
            </th>
            <th aria-sort={ariaSort('name')}>
              <button
                class="sort"
                class:active={sort?.col === 'name'}
                onclick={() => toggleSort('name')}
              >
                {m.filelist_col_name()}<span
                  class="arrow"
                  class:idle={sort?.col !== 'name'}
                  aria-hidden="true"
                  >{sort?.col === 'name' ? (sort.dir === 'asc' ? '↑' : '↓') : '↕'}</span
                >
              </button>
            </th>
            <th class="size" aria-sort={ariaSort('size')}>
              <button
                class="sort"
                class:active={sort?.col === 'size'}
                onclick={() => toggleSort('size')}
              >
                {m.filelist_col_size()}<span
                  class="arrow"
                  class:idle={sort?.col !== 'size'}
                  aria-hidden="true"
                  >{sort?.col === 'size' ? (sort.dir === 'asc' ? '↑' : '↓') : '↕'}</span
                >
              </button>
            </th>
            <th class="mod" aria-sort={ariaSort('mod')}>
              <button
                class="sort"
                class:active={sort?.col === 'mod'}
                onclick={() => toggleSort('mod')}
              >
                {m.filelist_col_modified()}<span
                  class="arrow"
                  class:idle={sort?.col !== 'mod'}
                  aria-hidden="true"
                  >{sort?.col === 'mod' ? (sort.dir === 'asc' ? '↑' : '↓') : '↕'}</span
                >
              </button>
            </th>
            <th class="rowmenu" aria-label={m.filelist_actions_col()}></th>
          </tr>
        </thead>
        <tbody>
          {#each sortedFolders as folder (folder.view.folder_id)}
            <tr
              class:selected={browser.selectedFolders.has(folder.view.folder_id)}
              oncontextmenu={(e) => openRowMenuAt(e, { folder })}
            >
              <td class="check">
                <input
                  type="checkbox"
                  checked={browser.selectedFolders.has(folder.view.folder_id)}
                  onchange={() => browser.toggleFolder(folder.view.folder_id)}
                  aria-label={m.filelist_select_folder({ name: folder.name })}
                />
              </td>
              <td>
                <button class="name folder" onclick={() => browser.openChild(folder)}>
                  <span class="icon folder-icon" aria-hidden="true"><IconFolder size={18} /></span>
                  <span class="fname"
                    >{folder.name}<span class="meta2"
                      >{formatDateTime(folder.view.modified_at)}</span
                    ></span
                  >
                </button>
              </td>
              <td class="size">—</td>
              <td class="mod">{formatDateTime(folder.view.modified_at)}</td>
              <td class="rowmenu">
                <button
                  class="menu-btn"
                  aria-label={m.filelist_actions_menu()}
                  onclick={(e) => openRowMenuButton(e, { folder })}>⋯</button
                >
              </td>
            </tr>
          {/each}
          {#each sortedFiles as file (file.view.file_id)}
            {@const FileIcon = iconForFile(file.name)}
            <tr
              class:selected={browser.selectedFiles.has(file.view.file_id)}
              oncontextmenu={(e) => openRowMenuAt(e, { file })}
            >
              <td class="check">
                <input
                  type="checkbox"
                  checked={browser.selectedFiles.has(file.view.file_id)}
                  onchange={() => browser.toggleFile(file.view.file_id)}
                  aria-label={m.filelist_select_file({ name: file.name })}
                />
              </td>
              <td>
                <button class="name" onclick={() => browser.toggleFile(file.view.file_id)}>
                  <span class="icon" aria-hidden="true"><FileIcon size={18} /></span>
                  <span class="fname"
                    >{file.name}<span class="meta2"
                      >{formatBytes(file.view.plaintext_bytes ?? file.view.size_bytes)} · {formatDateTime(
                        file.view.modified_at,
                      )}</span
                    ></span
                  >
                </button>
              </td>
              <td class="size">{formatBytes(file.view.plaintext_bytes ?? file.view.size_bytes)}</td>
              <td class="mod">{formatDateTime(file.view.modified_at)}</td>
              <td class="rowmenu">
                <button
                  class="menu-btn"
                  aria-label={m.filelist_actions_menu()}
                  onclick={(e) => openRowMenuButton(e, { file })}>⋯</button
                >
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</section>

<style>
  .main {
    position: relative;
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    padding: 1.25rem 1.5rem;
    /* bug196 item 1: the PANE no longer scrolls — .listing does. That is what
       lets the toolbar above it stay put without threading its height into a
       sticky offset, and lets the column row stick at top:0 of its own box. */
    overflow: hidden;
  }
  .listing {
    flex: 1;
    min-height: 0; /* without this a flex child refuses to shrink and never scrolls */
    overflow-y: auto;
  }
  .crumbs {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
  }
  .crumb {
    border: 0;
    background: none;
    font: inherit;
    color: var(--ink-soft);
    cursor: pointer;
    padding: 0.1rem 0.2rem;
    border-radius: 6px;
  }
  .crumb:last-child {
    color: var(--ink);
    font-weight: 600;
  }
  .crumb:hover {
    color: var(--accent);
  }
  .sep {
    color: var(--muted);
  }
  /* Context banner when the Guardian is inside a PRSN's folder (Bug009 Q2): the
     Guardian has read-write here, so make whose space this is unmistakable. */
  .prsn-context {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0 0 0.85rem;
    padding: 0.5rem 0.75rem;
    background: var(--accent-soft);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius-sm);
    color: var(--ink-soft);
    font-size: 0.85rem;
  }
  /* bug196 item 1: once the list scrolls, this shrinks to a single tight line
     rather than disappearing. It is a SAFETY affordance — the sentence telling
     you these are someone else's files, editable as their Guardian — so it is
     the one piece of context deliberately kept on screen while you act. Costing
     a whole block for it would be too much; costing a line is right. */
  .prsn-context.compact {
    margin-bottom: 0.5rem;
    padding: 0.2rem 0.6rem;
    font-size: 0.78rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
  }
  .toolbar button {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.88rem;
    padding: 0.42rem 0.85rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .toolbar button:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .toolbar button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .toolbar .primary {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--on-accent);
    font-weight: 600;
  }
  .toolbar .primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .toolbar .danger:hover:not(:disabled) {
    border-color: var(--danger);
    color: var(--danger);
  }
  .sel-actions {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  /* Zero-footprint tooltip carrier for a disabled button (disabled elements
     swallow hover, so the explanation rides the wrapper — bug055/bug056). */
  .tipwrap {
    display: inline-flex;
  }
  .sel-chip {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--accent-text);
    background: var(--accent-soft);
    border-radius: 999px;
    padding: 0.22rem 0.65rem;
  }
  .hidden-input {
    display: none;
  }
  .error {
    margin: 0 0 1rem;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  .notice {
    margin: 0 0 1rem;
    padding: 0.6rem 0.75rem;
    background: var(--accent-soft);
    color: var(--ink);
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  .transfer-progress {
    margin: 0 0 1rem;
    padding: 0.6rem 0.75rem;
    background: var(--surface);
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
  }
  .transfer-progress-label {
    font-size: 0.85rem;
    color: var(--ink-soft);
    margin-bottom: 0.4rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .transfer-progress .bar {
    height: 6px;
    background: var(--bg);
    border-radius: 3px;
    overflow: hidden;
  }
  .transfer-progress .fill {
    height: 100%;
    background: var(--accent);
    border-radius: 3px;
    transition: width 0.2s ease;
  }
  .transfer-progress .fill.paused {
    background: var(--ink-soft);
  }
  .transfer-progress .retry-note,
  .transfer-progress .waiting-note,
  .transfer-progress .part-note {
    margin-left: 0.5rem;
    color: var(--ink-soft);
    font-size: 0.8rem;
  }
  .transfer-progress .paused-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
  .empty-hero,
  .empty-folder {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: 0.5rem;
    padding: 3rem 1rem;
  }
  .empty-title {
    font-family: var(--font-serif);
    font-size: var(--text-2xl);
    color: var(--ink);
    margin: 0;
  }
  .empty-zeroaccess {
    max-width: 32rem;
    color: var(--ink-soft);
    font-size: var(--text-sm);
    margin: 0;
  }
  .empty-guide {
    color: var(--muted);
    font-size: var(--text-xs);
    margin: 0.4rem 0 0;
  }
  .empty-folder-title {
    font-family: var(--font-serif);
    font-size: var(--text-lg);
    color: var(--ink-soft);
    margin: 0;
  }
  .empty-folder-hint {
    color: var(--muted);
    font-size: var(--text-sm);
    margin: 0;
  }
  .empty-upload {
    margin-top: 0.4rem;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: var(--text-sm);
    padding: 0.42rem 0.9rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .empty-upload:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .empty-upload:disabled {
    opacity: 0.5;
    cursor: default;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.92rem;
  }
  thead th {
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.8rem;
    padding: 0.4rem 0.6rem;
    border-bottom: 1px solid var(--border);
    /* bug196 item 1: the column row stays put while the list scrolls under it.
       An opaque background is required, not cosmetic — rows would otherwise
       show through it. */
    position: sticky;
    top: 0;
    z-index: 2;
    background: var(--bg);
  }
  th.size,
  td.size {
    width: 6rem;
  }
  th.mod,
  td.mod {
    /* Widened for date + time (bug196 item 3). 8rem fitted a bare date and would
       wrap "Aug 14, 2026, 5:14 PM". */
    width: 11rem;
    color: var(--muted);
  }
  th.check,
  td.check {
    width: 2.2rem;
    text-align: center;
  }
  th.rowmenu,
  td.rowmenu {
    width: 2.4rem;
    text-align: center;
  }
  /* bug101: the always-visible per-row ⋯ actions trigger (a visible affordance is
     the discoverability fix) — muted until the row or button is hovered. Right-click
     anywhere on the row opens the same menu. */
  .menu-btn {
    border: 0;
    background: none;
    color: var(--muted);
    font-size: 1.1rem;
    line-height: 1;
    padding: 0.2rem 0.45rem;
    border-radius: 5px;
    cursor: pointer;
    opacity: 0.55;
  }
  tbody tr:hover .menu-btn,
  .menu-btn:hover,
  .menu-btn:focus-visible {
    opacity: 1;
  }
  .menu-btn:hover {
    background: var(--surface-2);
    color: var(--ink-soft);
  }
  tbody td {
    padding: 0.35rem 0.6rem;
    height: 44px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  td.size,
  td.mod {
    font-variant-numeric: tabular-nums;
  }
  tbody tr:hover td {
    background: var(--surface-2);
  }
  tbody tr.selected td {
    background: var(--accent-soft);
  }
  tbody tr.selected td:first-child {
    box-shadow: inset 2px 0 0 var(--accent);
  }
  .name {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    border: 0;
    background: none;
    font: inherit;
    color: var(--ink);
    cursor: pointer;
    text-align: left;
    padding: 0.15rem 0;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name.folder {
    font-weight: 500;
  }
  .name:hover {
    color: var(--accent);
  }
  .icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    color: var(--muted);
  }
  .folder-icon {
    /* Folders carry the accent tint (§1.5); files stay muted. */
    color: var(--accent-text);
    opacity: 0.85;
  }
  .fname {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sort {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    border: 0;
    background: none;
    font: inherit;
    color: inherit;
    cursor: pointer;
    padding: 0;
  }
  /* ⚠ bug196 item 2: hover STRENGTHENS. This used to set --ink-soft — i.e. it made
     the label FAINTER — so the only feedback we gave for a sortable header read as
     "disabled". That was half the reason sorting was invisible. */
  .sort:hover,
  .sort:focus-visible {
    color: var(--ink);
  }
  /* The active column reads heavier by CONTRAST, never by font-weight: bolding
     changes the text's metrics, so the header would shift and neighbouring columns
     jitter every time the sort moved. */
  .sort.active {
    color: var(--ink);
  }
  .arrow {
    color: var(--accent-text);
    font-size: 0.85em;
  }
  /* Every sortable header shows a muted ↕ AT REST, so it reads as sortable before
     anyone touches it. The arrow used to render only on the active column, leaving
     Name and Modified looking like plain text — sorting was fully implemented,
     persisted and accessible, and simply could not be found. The evidence it was a
     real defect rather than polish: Chris asked for it as a NEW FEATURE. */
  .arrow.idle {
    color: var(--ink-soft);
    opacity: 0.45;
  }
  .sort:hover .arrow.idle,
  .sort:focus-visible .arrow.idle {
    opacity: 1;
  }
  /* The meta line is a mobile-only second row; hidden while the size/modified
     columns are shown. */
  .meta2 {
    display: none;
  }
  .drop-overlay {
    position: absolute;
    inset: 0.75rem;
    z-index: 5;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 2px dashed var(--accent);
    border-radius: var(--radius);
    background: color-mix(in srgb, var(--accent-soft) 82%, transparent);
    color: var(--accent-text);
    font-weight: 600;
    pointer-events: none;
  }
  @media (max-width: 720px) {
    th.size,
    td.size,
    th.mod,
    td.mod {
      display: none;
    }
    tbody td {
      height: 52px;
    }
    .name {
      align-items: flex-start;
    }
    .name .icon {
      margin-top: 0.15rem;
    }
    .fname {
      display: flex;
      flex-direction: column;
      white-space: normal;
    }
    .meta2 {
      display: block;
      margin-top: 0.1rem;
      font-size: var(--text-xs);
      color: var(--muted);
      font-variant-numeric: tabular-nums;
    }
  }
</style>
