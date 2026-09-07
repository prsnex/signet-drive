<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // Recursive folder tree for the left-nav (§1-35). The expand state + the lazy
  // child fetch live on the Browser (so a future main-pane tree-table reuses
  // them); this component is purely the left-nav presentation. A chevron expands
  // a folder in place; clicking the name navigates into it.
  import type { Browser, Crumb, NamedFolder } from '$lib/browser.svelte';
  import { nodePath } from '$lib/folder-tree';
  import { m } from '$lib/paraglide/messages.js';
  import Chevron from './Chevron.svelte';
  import Self from './FolderTree.svelte';
  import { sortByName } from '$lib/folder-order';

  let {
    browser,
    folders,
    activeId,
    owned = false,
    ancestors = [],
    zebra = false,
  }: {
    browser: Browser;
    folders: NamedFolder[];
    activeId: string | null;
    /** bug101: whether these folders are OWNED by the signed-in account (the Private
     *  + owned-Share sections) vs shared *to* them (PRSN groups, Shared-with-you).
     *  Gates the ⋯ menu's Rename/Delete (owner-only, server-enforced). Propagates
     *  down the recursion — a subfolder inherits its root's ownership. Defaults
     *  false so a caller that omits it never wrongly enables owner actions. */
    owned?: boolean;
    /** Path from the hierarchy root down to these folders' parent; empty at the
     *  top level. Drives navigation + distinguishes a top-level zone from a
     *  nested expansion for the empty-state copy. */
    ancestors?: Crumb[];
    /** bug109: zebra-stripe the folder rows (white ↔ --bg, first white) — only in
     *  the PRIVATE + SHARE folder sections. Off in the PRSN groups (they take the
     *  lavender bug103 ladder) and Shared-with-you. Propagates down the recursion so
     *  a subfolder level stripes within itself. */
    zebra?: boolean;
  } = $props();

  // ── S209 (Chris): the panel's standard ordering ────────────────────────────
  // Sorted HERE rather than at each call site because this component recurses into
  // itself for every subfolder level — so one derived covers all four sections and
  // every depth. Sorting in Sidebar.svelte would have ordered only the top level of
  // each list and left `workspace`'s children in creation order, which is the case
  // that prompted the request.
  //
  // ⚠ A DERIVED COPY, never a sort in place: `folders` is the store's array
  // (browser.privateFolders, treeChildren.get(id), …) and sorting it in place would
  // mutate shared state from a presentation component.
  const sorted = $derived(sortByName(folders));
</script>

{#if folders.length}
  <ul class:zebra>
    {#each sorted as folder (folder.view.folder_id)}
      {@const id = folder.view.folder_id}
      {@const expanded = browser.treeExpanded.has(id)}
      {@const path = nodePath(folder, ancestors)}
      <li>
        <div class="row" class:active={id === activeId}>
          <button
            class="chev"
            aria-expanded={expanded}
            aria-label={expanded
              ? m.sidebar_collapse_folder({ name: folder.name })
              : m.sidebar_expand_folder({ name: folder.name })}
            onclick={() => browser.toggleTree(folder)}
          >
            <Chevron open={expanded} />
          </button>
          <button
            class="name"
            onclick={() => browser.openTreePath(path)}
            oncontextmenu={(e) => {
              e.preventDefault();
              browser.openContextMenu(e.clientX, e.clientY, { folder }, owned);
            }}>{folder.name}</button
          >
          <!-- bug101: the ⋯ actions menu — the tree is the ONLY place a top-level
               folder (unselectable in the main panel) can be renamed. -->
          <button
            class="node-menu"
            aria-label={m.sidebar_folder_actions()}
            onclick={(e) => {
              e.stopPropagation();
              const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
              browser.openContextMenu(r.left, r.bottom + 2, { folder }, owned);
            }}>⋯</button
          >
        </div>
        {#if expanded}
          <!-- bug226: THREE states, not two. `treeChildren.get(id)` is `undefined`
               when the node has never been fetched and `[]` when it was fetched and
               is genuinely empty. The old `?? []` collapsed those, so a node restored
               as expanded across a reload — expansion is persisted, children are not —
               fell through to the empty branch and asserted "No subfolders." while the
               main panel listed its contents.
               ⭐ A FAILED fetch is not a fourth state: the store COLLAPSES that node
               (Gus's ruling), so an expanded node is always loading, empty, or full —
               an open chevron over nothing is this same bug rendered in whitespace. -->
          {#if browser.treeLoading.has(id) || !browser.treeChildren.has(id)}
            <p class="loading">{m.sidebar_loading_subfolders()}</p>
          {:else if browser.treeChildren.has(id)}
            <div class="children">
              <Self
                {browser}
                folders={browser.treeChildren.get(id) ?? []}
                {activeId}
                {owned}
                {zebra}
                ancestors={path}
              />
            </div>
          {/if}
        {/if}
      </li>
    {/each}
  </ul>
{:else if ancestors.length === 0}
  <p class="empty">{m.sidebar_none_yet()}</p>
{:else}
  <p class="empty">{m.sidebar_no_subfolders()}</p>
{/if}

<style>
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 0.15rem;
    border-radius: var(--radius-sm);
  }
  /* bug109: zebra-stripe the folder rows in the PRIVATE + SHARE sections — the tint
     sits on the <li> so the row's own hover/active backgrounds still win on top. The
     list starts on white (odd = --surface), even rows step to --bg; full-bleed bands
     (the row content is inset by its own chevron/name padding). The selected-folder
     highlight is the accent left-bar (bug111 — box-shadow, no fill), so it adds zero
     colour over the neutral zebra and never collides with the PRSN --accent-soft alt. */
  ul.zebra > li {
    /* content inset so the chevron/name clear the card edge while the band itself
       stays full-bleed (the tint fills the padded <li>). */
    padding: 0 0.5rem;
  }
  ul.zebra > li:nth-child(even) {
    /* S209: BOTH rows are now the section's own hue at two strengths — set as
       --row-a / --row-b on the <section> in Sidebar.svelte. Previously the pair was
       white / --bg for every section, so a row belonged to the panel rather than to
       its section.
       ⭐ CSS variables rather than props, deliberately: FolderTree recurses into
       itself for every subfolder level, so a prop would have to be threaded through
       each one and a level that forgot it would stripe in another section's colour —
       invisible until someone opened a deep tree. Inheritance carries it for free.
       ⚠ Fallbacks are the OLD values, so a section that sets neither renders exactly
       as it does today rather than losing its stripe. */
    background: var(--row-b, var(--bg));
  }
  ul.zebra > li:nth-child(odd) {
    background: var(--row-a, var(--surface));
  }
  .row:hover {
    background: var(--surface-2);
  }
  /* bug111: the selected folder shows via an accent LEFT-BAR with NO background fill —
     the row keeps its own zebra bg (white / --bg / --accent-soft) so no purple is
     introduced in the neutral folder sections. Global on .row.active, so it covers the
     active-folder-inside-a-PRSN-block case too (bug103's scoped Sidebar rule is now
     redundant and removed). */
  .row.active {
    box-shadow: inset 3px 0 0 var(--accent);
    background: transparent;
    border-radius: 0;
  }
  /* The chevron's click target (the glyph itself is the <Chevron> SVG, which owns its
     size + rotate-on-open). A comfortable hit area sized to the row (Bug013); colour
     feeds the SVG via currentColor. */
  .chev {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.6rem;
    height: 1.7rem;
    border: 0;
    background: none;
    color: var(--muted);
    cursor: pointer;
    padding: 0;
  }
  .name {
    flex: 1;
    min-width: 0;
    text-align: left;
    border: 0;
    background: none;
    font: inherit;
    color: var(--ink-soft);
    padding: 0.4rem 0.3rem;
    cursor: pointer;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .row.active .name {
    color: var(--accent-text);
    font-weight: 600;
  }
  /* bug101: the per-folder ⋯ actions trigger — faint-always (discoverability), full
     on row/button hover. Right-click the folder name opens the same menu. */
  .node-menu {
    flex: none;
    border: 0;
    background: none;
    color: var(--muted);
    font-size: 1rem;
    line-height: 1;
    padding: 0 0.35rem;
    border-radius: 5px;
    cursor: pointer;
    opacity: 0.45;
  }
  .row:hover .node-menu,
  .node-menu:hover,
  .node-menu:focus-visible {
    opacity: 1;
  }
  .node-menu:hover {
    color: var(--ink-soft);
  }
  .row.active .chev {
    color: var(--accent-text);
  }
  /* Nested folders indent under their parent (the chevron column aligns the
     trail). */
  .children {
    padding-left: 0.9rem;
  }
  .empty,
  .loading {
    margin: 0;
    color: var(--muted);
    font-size: 0.85rem;
    padding: 0.2rem 0.3rem;
  }
</style>
