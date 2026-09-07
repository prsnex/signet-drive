<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { createApiClient } from '$lib/api';
  import type { Browser } from '$lib/browser.svelte';
  import { formatBytes } from '$lib/format';
  import { prsnStateTag } from '$lib/garnet';
  import { m } from '$lib/paraglide/messages.js';
  import Chevron from './Chevron.svelte';
  import FolderTree from './FolderTree.svelte';
  import { compareDisplayNames } from '$lib/folder-order';
  import { loadPrsnSectionPref, prsnSectionVisible } from '$lib/prsn-section';
  import SealImpression from '$lib/seal/SealImpression.svelte';

  let { browser }: { browser: Browser } = $props();

  // ── The deployed SERVER version, as a quiet diagnostic (S203, Chris's ask) ──
  // He asked to be able to read the running version off the screen instead of
  // curling /v1/server-info.
  //
  // ⛔ LABELLED "server", never a bare number, and that is the whole point.
  // The web has three ends — server, bundle, service worker — and they DIVERGE
  // exactly when you would most want to look: right after a deploy, when the
  // browser may still be holding the previous bundle. A bare number in the corner
  // would then report the server's NEW version beside the OLD UI, and be trusted.
  // Saying which end it reports costs one word and removes the ambiguity.
  // (What the browser actually loaded is a separate question and deliberately not
  // answered here: web/package.json is "0.0.0" and does not track the release, so
  // reporting it would need the release bump procedure to change.)
  //
  // ⚠ FAIL-SILENT on purpose. This is a diagnostic, not a feature: if the fetch
  // fails the label simply does not render. A version line that could show an
  // error state would make the sidebar's health depend on an ornament.
  let serverVersion = $state<string | null>(null);
  onMount(async () => {
    try {
      const info = await createApiClient().getServerInfo();
      serverVersion = info.version ?? null;
    } catch {
      serverVersion = null; // diagnostic only — never surfaces as an error
    }
  });

  // Highlight the folder currently open in the main pane, at whatever depth.
  const activeId = $derived(browser.path.at(-1)?.folderId ?? null);

  // ── bug213 part 2: the active folder must never be left out of view ────────
  // Part 1 made the column scroll; scrolling introduces its own way to lose the
  // active row — expanding a section pushes it below the fold instead of
  // clipping it. Same symptom for the user, different route.
  //
  // ⚠ `block: 'nearest'` is load-bearing, not a default: it is a NO-OP when the
  // row is already visible, so this corrects only the broken case. A centring
  // scroll would yank the viewport on every navigation.
  //
  // ⚠ Fires on STATE CHANGES ONLY (active folder, section collapse) — never on
  // user scroll. A reveal that chased the scroll position would fight a user
  // deliberately browsing another section, which is worse than the bug.
  let sidebarEl: HTMLElement | undefined = $state();

  async function revealActiveFolder() {
    await tick();
    sidebarEl
      ?.querySelector('.row.active')
      ?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  $effect(() => {
    // Both reads register the dependency; the collapse array is reassigned (not
    // mutated) by toggleSection, so an expand/collapse re-runs this.
    void activeId;
    void collapsed;
    void revealActiveFolder();
  });
  const grouped = $derived(browser.groupedShares);
  // S209: the PRSN ACCOUNTS list itself. FolderTree sorts each PRSN's FOLDERS, but
  // the accounts are rendered here from `prsns.map(...)` in grouping.ts, i.e. in
  // whatever order the API returned. ⚠ They LOOK alphabetical on the staging account
  // only because the handles were created that way — incidental, not guaranteed.
  const prsnGroupsSorted = $derived(
    [...grouped.prsnGroups].sort((a, b) =>
      compareDisplayNames(a.prsn.handle ?? '', b.prsn.handle ?? ''),
    ),
  );
  const quotaPct = $derived(
    browser.quota && browser.quota.bytes_quota > 0
      ? Math.min(100, (browser.quota.bytes_used / browser.quota.bytes_quota) * 100)
      : 0,
  );

  // Per-PRSN expand state (collapsed by default; the Guardian opens a PRSN to see
  // its folders — keeps the nav calm at up to 8 PRSNs).
  // bug184: expansion state lives on the store so it survives a reload with the
  // rest of the navigation position. Was Record<string,boolean> local state here.
  function togglePrsn(id: string) {
    browser.togglePrsn(id);
  }

  // ── bug196 item 4: section-level collapse ─────────────────────────────────
  // Three stacked lists share ONE scroll column, so a long PRIVATE FOLDERS list
  // buries SHARE FOLDERS and PRSN ACCOUNTS beneath it. Collapsing is the standard
  // consumer answer (Finder, Drive and Dropbox all use collapsible groups with a
  // single scroll) and it reuses the chevron this sidebar already uses per-PRSN,
  // so it adds no interaction a user has to learn.
  //
  // ⚠ Draggable section HEIGHTS were considered and rejected: that is a
  // developer-tool pattern (VS Code), and it is not the width splitter rotated —
  // multiple dividers inside a scrolling column must answer what happens when a
  // section is shorter than its allotment, what the minimums are, how dragging
  // interacts with scrolling, and what any of it means on mobile.
  //
  // Persisted like the sort preference and the nav width: this browser, this user.
  // ⚠ S209: SectionId and the runtime filter below are ONE list in two places, and
  // TypeScript cannot bind them — the filter is a runtime whitelist over parsed JSON,
  // so a value added to the type but not to the guard type-checks, collapses fine, and
  // is then silently dropped on reload. Add to both or neither.
  type SectionId = 'private' | 'share' | 'prsns' | 'sharedIn';
  const SECTION_IDS: readonly SectionId[] = ['private', 'share', 'prsns', 'sharedIn'];
  const COLLAPSED_KEY = 'signet:nav-collapsed';

  function loadCollapsed(): SectionId[] {
    if (typeof localStorage === 'undefined') return [];
    try {
      const raw = JSON.parse(localStorage.getItem(COLLAPSED_KEY) ?? '[]');
      if (Array.isArray(raw)) {
        return raw.filter((v): v is SectionId => SECTION_IDS.includes(v as SectionId));
      }
    } catch {
      /* ignore malformed */
    }
    return [];
  }

  let collapsed = $state<SectionId[]>(loadCollapsed());
  const isCollapsed = (id: SectionId) => collapsed.includes(id);

  // bug196 item 5: most users have no PRSNs, and for them this section is noise.
  // ⚠ The default is DERIVED — see $lib/prsn-section. A flat "off" would have
  // hidden the section from Guardians actively using it. The toggle itself lives
  // in Settings, which always shows its PRSN card, so this can never become a
  // section you cannot get back.
  const prsnPref = loadPrsnSectionPref();
  const showPrsnSection = $derived(prsnSectionVisible(prsnPref, grouped.prsnGroups.length));

  function toggleSection(id: SectionId) {
    collapsed = isCollapsed(id) ? collapsed.filter((s) => s !== id) : [...collapsed, id];
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(COLLAPSED_KEY, JSON.stringify(collapsed));
    }
  }
</script>

<aside class="sidebar" bind:this={sidebarEl}>
  {#if !browser.isPrsn}
    <section class="folders private">
      <div class="head">
        <!-- bug160: each card title carries a hover explanation — same title-attribute
             pattern as the Verified chip and the PENDING DELETION tag. -->
        <h2 title={m.sidebar_private_folders_tip()}>
          <button
            class="disclose"
            onclick={() => toggleSection('private')}
            aria-expanded={!isCollapsed('private')}
          >
            <Chevron open={!isCollapsed('private')} />
            {m.sidebar_private_folders()}
          </button>
        </h2>
        <button
          class="add"
          onclick={() => browser.openNewFolder(true)}
          aria-label={m.sidebar_new_private_label()}>{m.sidebar_new()}</button
        >
      </div>
      {#if !isCollapsed('private')}
        <FolderTree {browser} folders={browser.privateFolders} {activeId} owned={true} zebra />
      {/if}
    </section>

    <section class="folders share">
      <div class="head">
        <h2 title={m.sidebar_share_folders_tip()}>
          <button
            class="disclose"
            onclick={() => toggleSection('share')}
            aria-expanded={!isCollapsed('share')}
          >
            <Chevron open={!isCollapsed('share')} />
            {m.sidebar_share_folders()}
          </button>
        </h2>
        <button
          class="add"
          onclick={() => browser.openNewShareFolder()}
          aria-label={m.sidebar_new_share_label()}>{m.sidebar_new()}</button
        >
      </div>
      {#if !isCollapsed('share')}
        <FolderTree {browser} folders={browser.ownedShareFolders} {activeId} owned={true} zebra />
      {/if}
    </section>

    <!-- ⚠⚠ bug196 item 5 SUPERSEDES bug017's always-render rule, deliberately and on
         Chris's request (S177) — recorded here because the two genuinely conflict and
         a silent reversal is how a ruling gets lost.

         bug017 said: always render for humans, because a Guardian with zero PRSNs
         still needs the "+ PRSN" affordance, so the section must not be gated on
         having ≥1 PRSN. That reasoning was sound when the sidebar was the ONLY route
         to it.

         What changed: most Signet Drive users will never have a PRSN (and cannot
         without an Apple-Silicon Mac to host one), so for them this is a permanent
         section of noise. The affordance bug017 protected is NOT lost — Settings
         always shows its PRSN card with the real "+ Add PRSN" button, and this
         sidebar link only ever deep-linked there anyway. What a zero-PRSN user loses
         is a signpost, not a capability.

         ⚠ If that trade is ever reconsidered, reconsider it as a PRODUCT call, not by
         quietly restoring the old condition: the derived default in $lib/prsn-section
         is what keeps existing Guardians unaffected. -->
    {#if showPrsnSection}
      <section class="prsns">
        <div class="head">
          <h2 title={m.sidebar_your_prsns_tip()}>
            <button
              class="disclose"
              onclick={() => toggleSection('prsns')}
              aria-expanded={!isCollapsed('prsns')}
            >
              <Chevron open={!isCollapsed('prsns')} />
              {m.sidebar_your_prsns()}
            </button>
          </h2>
          <a class="add" href="/account#prsns">{m.sidebar_add_prsn()}</a>
        </div>
        {#if !isCollapsed('prsns')}
          {#if grouped.prsnGroups.length}
            {#each prsnGroupsSorted as group, i (group.prsn.account_id)}
              <div class="prsn" class:alt={i % 2 === 1}>
                <button
                  class="prsn-head"
                  aria-expanded={browser.expandedPrsns.has(group.prsn.account_id)}
                  onclick={() => togglePrsn(group.prsn.account_id)}
                >
                  <span class="chev" aria-hidden="true">
                    <Chevron open={browser.expandedPrsns.has(group.prsn.account_id)} />
                  </span>
                  <!-- 12px dots render canonical regardless of seed (SealImpression
                   collapses <20px), so this is a neutral brand mark, deliberately
                   NOT per-PRSN (Gus carve review F1, S132; per-PRSN dots would
                   need a sub-20 seeded variant — post-launch). -->
                  <SealImpression seed="signet" size={12} />
                  <span class="prsn-handle">{group.prsn.handle ?? '—'}</span>
                  <!-- bug150 (Chris ruled option (b)): the two states a guardian must
                   not have to visit /account to learn — pending deletion, and
                   never-authorized. Same vocabulary as the consolidated card's
                   tags (prsnStateTag reads the server's grant_state projection);
                   tooltips on each. All other states show no marker, and an
                   older server (no grant_state) shows only the account-level
                   pending-deletion one. -->
                  {#if prsnStateTag(group.prsn) === 'pending_deletion'}
                    <span
                      class="marker pending"
                      title={m.sidebar_marker_pending_deletion_tip()}
                      role="img"
                      aria-label={m.prsn_tag_pending_deletion()}
                    ></span>
                  {:else if prsnStateTag(group.prsn) === 'not_authorized'}
                    <span
                      class="marker unauth"
                      title={m.sidebar_marker_not_authorized_tip()}
                      role="img"
                      aria-label={m.prsn_tag_not_authorized()}
                    ></span>
                  {/if}
                  <span class="prsn-count">{group.folders.length}</span>
                </button>
                {#if browser.expandedPrsns.has(group.prsn.account_id)}
                  <div class="prsn-body">
                    <!-- bug101: a PRSN's folders are OWNED by the PRSN — the Guardian is a
                     read-write recipient here, not the owner, so rename/delete are
                     disabled (owner-only server-side). -->
                    <FolderTree {browser} folders={group.folders} {activeId} owned={false} />
                  </div>
                {/if}
              </div>
            {/each}
          {:else}
            <p class="empty">{m.sidebar_no_prsns_yet()}</p>
          {/if}
        {/if}
      </section>
    {/if}

    {#if grouped.humanShared.length}
      <!-- S209 (Chris): this was a bare <section> with a plain <h2> — no card, no
           band, no collapse — while the three sections above it were cards. It read
           as a footnote rather than a peer.
           ⚠ It has NO "+ New", and that asymmetry is correct, not an omission: you
           cannot create a folder inside something someone else shared with you. -->
      <!-- ⭐ The dividing line above this section is KEPT (Chris, S209). It is not
           decoration: the three sections above are folders you OWN, and this one is
           not yours. The card makes it a peer in FORM; the rule keeps the boundary
           the card would otherwise erase.
           ⚠ An explicit element rather than a border on the section, because
           `section + section`'s hairline is cancelled by `section.folders` and a
           ::before on the card would be clipped by its own `overflow: hidden`
           (which exists for the band's rounded corners). -->
      <div class="section-divider" aria-hidden="true"></div>
      <section class="folders shared-in">
        <div class="head">
          <h2>
            <button
              class="disclose"
              onclick={() => toggleSection('sharedIn')}
              aria-expanded={!isCollapsed('sharedIn')}
            >
              <Chevron open={!isCollapsed('sharedIn')} />
              {m.sidebar_shared_with_you()}
            </button>
          </h2>
        </div>
        {#if !isCollapsed('sharedIn')}
          <FolderTree {browser} folders={grouped.humanShared} {activeId} owned={false} zebra />
        {/if}
      </section>
    {/if}
  {:else}
    <section class="folders share">
      <div class="head">
        <h2>{m.sidebar_share_folders()}</h2>
        <button
          class="add"
          onclick={() => browser.openNewShareFolder()}
          aria-label={m.sidebar_new_share_label()}>{m.sidebar_new()}</button
        >
      </div>
      <FolderTree {browser} folders={browser.shareFolders} {activeId} owned={true} zebra />
    </section>
  {/if}

  <div class="spacer"></div>

  <!-- A discoverable Settings affordance in the conventional bottom-of-nav spot
       (Bug019) — the account page was previously reachable only via the top-bar
       handle link. Both surfaces have an /account page, so it renders for both. -->
  <a class="settings" href="/account">
    <svg
      class="gear"
      viewBox="0 0 24 24"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="3" />
      <path
        d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"
      />
    </svg>
    <span>{m.sidebar_settings()}</span>
  </a>

  {#if serverVersion}
    <p class="server-version">server {serverVersion}</p>
  {/if}

  {#if browser.isPrsn && browser.me}
    <section class="dependent">
      <p>
        <span class="k">{m.sidebar_guardian()}</span><span class="v"
          >{browser.me.guardian?.handle ?? '—'}</span
        >
      </p>
      <p>
        <span class="k">{m.sidebar_sharing()}</span><span class="v"
          >{browser.me.prsn_sharing_capability ?? '—'}</span
        >
      </p>
    </section>
  {/if}

  {#if browser.quota}
    <section class="quota">
      <div class="bar">
        <div
          class="fill"
          class:warn={quotaPct >= 85}
          class:danger={quotaPct >= 95}
          style:width="{quotaPct}%"
        ></div>
      </div>
      <p>
        {m.sidebar_quota_used({
          used: formatBytes(browser.quota.bytes_used),
          quota: formatBytes(browser.quota.bytes_quota),
        })}
        {#if quotaPct >= 85}<span class="quota-note" class:danger={quotaPct >= 95}
            >{m.sidebar_quota_nearly_full()}</span
          >{/if}
      </p>
    </section>
  {/if}
</aside>

<style>
  /* A deliberately quiet diagnostic: legible when looked for, invisible when not. */
  .server-version {
    margin: 0.15rem 0 0 0;
    padding: 0 0.75rem 0.35rem;
    color: var(--muted);
    opacity: 0.65;
    font-size: 0.7rem;
    font-variant-numeric: tabular-nums;
    user-select: text; /* it exists to be read out and pasted into a report */
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    gap: 1.1rem;
    /* Width is user-resizable via the FileBrowser splitter (persisted to
       localStorage); 240px is the default if --nav-width is unset. */
    width: var(--nav-width, 240px);
    flex: none;
    padding: 1.25rem;
    border-right: 1px solid var(--border);
    background: var(--surface);
    overflow-y: auto;
  }
  /* bug213: the sections must NOT shrink. `.sidebar` is a flex column, and flex
     children default to `flex-shrink: 1` — so when the three lists together
     exceeded the panel height the browser COMPRESSED the sections to fit rather
     than letting the column overflow. Each section sets `overflow: hidden` (for
     its rounded band clipping), so the compressed section then clipped its own
     rows silently: no scrollbar, no fade, no recourse. The active folder — the
     one whose files fill the main pane — could vanish from the nav entirely.
     ⚠ This is why `overflow-y: auto` above never engaged: content was squeezed
     to fit instead of exceeding the box, so the scroll column shipped by
     bug196 item 4 has never once scrolled. Pinning shrink to 0 is the whole fix;
     `.spacer` (flex: 1) still pins the footer when there IS free space and
     collapses to 0 when there is not. */
  .sidebar > section {
    flex-shrink: 0;
  }
  /* Section rhythm (bug053): the two folder sections separate by a hairline +
     air, not colour; the eyebrow labels carry slightly more weight. */
  section + section {
    border-top: 1px solid var(--border);
    padding-top: 1.1rem;
  }
  /* YOUR PRSNS gets the one deliberate asymmetry — a soft accent wash — because
     PRSNs are people, not folders (the same distinction the main pane's Guardian
     context banner makes). --accent-wash is half-strength so FolderTree's active
     rows (--accent-soft) still read against it; the wash replaces the hairline. */
  /* bug103: the PRSN ACCOUNTS section is a three-tone zebra LADDER — a darkest
     header band, then per-PRSN rows alternating white ↔ --accent-soft (white
     first), as full-bleed bands clipped to the card's rounded corners. Replaces
     the barely-visible v0.5.22 stripe (a ~4-RGB step off the wash). */
  section.prsns {
    border-top: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    margin: 0 -0.65rem;
    padding: 0;
  }
  .prsns h2,
  .prsns .prsn-count {
    /* --muted misses AA on the band; --ink-soft clears it and suits the
       distinct-section intent. */
    color: var(--ink-soft);
  }
  /* bug103: the header row is the darkest rung of the ladder, full-bleed, with a
     hairline divider under it. */
  .prsns .head {
    margin: 0;
    padding: 0.6rem 0.65rem;
    background: var(--accent-band);
    border-bottom: 1px solid rgba(63, 61, 138, 0.18);
    align-items: center;
  }
  .prsns .head h2 {
    margin: 0;
  }
  /* bug103: rows start on white and alternate to --accent-soft; content is inset by
     the card gutter while the band itself is edge-to-edge. */
  .prsns .prsn {
    /* S209: was --surface (white). Now the section's own light rung, so a PRSN row
       belongs to the lavender family the way every other section's rows now belong
       to theirs. */
    background: var(--prsn-row-a);
    padding: 0 0.65rem;
  }
  /* bug112 refined by bug115 (S155 live-locked): box each PRSN NAME row with STRAIGHT
     asymmetric lines, drawn as pseudo-elements so they ignore the 9px hover-radius
     (bug112's border-top/bottom followed the rounded corners and curved at the ends).
     Top line full-width of the name box + darker (0.30): caps/separates each account.
     Bottom line inset 9px each side (= exactly where the old curves were) + lighter
     (0.10): reads as "this name owns the folders below it" rather than fencing them
     off. PRSN section only — the neutral folder sections stay untouched. */
  .prsns .prsn-head {
    border-top: 0;
    border-bottom: 0;
    position: relative;
  }
  .prsns .prsn-head::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: rgba(63, 61, 138, 0.3);
  }
  .prsns .prsn-head::after {
    content: '';
    position: absolute;
    bottom: 0;
    left: 9px;
    right: 9px;
    height: 1px;
    background: rgba(63, 61, 138, 0.1);
  }
  /* bug115 (2): a PRSN's folders are one nesting level deeper than the account name
     (which stays 16px, like the Private/Share folders — both direct section children),
     so the size step reflects real depth: 14px, scoped to the PRSN section only. */
  .prsns :global(.row) {
    font-size: 14px;
  }
  /* bug113: PRSN-section hover is a translucent accent overlay (not a fixed colour) — it
     composites over whatever the row's bg is, so it deepens BOTH a white row and an
     --accent-soft alt row consistently (a fixed colour could only do one). The
     light-purple analog of the folders' beige hover; folder sections keep their beige. */
  .prsns .prsn-head:hover {
    background: rgba(63, 61, 138, 0.06);
  }
  .prsns :global(.row:hover) {
    background: rgba(63, 61, 138, 0.06);
  }
  /* bug109: the PRIVATE + SHARE folder sections take the same ladder as bug103 in a
     neutral palette — a warm-grey header band + divider, then FolderTree rows zebra'd
     white ↔ --bg (first white), full-bleed and clipped to the card. */
  section.folders {
    border-top: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    margin: 0 -0.65rem;
    padding: 0 0 0.35rem;
  }
  .folders .head {
    margin: 0 0 0.35rem;
    padding: 0.6rem 0.65rem;
    /* Fallback only — every .folders section carries a modifier below. Kept so a
       new section without one is visibly unstyled-but-sane rather than transparent. */
    background: var(--neutral-band);
    border-bottom: 1px solid var(--border);
    align-items: center;
  }
  /* ── S209: one palette per section ─────────────────────────────────────────
     Each section sets --row-a / --row-b for its own zebra; FolderTree reads them
     through INHERITANCE (see its ul.zebra rules) rather than as props, so every
     subfolder level stripes in its own section's colour for free. A prop would
     have to be threaded through the recursion, and a level that forgot it would
     stripe in the wrong section's colour — a defect nobody would see until a deep
     tree happened to be open. */
  .folders.private {
    --row-a: var(--private-row-a);
    --row-b: var(--private-row-b);
  }
  .folders.private .head {
    background: var(--neutral-band);
  }
  .folders.share {
    --row-a: var(--share-row-a);
    --row-b: var(--share-row-b);
  }
  .folders.share .head {
    background: var(--share-band);
  }
  /* The kept boundary above SHARED WITH YOU. Matches the card's negative gutter so
     the rule spans the same width as the sections it separates, rather than being
     inset from them. `flex-shrink: 0` because .sidebar is a flex column and bug213
     showed unshrinkable is the only safe default here. */
  .section-divider {
    border-top: 1px solid var(--border);
    margin: 0.15rem -0.65rem 0;
    flex-shrink: 0;
  }
  .folders.shared-in {
    --row-a: var(--shared-in-row-a);
    --row-b: var(--shared-in-row-b);
  }
  .folders.shared-in .head {
    background: var(--shared-in-band);
  }
  .folders .head h2 {
    margin: 0;
  }
  .head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    /* bug196 item 4: section headers stay visible while the nav scrolls, so you
       always know which section you are looking at. The sidebar is one scroll
       column shared by three lists; without this, a long list leaves you reading
       folder names with no idea whose they are. */
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--surface);
  }
  /* The section title IS the disclosure control. The button sits INSIDE the
     heading rather than wrapping it: an h2 is flow content and is not valid
     inside a button, and this way the heading stays a heading for screen readers
     while the control is focusable and announces its own expanded state. */
  .disclose {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    border: 0;
    background: none;
    font: inherit;
    color: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    cursor: pointer;
    padding: 0;
  }
  .disclose:hover,
  .disclose:focus-visible {
    color: var(--ink);
  }
  h2 {
    /* Eyebrow labels, not display headings — stay sans against the global h2 serif. */
    font-family: var(--font-sans);
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
    margin: 0 0 0.5rem;
  }
  .add {
    border: 0;
    background: none;
    color: var(--accent);
    font: inherit;
    font-size: 0.82rem;
    font-weight: 500;
    cursor: pointer;
    padding: 0;
    text-decoration: none;
  }
  .add:hover {
    text-decoration: underline;
  }
  /* Empty-state line for a section with no entries yet (e.g. zero PRSNs). */
  .empty {
    margin: 0;
    color: var(--muted);
    font-size: 0.85rem;
    padding: 0.2rem 0.3rem;
  }
  /* Bottom-of-nav Settings link (Bug019). */
  .settings {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--ink-soft);
    font-size: 0.88rem;
    font-weight: 500;
    text-decoration: none;
    padding: 0.45rem 0.55rem;
    border-radius: var(--radius-sm);
  }
  .settings:hover {
    background: var(--bg);
    color: var(--ink);
  }
  .gear {
    flex: none;
    color: var(--muted);
  }
  .settings:hover .gear {
    color: var(--ink-soft);
  }
  /* Per-PRSN collapsible section (Bug009). */
  .prsn {
    display: flex;
    flex-direction: column;
  }
  /* bug103: the alternating bands separate one PRSN from the next now — drop the
     bug059 inter-block gap/hairline so the zebra reads as a continuous ladder (an
     expanded PRSN's folders stay banded with their owner via the block background). */
  .prsns .prsn + .prsn {
    margin-top: 0;
    padding-top: 0;
  }
  /* bug103: the mid rung — full-bleed, no inset radius (edge-to-edge reads as a zebra
     per the locked swatches). An active folder inside a block reads via FolderTree's
     global accent left-bar (bug111 — box-shadow, no fill) + its bold accent text; the
     old scoped `.prsns :global(.row.active)` inset-border is now redundant, removed. */
  .prsns .prsn.alt {
    /* S209: was --accent-soft. Moved to the section's own mid rung — --accent-soft is
       a SHARED token (active rows elsewhere) and must not be redefined to serve one
       section's zebra. Same reason the other three sections got their own pair. */
    background: var(--prsn-row-b);
  }
  .prsn-head {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    width: 100%;
    border: 0;
    background: none;
    font: inherit;
    color: var(--ink-soft);
    padding: 0.35rem 0.55rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
    /* Buttons default to text-align:center, which inherits into the flex:1 handle
       span and centres the label (bug052) — rows read left-aligned like FolderTree. */
    text-align: left;
  }
  .prsn-head:hover {
    background: var(--bg);
  }
  /* Holder for the per-PRSN <Chevron> SVG — width matches the folder-tree chevron
     column so the two align, and colour feeds the SVG via currentColor. The SVG owns
     its size + rotate-on-open, so the folder and PRSN chevrons render identically
     regardless of host font (Bug020). */
  .chev {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.6rem;
    color: var(--muted);
  }
  .prsn-handle {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 500;
  }
  .prsn-count {
    color: var(--muted);
    font-size: 0.78rem;
  }
  /* bug150: the per-PRSN state markers — an 8px dot beside the handle. Color
     families match the account card's tags (danger = pending deletion, accent =
     not authorized); the title tooltip carries the words. */
  .marker {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    cursor: help;
  }
  .marker.pending {
    background: var(--danger);
  }
  .marker.unauth {
    background: var(--accent);
    outline: 1px solid var(--accent-soft);
  }
  .prsn-body {
    padding-left: 0.85rem;
  }
  .spacer {
    flex: 1;
  }
  .dependent {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    padding: 0.7rem 0.75rem;
    background: var(--bg);
    border-radius: var(--radius-sm);
    font-size: 0.82rem;
  }
  .dependent p {
    margin: 0;
    display: flex;
    justify-content: space-between;
    gap: 0.5rem;
  }
  .dependent .k {
    color: var(--muted);
  }
  .dependent .v {
    color: var(--ink);
    font-weight: 500;
  }
  .quota p {
    margin: 0.45rem 0 0;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .bar {
    height: 6px;
    border-radius: 3px;
    background: var(--bg);
    overflow: hidden;
  }
  .fill {
    height: 100%;
    background: var(--accent);
    transition:
      width 0.2s,
      background 0.2s;
  }
  .fill.warn {
    background: var(--warn);
  }
  .fill.danger {
    background: var(--danger);
  }
  .quota-note {
    color: var(--warn);
    font-weight: 600;
  }
  .quota-note.danger {
    color: var(--danger);
  }
  /* Inside the mobile overlay drawer the sidebar fills the drawer, not the
     resizable desktop width. */
  @media (max-width: 720px) {
    .sidebar {
      width: 100%;
      height: 100%;
    }
  }
</style>
