<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // bug101: a small, reusable overflow / context menu. Rendered once at the top
  // level (FileBrowser) and opened by both the file panel and the left-nav tree via
  // `browser.contextMenu`. Dismisses on select, Escape, scroll, or any outside
  // click. Disabled items carry a tooltip (e.g. "only the owner can rename this").
  import { tooltip } from '$lib/tooltip';

  export type ActionMenuItem = {
    label: string;
    onSelect: () => void;
    disabled?: boolean;
    danger?: boolean;
    /** Shown on hover when the item is disabled (the reason). */
    tip?: string;
  };

  let {
    x,
    y,
    items,
    onClose,
  }: { x: number; y: number; items: ActionMenuItem[]; onClose: () => void } = $props();

  let menuEl = $state<HTMLDivElement | null>(null);
  // Null until measured + clamped in the effect below; the menu renders at the raw
  // (x, y) but hidden for one frame, then becomes visible at the clamped position —
  // so it never flashes off-screen near a viewport edge.
  let pos = $state<{ left: number; top: number } | null>(null);

  // Clamp into the viewport once measured — flip up / shift left near an edge so the
  // menu never opens off-screen (a right-click near the bottom-right is the case).
  $effect(() => {
    const el = menuEl;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const pad = 8;
    let left = x;
    let top = y;
    if (left + r.width + pad > window.innerWidth)
      left = Math.max(pad, window.innerWidth - r.width - pad);
    if (top + r.height + pad > window.innerHeight) top = Math.max(pad, y - r.height);
    pos = { left, top };
  });

  // Focus the first enabled item once the menu is visible, the way a keyboard
  // user expects a menu to open (Gus, folder-upload review, 2026-09-25): the
  // Upload menu is the keyboard path for folders, and Enter then lands on
  // "Files…" rather than back on the button. Only after `pos` is set: the menu is
  // `visibility: hidden` for its first frame, and a hidden element cannot take
  // focus. Once per opening — not on every re-position.
  let focused = false;
  $effect(() => {
    if (!pos || !menuEl || focused) return;
    focused = true;
    menuEl
      .querySelector<HTMLButtonElement>('button.item:not(:disabled)')
      ?.focus({ preventScroll: true });
  });

  function choose(item: ActionMenuItem) {
    if (item.disabled) return;
    // Fire the action BEFORE closing. onClose() nulls browser.contextMenu, and the
    // item closures read their target (file/folder) off it — reading after the close
    // hits a nulled reference and the action silently no-ops (caught by the bug101
    // e2e: the menu closed but the rename dialog never opened).
    item.onSelect();
    onClose();
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  }
</script>

<svelte:window onkeydown={onKey} />

<!-- Transparent full-viewport catcher: any outside click / right-click / scroll
     dismisses the menu. Keyboard dismissal is Escape (window handler above), so the
     static-interaction lint is intentionally waived here. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div
  class="backdrop"
  role="presentation"
  onclick={onClose}
  oncontextmenu={(e) => {
    e.preventDefault();
    onClose();
  }}
  onwheel={onClose}
></div>

<div
  class="menu"
  bind:this={menuEl}
  style="left: {pos?.left ?? x}px; top: {pos?.top ?? y}px; visibility: {pos ? 'visible' : 'hidden'}"
  role="menu"
>
  {#each items as item (item.label)}
    <span class="tipwrap" use:tooltip={item.disabled ? (item.tip ?? '') : ''}>
      <button
        class="item"
        class:danger={item.danger}
        role="menuitem"
        disabled={item.disabled}
        onclick={() => choose(item)}
      >
        {item.label}
      </button>
    </span>
  {/each}
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 40;
  }
  .menu {
    position: fixed;
    z-index: 41;
    min-width: 9rem;
    padding: 0.3rem;
    display: flex;
    flex-direction: column;
    gap: 0.05rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: 0 6px 24px rgba(0, 0, 0, 0.14);
  }
  .tipwrap {
    display: flex;
  }
  .item {
    flex: 1;
    text-align: left;
    border: 0;
    background: none;
    font: inherit;
    font-size: 0.9rem;
    color: var(--ink);
    padding: 0.4rem 0.6rem;
    border-radius: 5px;
    cursor: pointer;
  }
  .item:hover:not(:disabled) {
    background: var(--surface-2);
  }
  .item.danger {
    color: var(--danger);
  }
  .item:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
