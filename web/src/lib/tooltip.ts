// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
/**
 * bug056 — the app tooltip, as a Svelte action: `use:tooltip={text}`.
 *
 * Replaces native `title=` where a control's purpose needs explaining: native
 * tooltips are slow (~1–2 s UA delay, not tunable), render in OS chrome that's
 * easy to miss (S125: a careful user hovered, saw nothing in the window they
 * waited, and concluded tooltips weren't implemented), and don't exist on touch.
 *
 * Behavior:
 *  - hover: shows after a short delay (400 ms); hides on leave.
 *  - keyboard focus: shows immediately; hides on blur.
 *  - Esc dismisses.
 *  - wired via `aria-describedby` so it SUPPLEMENTS the accessible name rather
 *    than replacing it (the S121 W8 lesson — never collide with aria-labels).
 *
 * Design constraint carried from the bug doc: a tooltip is an enhancement, not
 * the explanation — touch devices and untested platforms may never show it, so
 * a genuinely unclear control still needs a clear label or adjacent text.
 *
 * The bubble is appended to <body> (escapes overflow/stacking contexts); its
 * styles live in app.css under `.sig-tooltip` (global — component-scoped CSS
 * can't reach a body-appended node).
 */

const SHOW_DELAY_MS = 400;
let seq = 0;

export function tooltip(node: HTMLElement, text: string) {
  let tip: HTMLDivElement | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const id = `sig-tooltip-${++seq}`;
  let current = text;

  function place() {
    if (!tip) return;
    const r = node.getBoundingClientRect();
    const t = tip.getBoundingClientRect();
    // Below the control, centred; clamped to the viewport with an 8px gutter.
    let left = r.left + r.width / 2 - t.width / 2;
    left = Math.max(8, Math.min(left, window.innerWidth - t.width - 8));
    let top = r.bottom + 6;
    if (top + t.height > window.innerHeight - 8) top = r.top - t.height - 6;
    tip.style.left = `${Math.round(left)}px`;
    tip.style.top = `${Math.round(top)}px`;
  }

  function show() {
    if (tip || !current) return;
    tip = document.createElement('div');
    tip.className = 'sig-tooltip';
    tip.id = id;
    tip.setAttribute('role', 'tooltip');
    tip.textContent = current;
    document.body.appendChild(tip);
    node.setAttribute('aria-describedby', id);
    window.addEventListener('keydown', onKeydown, true);
    place();
  }

  function hide() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    if (tip) {
      tip.remove();
      tip = null;
      node.removeAttribute('aria-describedby');
      window.removeEventListener('keydown', onKeydown, true);
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') hide();
  }

  const onEnter = () => {
    if (timer || tip) return;
    timer = setTimeout(() => {
      timer = null;
      show();
    }, SHOW_DELAY_MS);
  };
  const onLeave = () => hide();
  const onFocus = () => show();
  const onBlur = () => hide();

  node.addEventListener('mouseenter', onEnter);
  node.addEventListener('mouseleave', onLeave);
  node.addEventListener('focus', onFocus);
  node.addEventListener('blur', onBlur);

  return {
    update(newText: string) {
      current = newText;
      if (tip) {
        tip.textContent = newText;
        place();
      }
    },
    destroy() {
      hide();
      node.removeEventListener('mouseenter', onEnter);
      node.removeEventListener('mouseleave', onLeave);
      node.removeEventListener('focus', onFocus);
      node.removeEventListener('blur', onBlur);
    },
  };
}
