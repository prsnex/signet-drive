<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // IconFileSheet — Signet stroke icon (24px grid, 1.6 stroke, round caps/joins, currentColor).
  // Geometry verbatim from mockup v03 `#i-file-sheet` (bounded 2×2 grid — a grid, not a tree; Chris, S003).
  // Authored by Gus (S003 UI carve); integration + gate: Hlin.
  let { size = 16 }: { size?: number } = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.6"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <path
    d="M6 3h8l4 4v14a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z M14 3v4h4 M8.5 11.5h7v6.5h-7z M8.5 14.75h7 M12 11.5v6.5"
  />
</svg>
