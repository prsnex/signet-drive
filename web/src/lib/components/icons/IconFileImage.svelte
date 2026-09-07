<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // IconFileImage — Signet stroke icon (24px grid, 1.6 stroke, round caps/joins, currentColor).
  // Geometry verbatim from mockup v03 `#i-file-img`.
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
    d="M6 3h8l4 4v14a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z M14 3v4h4 M9.2 13.4a1.2 1.2 0 100-2.4 1.2 1.2 0 000 2.4z M7.5 19l3.4-3.7 2 2 2.3-2.7 2.3 3.2"
  />
</svg>
