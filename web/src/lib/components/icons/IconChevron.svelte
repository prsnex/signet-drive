<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // IconChevron — Signet stroke icon (24px grid, 1.6 stroke, round caps/joins, currentColor).
  // Geometry verbatim from mockup v03 `#i-chev`.
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
  <path d="M9 6l6 6-6 6" />
</svg>
