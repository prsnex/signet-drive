<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // IconDownload — Signet stroke icon (24px grid, 1.6 stroke, round caps/joins, currentColor).
  // Geometry verbatim from mockup v03 `#i-download`.
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
  <path d="M12 5v11m0 0l-4.5-4.5M12 16l4.5-4.5M4.5 19h15" />
</svg>
