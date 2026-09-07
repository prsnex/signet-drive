<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // IconFileCode — Signet stroke icon (24px grid, 1.6 stroke, round caps/joins, currentColor).
  // New-to-voice (not in mockup): paired code chevrons on the shared file base.
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
    d="M6 3h8l4 4v14a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z M14 3v4h4 M9.4 12.2l-2.3 2.4 2.3 2.4 M14.6 12.2l2.3 2.4-2.3 2.4"
  />
</svg>
