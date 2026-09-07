<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // Shared expand/collapse chevron for the left nav. An inline SVG, not the unicode
  // ▸ glyph: the glyph rendered at different sizes depending on the host element's
  // font (the folder tree's <button> fell back to the UA Arial; the PRSN header's
  // <span> inherited system-ui — same glyph, same font-size, visibly different
  // triangle). Drawing it ourselves makes it pixel-identical everywhere, and a single
  // component means the two call sites can't drift again (Bug020).
  let { open = false }: { open?: boolean } = $props();
</script>

<svg class="chevron" class:open viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
  <path d="M5.5 3 L11.5 8 L5.5 13 Z" fill="currentColor" />
</svg>

<style>
  .chevron {
    flex: none;
    transition: transform 0.15s;
  }
  .chevron.open {
    transform: rotate(90deg);
  }
</style>
