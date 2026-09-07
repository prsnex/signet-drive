<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // The seal, pressed — Brand Foundations §1.2, v03 geometry (S003 UI carve;
  // authored by Gus, integrated by Hlin). Layered mark: accent disc → paper
  // channel → offset core → press gradient. Never animated — a seal is
  // pressed once. Decorative only (aria-hidden).
  //
  // seed: Uint8Array = fingerprint bytes (identity surfaces — the caller
  // passes the per-type fingerprint pinned in impression.ts's module doc);
  // string = page path (anonymous app surfaces — hashed, deterministic).
  // Below 20 px the mark renders canonical (impressions collapse at that
  // scale). "New keys, new press": a re-enrolled identity presses anew.
  import { CANONICAL, sealImpression, stringSeedBytes, toCssVars } from './impression';

  let { seed, size = 16 }: { seed: Uint8Array | string; size?: number } = $props();

  const vars = $derived(
    size < 20 ? CANONICAL : sealImpression(typeof seed === 'string' ? stringSeedBytes(seed) : seed),
  );
  const style = $derived(
    `width:${size}px;height:${size}px;` +
      Object.entries(toCssVars(vars, size))
        .map(([k, v]) => `${k}:${v}`)
        .join(';'),
  );
</script>

<span class="seal-impression" {style} aria-hidden="true">
  <span class="disc"></span><span class="paper"></span><span class="core"></span><span class="press"
  ></span>
</span>

<style>
  /* Defaults (no style vars) = the canonical concentric mark. The press
     gradient uses color-mix() — Chrome-fine for launch; on the G2/G3
     cross-browser matrix (fallback: precomputed rgba stops, no visual
     change). */
  .seal-impression {
    position: relative;
    display: inline-block;
    flex: none;
  }
  .seal-impression .disc {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: var(--accent);
  }
  .seal-impression .paper {
    position: absolute;
    inset: var(--band, 7.5%);
    border-radius: 50%;
    background: var(--seal-paper, var(--bg));
  }
  .seal-impression .core {
    position: absolute;
    left: 50%;
    top: 50%;
    width: var(--core, 65%);
    height: var(--core, 65%);
    border-radius: 50%;
    background: var(--accent);
    transform: translate(calc(-50% + var(--dx, 0px)), calc(-50% + var(--dy, 0px)));
  }
  .seal-impression .press {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: linear-gradient(
      var(--ph, 0deg),
      color-mix(in srgb, var(--seal-paper, var(--bg)) calc(var(--dp, 0) * 100%), transparent),
      transparent 65%
    );
  }
</style>
