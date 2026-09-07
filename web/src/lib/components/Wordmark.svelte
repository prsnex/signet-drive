<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  let { size = 'md' }: { size?: 'md' | 'lg' } = $props();
</script>

<span class="wordmark" class:lg={size === 'lg'}>
  <span class="seal" aria-hidden="true"></span>
  <span class="name">Signet<span class="thin">&nbsp;Drive</span></span>
</span>

<style>
  .wordmark {
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
    font-family: var(--font-serif);
    font-size: 1.25rem;
    letter-spacing: 0.01em;
    color: var(--ink);
  }
  .lg {
    font-size: 1.85rem;
  }
  /* A small wax-seal dot — the signet mark, no asset needed. */
  .seal {
    width: 0.72em;
    height: 0.72em;
    border-radius: 50%;
    background: var(--accent);
    box-shadow:
      inset 0 0 0 0.13em var(--surface),
      0 0 0 0.09em var(--accent);
    flex: none;
  }
  .name {
    font-weight: 600;
  }
  .thin {
    font-weight: 400;
    color: var(--ink-soft);
  }
</style>
