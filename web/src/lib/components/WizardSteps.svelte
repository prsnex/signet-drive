<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script module lang="ts">
  import { m } from '$lib/paraglide/messages.js';

  /** The canonical add-PRSN wizard step list — ONE home (both wizard pages render
   *  it), so the two surfaces can never disagree about the flow's length again
   *  (pre-bug080 the naming page showed 4 steps while the confirm page showed 7).
   *  Six steps under the v08 flow: the §6 match-gate/Verify step is gone — the
   *  agent's signed pickup auto-confirms (bug084). */
  export function wizardStepLabels(): string[] {
    return [
      m.enrollwizard_step_name(),
      m.enrollwizard_step_handoff(),
      m.enrollwizard_step_approve(),
      m.enrollwizard_step_authorize(),
      m.enrollwizard_step_connect(),
      m.enrollwizard_step_done(),
    ];
  }
</script>

<script lang="ts">
  // The add-PRSN wizard's checklist header (§1-62, design note §3): a progress-dot
  // strip plus ONE rendered label — "Step N of M · <name>" (bug080). Exactly one
  // label ever renders, so label truncation is structurally unrepresentable at any
  // step count and any viewport (the old per-step labels collapsed to single
  // letters at seven steps in the fixed-width card). Purely presentational — the
  // CURRENT step is always DERIVED from server state by the page (never stored
  // client-side), so this component renders truth it is handed, and holds none of
  // its own.
  let { steps, current }: { steps: string[]; current: number } = $props();
  const where = $derived(
    m.enrollwizard_step_of({
      n: String(current + 1),
      m: String(steps.length),
      label: steps[current] ?? '',
    }),
  );
</script>

<div class="wizard-steps">
  <ol class="dots" aria-hidden="true">
    {#each steps as label, i (label)}
      <li class:done={i < current} class:current={i === current}></li>
    {/each}
  </ol>
  <p class="where" role="status">{where}</p>
</div>

<style>
  .wizard-steps {
    margin: 0 0 0.35rem;
  }
  .dots {
    display: flex;
    gap: 0.25rem;
    margin: 0 0 0.4rem;
    padding: 0;
    list-style: none;
  }
  .dots li {
    flex: 1;
    height: 3px;
    border-radius: 2px;
    background: var(--border);
  }
  .dots li.done,
  .dots li.current {
    background: var(--accent);
  }
  .dots li.current {
    /* The current dot reads slightly stronger than the completed trail. */
    box-shadow: 0 0 0 1px var(--accent);
  }
  .where {
    margin: 0;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--ink-soft);
  }
</style>
