<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // The read-only/over-quota notice atop the file browser (D2 web cluster). Derives
  // its state from /v1/me + the quota readout (billing.ts owns the precedence) and
  // renders the matching message. A human can act (CTA → the account billing section);
  // a PRSN never bills — it draws from its Guardian's pooled quota — so its variants
  // inform without a billing CTA. Renders nothing when the account can write normally.
  import type { MeResponse, QuotaResponse } from '$lib/api';
  import { billingBannerState } from '$lib/billing';
  import { formatDeadline } from '$lib/format';
  import { m } from '$lib/paraglide/messages.js';

  let { me, quota }: { me: MeResponse | null; quota: QuotaResponse | null } = $props();

  const state = $derived(billingBannerState(me, quota));
  // bug072: a deadline carries its time + zone — a bare date named a different day
  // than the email did for the same instant. See `formatDeadline`.
  const trialEndsOn = $derived(me ? formatDeadline(me.paid_until) : '');
</script>

{#if state !== 'none'}
  <div class="banner" role="status">
    {#if state === 'trial'}
      <span class="msg">{m.billingbanner_trial({ date: trialEndsOn })}</span>
      <a class="cta" href="/account#billing">{m.billingbanner_trial_cta()}</a>
    {:else if state === 'needs_activation'}
      <span class="msg">{m.billingbanner_needs_activation()}</span>
      <a class="cta" href="/account#billing">{m.billingbanner_choose_plan()}</a>
    {:else if state === 'lapsed'}
      <span class="msg">{m.billingbanner_lapsed()}</span>
      <a class="cta" href="/account#billing">{m.billingbanner_manage_subscription()}</a>
    {:else if state === 'over_quota'}
      <span class="msg">{m.billingbanner_over_quota()}</span>
      <a class="cta" href="/account#billing">{m.billingbanner_manage_plan()}</a>
    {:else if state === 'prsn_lapsed'}
      <span class="msg">{m.billingbanner_prsn_lapsed()}</span>
    {:else if state === 'prsn_over_quota'}
      <span class="msg">{m.billingbanner_prsn_over_quota()}</span>
    {/if}
  </div>
{/if}

<style>
  .banner {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-wrap: wrap;
    gap: 0.4rem 0.9rem;
    padding: 0.7rem 1.5rem;
    background: #fbf4e6;
    border-bottom: 1px solid #ecdcb8;
    color: #7a5a1e;
    font-size: 0.9rem;
    line-height: 1.45;
    text-align: center;
  }
  .msg {
    max-width: 70ch;
  }
  .cta {
    color: #7a5a1e;
    font-weight: 600;
    text-decoration: underline;
    white-space: nowrap;
  }
  .cta:hover {
    color: #5e4416;
  }
</style>
