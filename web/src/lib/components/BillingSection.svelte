<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // The human account's billing section (D2 web cluster), three states keyed off
  // /v1/me: never-activated → subscribe-to-activate (the tiers + a card-up-front
  // checkout); lapsed (read_only) → recover via the Stripe portal; active → a plan
  // summary + the portal. Prop-driven + DOM-light: the parent owns the store and
  // performs the redirect; this only renders + emits intent. PRSNs never see it
  // (they draw from a Guardian's pooled quota and never bill).
  import type { MeResponse, QuotaResponse, TierAmount } from '$lib/api';
  import { formatBytes, formatDate, formatDeadline } from '$lib/format';
  import { formatTierAmounts, sortTiers, tierDisplayName } from '$lib/billing';
  import { m } from '$lib/paraglide/messages.js';

  let {
    me,
    tiers,
    tierPrices = undefined,
    quota,
    busy,
    onSubscribe,
    onAddCard,
    onManage,
  }: {
    me: MeResponse;
    tiers: string[];
    /** bug171: per-currency amounts by tier; absent => labels only (degrade). */
    tierPrices?: Record<string, TierAmount[]> | undefined;
    quota: QuotaResponse | null;
    busy: boolean;
    onSubscribe: (tier: string) => void;
    onAddCard: () => void;
    onManage: () => void;
  } = $props();
</script>

<section class="billing card" id="billing">
  <h2>{m.billingsection_title()}</h2>
  {#if me.needs_activation}
    <!-- A two-window free trial (S134): usable now. Before the one-time card
         extension (S135) the account can add a card to extend the free window (never
         charged) or upgrade; once carded (trial_card_added) it can only upgrade — a
         carded trial cannot re-extend, so the status text + the Add-a-card button
         both switch off. -->
    <p class="why-card">
      {#if me.trial_card_added}
        {m.billingsection_trial_status_carded({ date: formatDeadline(me.paid_until) })}
      {:else}
        {m.billingsection_trial_status({ date: formatDeadline(me.paid_until) })}
      {/if}
    </p>
    {#if !me.trial_card_added}
      <button class="ghost add-card" onclick={onAddCard} disabled={busy}>
        {m.billingsection_add_card()}
      </button>
    {/if}
    {#if tiers.length}
      <p class="upgrade-lead">{m.billingsection_upgrade_lead()}</p>
      <div class="tiers">
        {#each sortTiers(tiers) as tier (tier)}
          <div class="tier">
            <div class="tier-name">
              <span class="tier-size">{tierDisplayName(tier)}</span>
              <!-- bug171 (ruled Option 3): both currencies, fetched from Stripe
                   via the server — never typed into copy. Absent amounts render
                   nothing here: the pre-bug171 screen is the degrade state. -->
              {#if tierPrices?.[tier]?.length}
                <span class="tier-price">{formatTierAmounts(tierPrices[tier])}</span>
              {/if}
              <span class="tier-cadence">{m.billingsection_per_month()}</span>
            </div>
            <button class="confirm" onclick={() => onSubscribe(tier)} disabled={busy}>
              {m.billingsection_upgrade()}
            </button>
          </div>
        {/each}
      </div>
      <p class="price-note">{m.billingsection_price_note()}</p>
    {:else}
      <p class="muted-note">{m.billingsection_unavailable()}</p>
    {/if}
  {:else if me.read_only}
    <p class="hint">
      {m.billingsection_lapsed_1()}{me.paid_until
        ? m.billingsection_lapsed_on({ date: formatDate(me.paid_until) })
        : ''}{m.billingsection_lapsed_2()}
    </p>
    <button class="confirm" onclick={onManage} disabled={busy}>{m.billingsection_manage()}</button>
  {:else}
    <p class="hint">
      {m.billingsection_active_1()}{quota
        ? m.billingsection_active_plan({ size: formatBytes(quota.bytes_quota) })
        : ''}{m.billingsection_active_2({ date: formatDate(me.paid_until) })}
    </p>
    <!-- bug074: an active subscriber had NO discoverable way to change tiers — the only
         control was "Manage subscription", which does not read as "upgrade" (§3). Both
         buttons open the same Stripe portal; the labelled one is what a user looking to
         move tiers will recognize. The policy line states the S168-ruled proration so the
         consequence is known BEFORE the redirect, not discovered inside Stripe. -->
    <p class="policy">{m.billingsection_change_policy()}</p>
    <div class="actions">
      <button class="confirm" onclick={onManage} disabled={busy}>
        {m.billingsection_change_plan()}
      </button>
      <button class="ghost" onclick={onManage} disabled={busy}>{m.billingsection_manage()}</button>
    </div>
  {/if}
</section>

<style>
  .billing {
    margin: 0;
  }
  .billing h2 {
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0 0 1.1rem;
  }
  .billing h2 {
    font-size: 1rem;
    font-weight: 600;
    margin: 0 0 0.8rem;
  }
  .why-card {
    margin: 0 0 1.1rem;
    color: var(--ink-soft);
    font-size: 0.9rem;
    line-height: 1.55;
  }
  .add-card {
    margin: 0 0 1.4rem;
  }
  .upgrade-lead {
    margin: 0 0 0.8rem;
    color: var(--ink-soft);
    font-size: 0.9rem;
    font-weight: 600;
  }
  .tiers {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .tier {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.6rem 1rem;
    padding: 0.8rem 1rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface);
  }
  .tier-name {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }
  .tier-size {
    font-size: 1.05rem;
    font-weight: 600;
    color: var(--ink);
    white-space: nowrap;
  }
  .tier-cadence {
    font-size: 0.85rem;
    color: var(--muted);
    white-space: nowrap;
  }
  /* bug171: the both-currencies amount (`CA$6 / US$5`) — between size and
     cadence, weighted under the size but above the muted cadence, because it
     is the number the decision is made on. */
  .tier-price {
    font-size: 0.95rem;
    font-weight: 500;
    color: var(--ink);
    white-space: nowrap;
  }
  .price-note {
    margin: 0.8rem 0 0;
    font-size: 0.82rem;
    color: var(--muted);
  }
  .muted-note {
    margin: 0;
    color: var(--muted);
    font-size: 0.9rem;
  }
  .hint {
    margin: 0 0 1rem;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  /* bug074: the proration policy, stated before the redirect. */
  .policy {
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
    line-height: 1.5;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
  }
  .confirm {
    border: 0;
    background: var(--accent);
    color: var(--on-accent);
    font: inherit;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .ghost {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-weight: 500;
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .ghost:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .confirm:disabled,
  .ghost:disabled {
    opacity: 0.55;
    cursor: default;
  }
</style>
