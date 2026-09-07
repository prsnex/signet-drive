<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { goto } from '$app/navigation';
  import type { AccountStore } from '$lib/account.svelte';
  import type { GarnetStore } from '$lib/garnet.svelte';
  import type { GarnetGrant, GuardedPrsn } from '$lib/api';
  import { prsnStateTagFromGrants, type PrsnStateTag } from '$lib/garnet';
  import { formatCapability, formatDateTime, formatDeletionHour } from '$lib/format';
  import { m } from '$lib/paraglide/messages.js';
  import Modal from '$lib/components/Modal.svelte';
  import { loadPrsnSectionPref, prsnSectionVisible, savePrsnSectionPref } from '$lib/prsn-section';
  import SealImpression from '$lib/seal/SealImpression.svelte';
  import { identitySeed } from '$lib/seal/seed';

  // §1-64 (S166, Chris-approved mock-up): THE one PRSN card. One row per PRSN —
  // handle · Verified · sharing capability · ONE state tag · the actions that
  // state allows. The old second card ("Signet Drive Account Access Management")
  // is deleted; its grant actions live inline here, its dialogs + the machine
  // setup card remain in GarnetPanel (the dialog host). The two-card split was
  // the bug148/150/151 family's root: two cards answering one question gave
  // every state two chances to be mis-rendered, and the never-authorized state
  // rendered NOWHERE except a dropdown inside the Authorize dialog.
  let { store, garnet }: { store: AccountStore; garnet: GarnetStore } = $props();

  // bug098: at the guardian's effective PRSN cap, "+ Add PRSN" must not walk the
  // guardian into a wizard the server will only reject on Continue. Fail fast on
  // the same numbers the server `confirm` gate uses (prsn_count / prsn_cap, both
  // from /v1/me) — so the button and the server can never disagree. Data-absent
  // (still loading) reads as not-at-cap; the wizard PAGE gate is the structural
  // backstop for that race and for direct navigation.
  const atCap = $derived(
    store.me?.prsn_cap != null &&
      store.me?.prsn_count != null &&
      store.me.prsn_count >= store.me.prsn_cap,
  );
  let showCapModal = $state(false);
  let showBrokerModal = $state(false);

  // bug154 §2c: the fast-path broker gate. Block ONLY the certain case — no
  // broker at all (the wizard's `signet` command can only fail). Loading reads
  // as not-blocked, same as the cap gate's data-absent rule: the wizard PAGE
  // gate is the structural backstop. With a broker present we assert nothing
  // about THIS Mac (per-guardian, not per-Mac — S164 §E).
  const noBroker = $derived(!garnet.loading && !garnet.hasBroker);

  // "+ Add PRSN" opens a server enrollment rendezvous and sends the Guardian to the
  // confirm-and-approve page (no hand-transcription — S052). The agent reaches the
  // same page directly via `signet enroll`.
  async function startAddPrsn() {
    if (atCap) {
      showCapModal = true;
      return;
    }
    if (noBroker) {
      showBrokerModal = true;
      return;
    }
    // §1-62: the wizard names FIRST and mints on Continue (design note §5) — this
    // is now a plain navigation; the enrollment row is created at the hand-off step.
    await goto('/account/add-prsn');
  }

  function goToGarnetSetup(): void {
    showBrokerModal = false;
    // Same page — the setup card renders inside GarnetPanel whenever no broker
    // is registered; scrolling is the whole routing.
    document.getElementById('garnet')?.scrollIntoView({ behavior: 'smooth' });
  }

  function attestationLabel(prsn: GuardedPrsn): string {
    const a = prsn.attestation;
    if (!a) return m.guardianprsns_no_attestation();
    if (a.status === 'active') return m.guardianprsns_att_valid();
    if (a.status === 'revoked') return m.guardianprsns_att_revoked();
    if (a.status === 'expired') return m.guardianprsns_att_expired();
    return a.status;
  }

  // The row's grant, for the meta dates and the grant-action targets. Display
  // metadata + action routing only, joined by handle — the identity binding is
  // the server's `prsn_account_id` FK; nothing here decides access.
  function activeGrantFor(prsn: GuardedPrsn): GarnetGrant | undefined {
    return garnet.grants.find((g) => g.prsn_handle === prsn.handle && g.status === 'active');
  }

  // The seven-tag vocabulary (v02 design doc, Chris ruled Option B + the
  // WRITES PAUSED rename). Message functions keyed by tag; tooltips on every
  // tag (the prsn_pending_deletion_tip / garnet_waiting_tip copy is reused
  // verbatim where it already said the right thing).
  const TAG_LABEL: Record<PrsnStateTag, () => string> = {
    active: m.prsn_tag_active,
    not_authorized: m.prsn_tag_not_authorized,
    waiting_to_connect: m.prsn_tag_waiting,
    writes_paused: m.prsn_tag_writes_paused,
    stopped: m.prsn_tag_stopped,
    pending_deletion: m.prsn_tag_pending_deletion,
    revoked: m.prsn_tag_revoked,
    contested: m.prsn_tag_contested,
  };
  const TAG_TIP: Record<PrsnStateTag, () => string> = {
    active: m.prsn_tag_active_tip,
    not_authorized: m.prsn_tag_not_authorized_tip,
    waiting_to_connect: m.garnet_waiting_tip,
    writes_paused: m.prsn_tag_writes_paused_tip,
    stopped: m.prsn_tag_stopped_tip,
    pending_deletion: m.prsn_pending_deletion_tip,
    revoked: m.prsn_tag_revoked_tip,
    contested: m.garnet_contested_note,
  };

  const busy = $derived(store.busy || garnet.busy);

  // bug196 item 5: whether the DASHBOARD sidebar shows the PRSN section. Seeded
  // from the derived rule so a Guardian who has never touched this sees the right
  // thing on both surfaces without having chosen anything.
  // The user's EXPLICIT choice is the state; what the switch shows is DERIVED from
  // it plus the account. Seeding a plain $state from store.prsns.length would
  // capture only its initial value, so a Guardian enrolling their first PRSN would
  // not see the switch follow.
  let prsnSectionPref = $state<boolean | null>(loadPrsnSectionPref());
  const showInDashboard = $derived(prsnSectionVisible(prsnSectionPref, store.prsns.length));
  function setShowInDashboard(next: boolean): void {
    prsnSectionPref = next;
    savePrsnSectionPref(next);
  }
</script>

<!-- id="prsns" is the scroll target for the sidebar "+ PRSN" deep-link (Bug017, Option A). -->
<section class="prsns card" id="prsns">
  <div class="head">
    <h2>{m.guardianprsns_title()}</h2>
    <!-- bug196 item 7: the hint reuses item 6's message key. ONE string, two
         placements, so the two statements cannot drift apart. Native title
         deliberately (Chris dropped the fast-acting requirement): the same text is
         permanently visible just below, so this is a convenience, not the channel. -->
    <button
      class="add"
      onclick={startAddPrsn}
      disabled={busy}
      title={m.guardianprsns_requirement()}
    >
      {m.guardianprsns_add()}
    </button>
  </div>

  <!-- ⚠⚠ bug196 item 6: the requirement is about the PRSN'S machine, NOT the
       guardian's. The wording first proposed ("only possible if YOU are using an
       Apple computer with M1 or newer") states the opposite of our own settled
       decision — ROOTS §C-3.6: guardian auth is a device-portable passkey, and the
       Apple-Silicon requirement is PRSN-side only. A guardian on Windows can
       legitimately manage a PRSN that lives on a Mac, and the wrong text would have
       turned away users who can actually use the feature.

       Inline, not a tooltip: tooltips do not work on touch, are awkward for
       keyboard users, and hide exactly what a newcomer most needs. -->
  <p class="requirement">{m.guardianprsns_requirement()}</p>

  <!-- bug196 item 5: governs the DASHBOARD sidebar only; this card is always
       visible, so the control can never hide itself. The default is DERIVED (see
       $lib/prsn-section) — a flat "off" would have hidden the section from
       Guardians actively using it. -->
  <label class="dash-toggle">
    <input
      type="checkbox"
      role="switch"
      checked={showInDashboard}
      onchange={(e) => setShowInDashboard(e.currentTarget.checked)}
    />
    <span>{m.guardianprsns_show_in_dashboard()}</span>
  </label>

  {#if store.prsns.length === 0}
    <p class="empty">{m.guardianprsns_empty()}</p>
  {:else}
    <ul>
      {#each store.prsns as prsn (prsn.account_id)}
        <!-- The tag derives from the LIVE grants list (GarnetStore — refreshed at
             every ceremony + hot-poll tick), never from the roster's grant_state
             snapshot: the roster is fetched at page mount, so a snapshot-derived
             tag would sit stale through every authorize/revoke until a reload
             (caught by the garnet e2e). The sidebar, which holds no grants list,
             is the surface the server projection serves. -->
        {@const tag = garnet.loading ? null : prsnStateTagFromGrants(prsn, garnet.grants)}
        {@const grant = activeGrantFor(prsn)}
        <li class:inactive={tag === 'pending_deletion' || tag === 'revoked'}>
          <div class="top">
            <SealImpression seed={identitySeed(null, prsn.handle)} size={22} />
            <span class="handle" title={prsn.handle ?? ''}>{prsn.handle ?? '—'}</span>
            <span
              class="att"
              class:verified={prsn.attestation?.status === 'active'}
              class:revoked={prsn.attestation?.status !== 'active'}
              title={prsn.attestation?.key_protection}
            >
              {attestationLabel(prsn)}
            </span>
            {#if tag}
              <!-- ONE state tag per row (tooltips on all — Chris). N-1 fallback:
                   no recognizable state ⇒ no tag, never a guess. -->
              <span class="tag {tag}" title={TAG_TIP[tag]()}>{TAG_LABEL[tag]()}</span>
            {/if}
          </div>
          <div class="meta">
            <!-- bug156 §4.4 (Chris ruled displace-both, S168): a pending-deletion row
                 drops the capability line too — access is already blocked, so
                 "Can share, …" asserts something currently false. -->
            {#if tag !== 'pending_deletion'}
              <span class="cap"
                >{m.guardianprsns_sharing({
                  cap: formatCapability(prsn.prsn_sharing_capability),
                })}</span
              >
            {/if}
            {#if tag === 'pending_deletion'}
              <!-- bug156: the deletion statement REPLACES "Confirmed …" here — the
                   grant's last_confirmed_at is unrelated to the deletion clock, and as
                   the only date on the row it invited reading it as the anchor (the
                   measured gap on the two live S167 rows was 4–5 days). `deletes_at`
                   is server-computed; absent (older server) ⇒ no date, never a guess. -->
              {#if prsn.deletes_at != null}
                <span
                  >{m.guardianprsns_deletes_at({ date: formatDeletionHour(prsn.deletes_at) })}</span
                >
              {/if}
            {:else if grant?.last_confirmed_at}
              <span>{m.garnet_confirmed_at({ date: formatDateTime(grant.last_confirmed_at) })}</span
              >
            {/if}
            {#if tag === 'active' && grant?.reconfirm_deadline_at != null}
              <span
                >{m.garnet_reconfirm_by({
                  date: formatDateTime(grant.reconfirm_deadline_at),
                })}</span
              >
            {/if}
          </div>
          {#if tag === 'contested'}
            <!-- bug042: the one badge whose meaning decides "alarm or all-clear"
                 gets its explainer inline — a guardian must not have to ask. -->
            <p class="note">{m.garnet_contested_note()}</p>
          {:else if tag === 'waiting_to_connect' && prsn.handle}
            <!-- bug148 (Chris ruled the line, S168): the waiting state names the next
                 action INLINE — the old guidance lived only in a hover tip, and "the
                 guidance in the human UI is not adequate" was his standing note. -->
            <p class="note">{m.garnet_waiting_note({ handle: prsn.handle })}</p>
          {:else if tag === 'writes_paused' && prsn.handle}
            <p class="note">{m.garnet_grace_note({ handle: prsn.handle })}</p>
          {:else if tag === 'stopped' && prsn.handle}
            <p class="note">{m.garnet_stopped_note({ handle: prsn.handle })}</p>
          {/if}
          <div class="actions">
            <!-- The v02 actions table: what each state allows, inline. Grant
                 gestures ride GarnetStore (ceremonies); identity actions ride
                 AccountStore. Grant buttons guard on the grant row existing —
                 the two lists refresh independently, and a momentarily-missing
                 grant must no-op rather than throw. -->
            {#if tag === 'not_authorized'}
              <button
                class="primary"
                onclick={() => garnet.openAuthorize(prsn.account_id)}
                disabled={busy}
              >
                {m.garnet_authorize_confirm()}
              </button>
            {/if}
            {#if (tag === 'writes_paused' || tag === 'stopped' || (tag === 'active' && grant?.reconfirm_available)) && grant}
              <button class="primary" onclick={() => garnet.openConfirm(grant)} disabled={busy}>
                {m.garnet_reconfirm_btn()}
              </button>
            {/if}
            {#if tag === 'revoked'}
              <button
                class="primary"
                onclick={() => void garnet.authorize(prsn.account_id)}
                disabled={busy}
                title={m.garnet_reauthorize_tip()}
              >
                {m.garnet_reauthorize_btn()}
              </button>
            {/if}
            {#if tag === 'waiting_to_connect' && prsn.handle}
              {@const handle = prsn.handle}
              <button onclick={() => (garnet.instructionsFor = handle)} disabled={busy}>
                {m.garnet_instructions_btn()}
              </button>
            {/if}
            {#if tag === 'active' || tag === 'not_authorized' || tag == null}
              <button
                onclick={() => store.openSetCapability(prsn)}
                disabled={busy}
                title={m.guardianprsns_change_cap_tip()}
              >
                {m.guardianprsns_change_cap()}
              </button>
            {/if}
            {#if (tag === 'active' || tag === 'waiting_to_connect' || tag === 'writes_paused' || tag === 'stopped' || tag === 'contested') && grant}
              <button
                onclick={() => garnet.openRevoke(grant)}
                disabled={busy}
                title={m.garnet_revoke_tip()}
              >
                {m.garnet_revoke_btn()}
              </button>
            {/if}
            {#if tag === 'active' || tag === 'not_authorized' || tag === 'revoked' || tag == null}
              <button
                class="del"
                onclick={() => store.openDeletePrsn(prsn)}
                disabled={busy}
                title={m.guardianprsns_delete_tip()}
              >
                {m.guardianprsns_delete()}
              </button>
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
  {#if garnet.error && !garnet.dialog}<p class="panel-error">{garnet.error}</p>{/if}
</section>

{#if showCapModal}
  <!-- bug098: the effective-cap message (never a hardcoded 8 — it is 2 for an
       un-upgraded trial guardian, 8 for a paid one; prsn_cap carries the right one). -->
  <Modal title={m.addprsn_cap_title()} onClose={() => (showCapModal = false)}>
    <p class="cap-hint">{m.addprsn_cap_body({ n: store.me?.prsn_cap ?? 0 })}</p>
    {#snippet footer()}
      <button class="confirm" onclick={() => (showCapModal = false)}>{m.addprsn_cap_ok()}</button>
    {/snippet}
  </Modal>
{/if}

{#if showBrokerModal}
  <!-- bug154 §2c: the no-broker gate — the one state where starting the wizard
       can only end at a failing command. Routes to the setup card on this page. -->
  <Modal title={m.addprsn_broker_gate_title()} onClose={() => (showBrokerModal = false)}>
    <p class="cap-hint">{m.addprsn_broker_gate_body()}</p>
    {#snippet footer()}
      <button class="confirm" onclick={goToGarnetSetup}>{m.addprsn_broker_gate_go()}</button>
    {/snippet}
  </Modal>
{/if}

<style>
  /* bug196 items 5-6 */
  .requirement {
    margin: 0.35rem 0 0.6rem;
    color: var(--ink-soft);
    font-size: 0.85rem;
  }
  .dash-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.9rem;
    color: var(--ink-soft);
    font-size: 0.88rem;
    cursor: pointer;
  }
  .prsns {
    margin: 0;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.8rem;
  }
  h2 {
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0;
  }
  .add {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--accent);
    font: inherit;
    font-size: 0.85rem;
    font-weight: 600;
    padding: 0.4rem 0.8rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .add:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .add:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .empty {
    color: var(--muted);
    font-size: 0.92rem;
    margin: 0;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
    /* bug093-2: scroll at ~4 PRSN cards so a full guardian (up to 8) keeps the card
       compact and the rest of the page reachable; "+ Add PRSN" is in the header,
       outside this list. A partial fifth peeks to signal there's more below. */
    max-height: 26rem;
    overflow-y: auto;
    padding-right: 0.15rem;
  }
  li {
    /* bug100 (S152 redesign): buttons IN-LINE with the text — a two-column grid
       (text left, actions right, vertically centered) collapses the empty third
       row each card used to spend on its own actions row. */
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    column-gap: 1.25rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    /* ~50% more vertical padding for breathing room between each row's outline
       and its content. */
    padding: 1.2rem 0.9rem;
    background: var(--surface);
  }
  li.inactive {
    opacity: 0.7;
  }
  .top {
    grid-column: 1;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
    /* let the flexed handle shrink so its ellipsis engages instead of shoving the
       actions column (bug100 handle-truncation). */
    min-width: 0;
  }
  .handle {
    font-weight: 600;
    /* bug100: a long handle truncates rather than shoving the badge/buttons; the
       full handle rides the title tooltip. */
    display: inline-block;
    max-width: 20rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    vertical-align: bottom;
  }
  .att {
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--muted);
    background: var(--surface-2);
    border-radius: 999px;
    padding: 0.12rem 0.55rem;
  }
  .att.verified {
    color: var(--positive);
    background: var(--positive-bg);
  }
  .att.revoked {
    color: var(--danger);
    background: var(--danger-bg);
  }
  /* §1-64: the ONE state tag. Same geometry as the old status chip; the seven
     states get four visual families — good (positive), needs-you (accent),
     paused/warn (amber), and gone/alarm (danger, muted for history). Every tag
     carries a title tooltip, so cursor:help. */
  .tag {
    font-size: 0.74rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-weight: 600;
    padding: 0.1rem 0.45rem;
    border-radius: 4px;
    cursor: help;
  }
  .tag.active {
    color: var(--positive);
    background: var(--positive-bg);
  }
  .tag.not_authorized {
    color: var(--accent);
    background: var(--accent-soft);
  }
  .tag.waiting_to_connect {
    color: #8a5a00;
    background: #fdf6e8;
  }
  .tag.writes_paused {
    color: #8a5a00;
    background: #fdf6e8;
  }
  .tag.stopped,
  .tag.pending_deletion,
  .tag.contested {
    color: var(--danger);
    background: var(--danger-bg);
  }
  .tag.revoked {
    color: var(--muted);
    background: var(--surface-2);
    border: 1px solid var(--border);
  }
  .meta {
    grid-column: 1;
    display: flex;
    /* §1-64: the meta line now carries capability + grant dates — it must wrap
       (the old single-span line never needed to; on a phone this one does). */
    flex-wrap: wrap;
    gap: 0.35rem 0.9rem;
    margin-top: 0.35rem;
    font-size: 0.82rem;
    color: var(--ink-soft);
  }
  .note {
    grid-column: 1 / -1;
    margin: 0.55rem 0 0;
    font-size: 0.82rem;
    color: var(--ink-soft);
    background: var(--surface-2);
    border-left: 3px solid var(--border);
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
  }
  .actions {
    /* bug100 (S152 redesign): actions live in grid column 2, vertically centered
       against the full text block, filling the wasted horizontal space. */
    grid-column: 2;
    grid-row: 1 / -1;
    align-self: center;
    justify-self: end;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0;
    justify-content: flex-end;
  }
  .actions button {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.82rem;
    padding: 0.34rem 0.7rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .actions button:hover:not(:disabled) {
    border-color: var(--muted);
  }
  .actions .primary {
    border-color: var(--accent);
    color: var(--accent);
    font-weight: 600;
  }
  .actions .primary:hover:not(:disabled) {
    border-color: var(--accent-hover);
  }
  .actions .del {
    color: var(--danger);
  }
  .actions .del:hover:not(:disabled) {
    border-color: var(--danger);
  }
  .actions button:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .panel-error {
    margin: 0.7rem 0 0;
    color: var(--danger);
    font-size: 0.85rem;
  }
  /* bug100: on a narrow viewport, return to a single column with the actions on
     their own row (keeps the existing wrap so nothing is crushed). */
  @media (max-width: 40rem) {
    li {
      grid-template-columns: 1fr;
    }
    .actions {
      grid-column: 1;
      grid-row: auto;
      justify-self: stretch;
      justify-content: flex-end;
      margin-top: 0.7rem;
    }
  }
  /* bug098 cap-modal: local copies of the account page's hint + confirm recipe
     (Modal renders the footer snippet as-is; the button styling is the host's). */
  .cap-hint {
    margin: 0;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
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
  .confirm:hover {
    background: var(--accent-hover);
  }
</style>
