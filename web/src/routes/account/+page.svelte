<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import { onDestroy, tick, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { tooltip } from '$lib/tooltip';
  import Wordmark from '$lib/components/Wordmark.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import GuardianPrsns from '$lib/components/GuardianPrsns.svelte';
  import GarnetPanel from '$lib/components/GarnetPanel.svelte';
  import SetupDeadlineWarning from '$lib/components/SetupDeadlineWarning.svelte';
  import AccountHistory from '$lib/components/AccountHistory.svelte';
  import BillingSection from '$lib/components/BillingSection.svelte';
  import SealImpression from '$lib/seal/SealImpression.svelte';
  import { meSeed } from '$lib/seal/seed';
  import { AccountStore } from '$lib/account.svelte';
  import { GarnetStore } from '$lib/garnet.svelte';
  import { createApiClient } from '$lib/api';
  import { persistSession, purgePersisted, restoreSession } from '$lib/persist';
  import { sessionStore } from '$lib/session.svelte';
  import { formatBytes, formatCapability, formatDate } from '$lib/format';
  import { m } from '$lib/paraglide/messages.js';

  // Suppresses the auth-redirect during the deliberate post-self-delete navigation
  // (we clear the session ourselves, then leave the page).
  let leaving = $state(false);

  // /account requires a session — same model as the file browser: a refresh clears
  // the in-memory KEM session and sends you back to sign-in — unless the S116
  // persisted-unlock restore recovers it (the no-reload standard: a reload on
  // this page must not force a gesture). Restore failure → today's redirect.
  let restoring = false;
  $effect(() => {
    if (leaving || sessionStore.current || restoring) return;
    restoring = true;
    void restoreSession()
      .then((restored) => {
        if (restored && !sessionStore.current) sessionStore.set(restored);
        else if (!restored && !leaving && !sessionStore.current) void goto('/signin');
      })
      .finally(() => {
        restoring = false;
      });
  });

  const store = untrack(() => new AccountStore());
  void store.init();
  // bug095: ONE GarnetStore instance, owned here and shared by GarnetPanel (which
  // manages its lifecycle) and the relocated Mac-setup card at the page bottom, so
  // both read the same reactive broker/grant state.
  const garnetStore = untrack(() => new GarnetStore());
  // Bug033-1b: drop the refetch-on-return listener when the page unmounts.
  onDestroy(() => store.dispose());

  // The signed-in identity's own seal — its key fingerprint per type (a PRSN's
  // signing fp, a human's KEM fp; else the handle).
  const ownSeed = $derived(meSeed(store.me));

  // Honor a "#prsns" deep-link from the sidebar "+ PRSN" entry (Bug017, Option A):
  // once the page's data has loaded, scroll the PRSN-management section into view.
  // SvelteKit's own hash scroll can fire before the async content exists, so we do it
  // ourselves — once.
  let scrolledToPrsns = false;
  $effect(() => {
    if (scrolledToPrsns || store.loading) return;
    if (typeof location !== 'undefined' && location.hash === '#prsns') {
      scrolledToPrsns = true;
      void tick().then(() => {
        document.getElementById('prsns')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }
  });

  // Local confirm-form state, reset as each dialog opens.
  let setCapValue = $state<'none' | 'read_only' | 'read_write'>('read_only');
  let deletePrsnHandle = $state('');
  let deleteOwnHandle = $state('');

  $effect(() => {
    const d = store.dialog;
    if (d?.kind === 'setCapability') {
      const c = d.prsn.prsn_sharing_capability;
      setCapValue = c === 'none' || c === 'read_write' ? c : 'read_only';
    }
    if (d?.kind === 'deletePrsn') deletePrsnHandle = '';
    if (d?.kind === 'deleteOwn') deleteOwnHandle = '';
  });

  async function confirmDeleteOwn() {
    const outcome = await store.deleteOwn(deleteOwnHandle);
    if (outcome) {
      leaving = true;
      await purgePersisted(); // the account is gone — so is its persisted unlock
      sessionStore.clear();
      await goto('/');
    }
  }

  async function rotatePasskey() {
    const session = sessionStore.current;
    if (!session) return;
    const newBlob = await store.rotatePasskey(session.wrappedKemPrivkeyBlob);
    if (newBlob) {
      // The KEM keypair is unchanged — only its wrap envelope rotated. Keep the
      // live (non-extractable) session key; swap in the new blob so the session
      // stays usable + a subsequent rotation works.
      const updated = { ...session, wrappedKemPrivkeyBlob: newBlob };
      sessionStore.set(updated);
      // Rotation is a real (3-gesture) ceremony — re-persist with the new blob
      // so the record stays rotation-current (design §3.4; S116).
      void persistSession(updated);
    }
  }

  // Billing redirects leave the app for a Stripe-hosted page; the store creates the
  // URL (DOM-free) and we navigate. `window.location` is a full external nav (goto
  // is for in-app SPA routes only). The in-memory KEM session is lost on the
  // round-trip — that is inherent (the key is non-extractable); the user re-auths
  // with one passkey tap on return.
  async function subscribe(tier: string) {
    const url = await store.startCheckout(tier);
    if (url) window.location.href = url;
  }

  async function addCard() {
    const url = await store.addCard();
    if (url) window.location.href = url;
  }

  async function manageBilling() {
    const url = await store.openBillingPortal();
    if (url) window.location.href = url;
  }

  async function lock() {
    // Same move as the file browser's Lock (S121 review, W12 — the affordance
    // belongs wherever the session is visible): purge the persisted capability +
    // drop the in-memory session, keep the server session; "/" shows the one-tap
    // re-unlock.
    await purgePersisted();
    sessionStore.clear();
    goto('/');
  }

  async function signOut() {
    // `leaving` suppresses the auth-redirect effect so sign-out lands on the
    // landing page deterministically (not a race with the effect's /signin).
    leaving = true;
    // Purge the persisted unlock BEFORE the logout POST — the local purge must
    // never depend on the network call landing (S116 unlock persistence).
    await purgePersisted();
    // End the server session FIRST (clears the cookie) so the landing's re-unlock
    // probe doesn't see a still-valid cookie and offer to re-unlock (Bug014).
    // Best-effort — a failed logout still clears locally.
    try {
      await createApiClient().logout();
    } catch {
      // ignore — fall through to the local clear
    }
    sessionStore.clear();
    void goto('/');
  }
</script>

<svelte:head>
  <title>Signet Drive — Account Settings</title>
</svelte:head>

<div class="page">
  <header class="bar">
    <Wordmark />
    <div class="acct">
      <a class="back" href="/" use:tooltip={m.account_back_to_drive_title()}
        ><span aria-hidden="true">←</span> {m.account_back_to_drive_link()}</a
      >
      {#if store.me?.admin_role}<a class="link" href="/admin">{m.account_admin()}</a>{/if}
      <button class="signout" onclick={lock} use:tooltip={m.filebrowser_lock_title()}>
        {m.filebrowser_lock()}
      </button>
      <button class="signout" onclick={signOut} use:tooltip={m.account_sign_out_title()}
        >{m.account_sign_out()}</button
      >
    </div>
  </header>

  {#if store.loading}
    <div class="loading"><span class="spinner" aria-hidden="true"></span>{m.account_loading()}</div>
  {:else if store.me}
    {@const me = store.me}
    <main>
      <h1>{m.account_title()}</h1>

      <div class="dashboard">
        <nav class="section-nav" aria-label={m.account_sections_label()}>
          <a href="#identity">{m.account_section_identity()}</a>
          {#if !store.isPrsn}
            <a href="#billing">{m.account_section_plan()}</a>
            <a href="#prsns">{m.guardianprsns_title()}</a>
            <!-- bug157: same predicate as the GarnetPanel card it targets — the nav
                 must not assert a section the page derives differently. With a broker
                 registered (the common steady state) the card doesn't render, so the
                 link was a dead anchor for the rest of the account's life. -->
            {#if !garnetStore.loading && !garnetStore.hasBroker}
              <a href="#garnet">{m.account_section_garnet()}</a>
            {/if}
          {/if}
          <a href="#history">{m.account_section_history()}</a>
        </nav>

        <div class="cards">
          <section class="card" id="identity">
            <h2>{m.account_section_identity()}</h2>
            <div class="identity-head">
              <SealImpression seed={ownSeed} size={48} />
              <div class="identity-who">
                <div class="handle-lg">{me.handle ?? '—'}</div>
                <div class="sub-lines">
                  {#if !store.isPrsn && me.email}<span>{me.email}</span>{/if}
                  <span>{m.account_joined_on({ date: formatDate(me.created_at) })}</span>
                </div>
              </div>
            </div>

            <dl class="facts">
              {#if store.isPrsn}
                {#if me.guardian}
                  <div class="fact">
                    <dt>{m.account_guardian()}</dt>
                    <dd>{me.guardian.handle ?? '—'}</dd>
                  </div>
                {/if}
                <div class="fact">
                  <dt>{m.account_sharing_capability()}</dt>
                  <dd>{formatCapability(me.prsn_sharing_capability)}</dd>
                </div>
                {#if me.attestation}
                  <div class="fact">
                    <dt>{m.account_attestation()}</dt>
                    <dd>
                      {#if me.attestation.status === 'active'}
                        <span class="chip pos" title={m.account_verified_desc()}
                          >{m.account_verified()}</span
                        >
                      {:else}
                        <span class="chip mut">{me.attestation.status}</span>
                      {/if}
                      {#if me.attestation.expires_at}
                        <span class="expires"
                          >{m.account_attestation_expires({
                            date: formatDate(me.attestation.expires_at),
                          })}</span
                        >
                      {/if}
                    </dd>
                  </div>
                {/if}
              {:else}
                <div class="fact">
                  <dt>{m.account_paid_until()}</dt>
                  <dd>{formatDate(me.paid_until)}</dd>
                </div>
              {/if}
              {#if store.quota}
                <div class="fact">
                  <dt>{m.account_storage_used()}</dt>
                  <dd>
                    {formatBytes(store.quota.bytes_used)} / {formatBytes(store.quota.bytes_quota)}
                  </dd>
                </div>
              {/if}
            </dl>
          </section>

          {#if store.isPrsn}
            <section class="card">
              <p class="guardian-note">{m.account_guardian_note()}</p>
              <p class="guardian-note">{m.account_device_loss_note()}</p>
            </section>
          {:else}
            <BillingSection
              {me}
              tiers={store.tiers}
              tierPrices={store.tierPrices}
              quota={store.quota}
              busy={store.billingBusy}
              onSubscribe={subscribe}
              onAddCard={addCard}
              onManage={manageBilling}
            />
            <GuardianPrsns {store} garnet={garnetStore} />
            <GarnetPanel store={garnetStore} />
            <!-- bug114 Part B: the 5-min setup-deadline warning rides the same shared
                 GarnetStore (its /v1/me/prsns poll carries setup_deadline). -->
            <SetupDeadlineWarning store={garnetStore} />
          {/if}

          <section class="card" id="history">
            <h2>{m.account_section_history()}</h2>

            <!-- bug110: the verification content (transparency-log link + Key fingerprints)
                 lives here in Account Details, relocated off the Identity card — Identity
                 keeps who-you-are + billing/storage only. The transparency-log link is an
                 action; the fingerprints are the account's public-key identity (bug102:
                 both hybrid KEMs). -->
            <!-- bug158: the plain-language PQ line (Chris's copy, S167) — statement here,
                 precision two lines down in the fingerprints expander (ML-KEM-1024 label);
                 progressive disclosure. Honest as built: the content wrap includes
                 ML-KEM-1024 unconditionally. -->
            <p class="pq-line">{m.account_pq_line()}</p>
            <div class="trust">
              <a class="trust-log" href="/api-docs#transparency">{m.account_trust_log()}</a>
            </div>

            {#if store.isPrsn && me.attestation}
              <details class="key-details">
                <summary>{m.account_key_details()}</summary>
                <dl class="facts mono">
                  <div class="fact">
                    <dt>{m.account_key_protection()}</dt>
                    <dd>{me.attestation.key_protection}</dd>
                  </div>
                  <div class="fact">
                    <dt>{m.account_signing_fingerprint()}</dt>
                    <dd class="small">{me.attestation.signing_pubkey_fingerprint}</dd>
                  </div>
                  {#if me.attestation.signing_pq_pubkey_fingerprint}
                    <div class="fact">
                      <dt>{m.account_signing_pq_fingerprint()}</dt>
                      <dd class="small">{me.attestation.signing_pq_pubkey_fingerprint}</dd>
                    </div>
                  {/if}
                  {#if me.kem_pubkey_fingerprint}
                    <div class="fact">
                      <dt>{m.account_kem_fingerprint()}</dt>
                      <dd class="small">{me.kem_pubkey_fingerprint}</dd>
                    </div>
                  {/if}
                  {#if me.kem_pq_pubkey_fingerprint}
                    <div class="fact">
                      <dt>{m.account_kem_pq_fingerprint()}</dt>
                      <dd class="small">{me.kem_pq_pubkey_fingerprint}</dd>
                    </div>
                  {/if}
                </dl>
              </details>
            {:else if !store.isPrsn && (me.kem_pubkey_fingerprint || me.kem_pq_pubkey_fingerprint)}
              <details class="key-details">
                <!-- bug102: the human view renders BOTH hybrid-KEM fingerprints (P-256 +
                     ML-KEM-1024). A human's content-encryption identity IS the pair, so
                     showing one under-represented the hybrid and left the (plural) tooltip
                     internally inconsistent. Plural label ("Key fingerprints", shared with
                     the PRSN branch) makes the tooltip correct. Supersedes bug091-3's
                     singularization. -->
                <summary use:tooltip={m.account_key_detail_tooltip()}
                  >{m.account_key_details()}</summary
                >
                <dl class="facts mono">
                  {#if me.kem_pubkey_fingerprint}
                    <div class="fact">
                      <dt>{m.account_kem_fingerprint()}</dt>
                      <dd class="small">{me.kem_pubkey_fingerprint}</dd>
                    </div>
                  {/if}
                  {#if me.kem_pq_pubkey_fingerprint}
                    <div class="fact">
                      <dt>{m.account_kem_pq_fingerprint()}</dt>
                      <dd class="small">{me.kem_pq_pubkey_fingerprint}</dd>
                    </div>
                  {/if}
                </dl>
              </details>
            {/if}

            <div class="account-actions">
              <button class="ghost" onclick={() => store.openHistory()}
                >{m.account_history_btn()}</button
              >
              {#if !store.isPrsn}
                <button class="danger-btn" onclick={() => store.openDeleteOwn()}
                  >{m.account_delete_btn()}</button
                >
              {/if}
            </div>
          </section>

          {#if !store.isPrsn && garnetStore.hasBroker}
            <!-- bug095: the "Moving to a new Mac?" replace/new-Mac action, relocated
                 from inside the Signet-Drive-access panel to its own card here (a rare,
                 device-level action, grouped with Rotate passkey below). It shares
                 GarnetPanel's store, so Get-code / Remove-this-Mac open the dialogs that
                 panel renders. Shown only once a broker is registered. -->
            <section class="card" id="mac-setup">
              <h2>{m.garnet_replace_lead()}</h2>
              <p class="mac-body">{m.garnet_replace_body()}</p>
              <div class="account-actions">
                <button
                  class="ghost"
                  onclick={() => garnetStore.mintProvisionCode()}
                  disabled={garnetStore.busy}>{m.garnet_replace_get_code()}</button
                >
                <!-- bug116: a BUTTON matching "Delete account" (both are deliberate,
                     consequential account actions — presented identically), no longer a
                     text link. Behavior unchanged (the #37 broker-deregister path). -->
                <button
                  class="danger-btn"
                  onclick={() =>
                    garnetStore.brokers[0] && garnetStore.openRemoveBroker(garnetStore.brokers[0])}
                  disabled={garnetStore.busy || !garnetStore.brokers[0]}
                  >{m.garnet_remove_broker_btn()}</button
                >
              </div>
            </section>
          {/if}

          {#if !store.isPrsn}
            <!-- bug091-4: passkey rotation is a rare, consequential device-level
                 action (a 3-gesture ceremony), not an Identity fact — its own card
                 at the page bottom. The lead copy's "your files and keys stay intact"
                 is verified against rotate.ts/ceremony.rs: rotation re-wraps the same
                 KEM key under the new passkey PRF, never changing the keypair. -->
            <section class="card" id="passkey">
              <h2>{m.account_passkey_title()}</h2>
              <div class="passkey-row">
                <span>{m.account_passkey_desc()}</span>
                <button class="ghost" onclick={() => store.openRotatePasskey()}
                  >{m.account_rotate_passkey()}</button
                >
              </div>
            </section>
          {/if}

          {#if store.error && !store.dialog}<p class="page-error">{store.error}</p>{/if}
        </div>
      </div>
    </main>
  {/if}
</div>

{#if store.dialog?.kind === 'setCapability'}
  {@const prsn = store.dialog.prsn}
  <Modal title={m.account_setcap_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.account_setcap_hint_before()} <strong>{prsn.handle ?? m.account_this_prsn()}</strong>
      {m.account_setcap_hint_after()}
    </p>
    <select class="cap-select" bind:value={setCapValue} disabled={store.busy}>
      <option value="none">{m.account_cap_none()}</option>
      <option value="read_only">{m.account_cap_read_only()}</option>
      <option value="read_write">{m.account_cap_read_write()}</option>
    </select>
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.account_cancel()}</button
      >
      <button
        class="confirm"
        onclick={() => store.setCapability(prsn, setCapValue)}
        disabled={store.busy}
      >
        {m.account_setcap_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'deletePrsn'}
  {@const prsn = store.dialog.prsn}
  <Modal title={m.account_deleteprsn_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.account_deleteprsn_hint_before()}
      <strong>{prsn.handle ?? m.account_this_prsn()}</strong>{m.account_deleteprsn_hint_after()}
    </p>
    <input
      class="confirm-input"
      bind:value={deletePrsnHandle}
      placeholder={prsn.handle ?? ''}
      disabled={store.busy}
    />
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.account_cancel()}</button
      >
      <button
        class="danger"
        onclick={() => store.deletePrsn(prsn, deletePrsnHandle)}
        disabled={store.busy || deletePrsnHandle.trim() !== prsn.handle}
      >
        {m.account_deleteprsn_confirm()}
      </button>
    {/snippet}
  </Modal>
{:else if store.dialog?.kind === 'deleteOwn'}
  <Modal title={m.account_deleteown_title()} onClose={() => store.closeDialog()}>
    <p class="hint">
      {m.account_deleteown_hint_base()}{store.prsns.length
        ? store.prsns.length === 1
          ? m.account_deleteown_prsn_clause_one({ n: store.prsns.length })
          : m.account_deleteown_prsn_clause_many({ n: store.prsns.length })
        : ''}{m.account_deleteown_hint_suffix()}
    </p>
    <input
      class="confirm-input"
      bind:value={deleteOwnHandle}
      placeholder={store.me?.handle ?? ''}
      disabled={store.busy}
    />
    {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {#snippet footer()}
      <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}
        >{m.account_cancel()}</button
      >
      <button
        class="danger"
        onclick={confirmDeleteOwn}
        disabled={store.busy || deleteOwnHandle.trim() !== store.me?.handle}
      >
        {m.account_deleteown_confirm()}
      </button>
    {/snippet}
  </Modal>
{/if}

{#if store.dialog?.kind === 'rotatePasskey'}
  <Modal title={m.account_rotate_title()} onClose={() => store.closeDialog()}>
    {#if store.rotateComplete}
      <p class="hint">
        {m.account_rotate_done_hint()}
      </p>
    {:else}
      <p class="hint">
        {m.account_rotate_hint()}
      </p>
      {#if store.error}<p class="dialog-error">{store.error}</p>{/if}
    {/if}
    {#snippet footer()}
      {#if store.rotateComplete}
        <button class="confirm" onclick={() => store.closeDialog()}
          >{m.account_rotate_done()}</button
        >
      {:else}
        <button class="ghost" onclick={() => store.closeDialog()} disabled={store.busy}>
          {m.account_cancel()}
        </button>
        <button class="confirm" onclick={rotatePasskey} disabled={store.busy}>
          {store.busy ? m.account_rotating() : m.account_rotate_now()}
        </button>
      {/if}
    {/snippet}
  </Modal>
{/if}

<AccountHistory {store} />

<style>
  .page {
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
  }
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    /* Never widen the page (S121 review, W4-class): wrap to a second line
       before forcing horizontal overflow at narrow widths. */
    flex-wrap: wrap;
    gap: 0.35rem 0.75rem;
    min-width: 0;
  }
  .acct {
    display: flex;
    align-items: center;
    gap: 1rem;
    min-width: 0;
    flex: 0 1 auto;
  }
  @media (max-width: 720px) {
    .bar {
      padding: 0.85rem 1rem;
    }
    .acct {
      gap: 0.5rem;
    }
  }
  .link {
    color: var(--ink-soft);
    font-size: 0.9rem;
    text-decoration: none;
  }
  .link:hover {
    color: var(--ink);
  }
  /* The way back to the drive is the header's exit affordance — a real button
     (bug054), matching .signout's recipe; an <a> underneath so middle-click and
     open-in-new-tab keep working. */
  .back {
    display: inline-block;
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font-size: 0.85rem;
    padding: 0.36rem 0.8rem;
    border-radius: var(--radius-sm);
    text-decoration: none;
  }
  .back:hover {
    border-color: var(--muted);
  }
  .signout {
    border: 1px solid var(--field-border);
    background: var(--surface);
    color: var(--ink-soft);
    font: inherit;
    font-size: 0.85rem;
    padding: 0.36rem 0.8rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .signout:hover {
    border-color: var(--muted);
  }
  main {
    max-width: 940px;
    width: 100%;
    margin: 0 auto;
    padding: 2rem 1.5rem 3rem;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 600;
    margin: 0 0 1.4rem;
  }
  .dashboard {
    display: flex;
    gap: 2rem;
    align-items: flex-start;
  }
  .section-nav {
    display: none;
  }
  .cards {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1.2rem;
  }
  /* The slim sticky section index shows only where the page is wide enough. */
  @media (min-width: 1100px) {
    .section-nav {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      position: sticky;
      top: 2rem;
      width: 150px;
      flex: none;
    }
    .section-nav a {
      color: var(--ink-soft);
      font-size: var(--text-sm);
      padding: 0.25rem 0.5rem;
      border-radius: var(--radius-sm);
      text-decoration: none;
    }
    .section-nav a:hover {
      background: var(--surface-2);
      color: var(--ink);
    }
  }
  .card h2 {
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0 0 1.1rem;
  }
  .identity-head {
    display: flex;
    align-items: center;
    gap: 0.9rem;
    margin-bottom: 1.2rem;
  }
  .handle-lg {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--ink);
  }
  .sub-lines {
    display: flex;
    flex-direction: column;
    color: var(--muted);
    font-size: var(--text-sm);
  }
  .facts {
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }
  .fact {
    display: flex;
    gap: 1rem;
    font-size: var(--text-sm);
  }
  .fact dt {
    width: 150px;
    flex: none;
    margin: 0;
    color: var(--muted);
  }
  .fact dd {
    margin: 0;
    color: var(--ink);
  }
  .facts.mono dd {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
  }
  .fact dd.small {
    font-size: var(--text-xs);
    word-break: break-all;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    font-size: var(--text-xs);
    font-weight: 600;
    border-radius: 999px;
    padding: 0.14rem 0.6rem;
  }
  .chip.pos {
    color: var(--positive);
    background: var(--positive-bg);
  }
  .chip.mut {
    color: var(--muted);
    background: var(--surface-2);
    border: 1px solid var(--border);
  }
  .expires {
    color: var(--muted);
    font-size: var(--text-xs);
    margin-left: 0.4rem;
  }
  /* bug158: the plain-language PQ statement above the verification actions. */
  .pq-line {
    margin-top: 0.4rem;
    font-size: var(--text-sm);
  }
  /* bug110: relocated to the top of the Account Details card — first content under the
     h2, so no top divider (the hairline now sits above the actions row instead). */
  .trust {
    margin-top: 0.4rem;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .trust-log {
    font-size: var(--text-sm);
  }
  .key-details {
    margin-top: 1.1rem;
  }
  .key-details summary {
    font-size: var(--text-sm);
    color: var(--muted);
    cursor: pointer;
  }
  .key-details .facts {
    margin-top: 0.7rem;
  }
  .guardian-note {
    margin: 0 0 0.8rem;
    padding: 0.8rem 0.9rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--ink-soft);
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .guardian-note:last-child {
    margin-bottom: 0;
  }
  .mac-body {
    margin: 0 0 1rem;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  .passkey-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    font-size: 0.92rem;
    color: var(--ink-soft);
  }
  .account-actions {
    /* bug110: History (left) · Delete (right), divided from the verification content
       above by a hairline. */
    display: flex;
    gap: 1.2rem;
    align-items: center;
    justify-content: space-between;
    margin-top: 1.3rem;
    padding-top: 1.1rem;
    border-top: 1px solid var(--border);
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
  /* (bug116: the .danger-text link style is GONE — its one user, Remove this Mac,
     is now a .danger-btn matching Delete account.) */
  /* bug110: the outline danger button for Delete account — low-prominence (out of the
     primary click path), fills on hover. Deletion is passkey-ceremony-gated regardless. */
  .danger-btn {
    border: 1px solid var(--danger);
    background: var(--surface);
    color: var(--danger);
    font: inherit;
    font-weight: 500;
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .danger-btn:hover {
    background: var(--danger);
    color: #fff;
  }
  .loading {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.6rem;
    color: var(--muted);
  }
  .spinner {
    width: 1.1em;
    height: 1.1em;
    border: 2px solid var(--field-border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .page-error {
    margin-top: 1.2rem;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
  .hint {
    margin: 0;
    color: var(--ink-soft);
    font-size: 0.92rem;
    line-height: 1.5;
  }
  .cap-select,
  .confirm-input {
    width: 100%;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 0.6rem 0.75rem;
    font: inherit;
    color: var(--ink);
  }
  .cap-select:focus,
  .confirm-input:focus {
    outline: 0;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--ring);
  }
  .dialog-error {
    margin: 0;
    padding: 0.55rem 0.7rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.86rem;
  }
  .ghost:disabled {
    opacity: 0.55;
    cursor: default;
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
  .danger {
    border: 0;
    background: var(--danger);
    color: #fff;
    font: inherit;
    font-weight: 600;
    padding: 0.5rem 1.1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .confirm:disabled,
  .danger:disabled {
    opacity: 0.55;
    cursor: default;
  }
</style>
