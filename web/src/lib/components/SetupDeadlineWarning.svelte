<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script module lang="ts">
  // One warning per account per PAGE-LOAD, shared across instances — a courtesy, not a
  // nag. MODULE-level on purpose: this component mounts on both the account page and
  // the wizard, and an instance-local set would re-fire the just-acknowledged warning
  // the moment "OK" navigates to the wizard (whose own instance hasn't warned yet).
  // Deliberately non-reactive: firing is an event, not derived state. A full reload
  // resets it, which is fine (re-warning minutes before the wipe is arguably right).
  const warned = new Set<string>();
</script>

<script lang="ts">
  import { goto } from '$app/navigation';
  import Modal from '$lib/components/Modal.svelte';
  import type { GarnetStore } from '$lib/garnet.svelte';
  import { setupWarningTarget } from '$lib/garnet';
  import { m } from '$lib/paraglide/messages.js';

  // bug114 Part B: the 5-minute courtesy warning before an in-setup PRSN account's
  // server-side wipe. A single "OK" modal, armed against the SERVER-provided deadline
  // (`GuardedPrsn.setup_deadline` — the authoritative clock), tracking the soonest
  // in-setup account in the shared GarnetStore. Mounted wherever that store lives (the
  // account page + the add-PRSN wizard), so it covers the present-but-distracted case.
  //
  // Honest limit (bug114 Part B, stated by design): this is a COURTESY layer, not the
  // guarantee — it only shows while a signed-in page is open. The tab-closed /
  // walked-away case has no browser to warn; the server-side sweep is the enforcer.
  let { store }: { store: GarnetStore } = $props();

  let showFor = $state<{ handle: string; deadline: number } | null>(null);

  $effect(() => {
    const target = setupWarningTarget(store.prsns);
    if (!target || warned.has(target.handle)) return;
    const now = Math.floor(Date.now() / 1000);
    const fire = () => {
      warned.add(target.handle);
      showFor = { handle: target.handle, deadline: target.deadline };
    };
    if (now >= target.warnAt) {
      fire();
      return;
    }
    // Bounded by construction: warnAt is at most the 30-min setup window out.
    const timer = setTimeout(fire, (target.warnAt - now) * 1000);
    return () => clearTimeout(timer);
  });

  // The S155 decision: "OK" returns the guardian to the setup process while time
  // remains, or to the account page if the window already closed (the wipe is the
  // server's; this only routes the human sensibly either side of it).
  function acknowledge() {
    const t = showFor;
    showFor = null;
    if (!t) return;
    if (Math.floor(Date.now() / 1000) < t.deadline) {
      void goto(`/account/add-prsn/confirm?handle=${encodeURIComponent(t.handle)}`);
    } else {
      void goto('/account');
    }
  }
</script>

{#if showFor !== null}
  <Modal title={m.setupwarn_title()} onClose={acknowledge}>
    <p class="body">{m.setupwarn_body({ handle: showFor.handle })}</p>
    {#snippet footer()}
      <button class="ok" onclick={acknowledge}>{m.setupwarn_ok()}</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .body {
    margin: 0;
    font-size: 0.92rem;
  }
  .ok {
    border: 1px solid var(--accent);
    background: var(--accent);
    color: #fff;
    font: inherit;
    font-size: 0.86rem;
    padding: 0.4rem 1rem;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }
  .ok:hover {
    opacity: 0.92;
  }
</style>
