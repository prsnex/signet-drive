<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // The Terms of Service + Privacy Policy checkbox (Chris, 2026-09-23). One component
  // for both places a person accepts: the sign-up form, and the email-link page for an
  // admin invitee who never saw the form. The server refuses both paths without it
  // (`terms_not_accepted`) and records the acceptance on the account; this box is the
  // person's act, not the enforcement.
  import { m } from '$lib/paraglide/messages.js';
  import { PRIVACY_URL, TERMS_URL } from '$lib/legal';

  let { checked = $bindable(false), disabled = false }: { checked?: boolean; disabled?: boolean } =
    $props();
</script>

<label class="consent">
  <input type="checkbox" bind:checked {disabled} />
  <span>
    {m.terms_consent_prefix()}
    <a href={TERMS_URL} target="_blank" rel="noopener noreferrer">{m.terms_consent_terms()}</a>
    {m.terms_consent_and()}
    <a href={PRIVACY_URL} target="_blank" rel="noopener noreferrer">{m.terms_consent_privacy()}</a>.
  </span>
</label>

<style>
  .consent {
    display: flex;
    align-items: flex-start;
    gap: 0.55rem;
    font-size: 0.92rem;
    line-height: 1.4;
    cursor: pointer;
  }
  .consent input {
    margin-top: 0.2rem;
    flex: none;
    width: 1rem;
    height: 1rem;
    accent-color: var(--accent);
  }
  .consent a {
    color: var(--accent);
  }
</style>
