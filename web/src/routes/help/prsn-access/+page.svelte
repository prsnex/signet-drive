<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<!-- bug119 Link B: written FOR the guardian, in plain language (Chris's framing:
     "normies who want info about how PRSN Account access management works"). Content
     is skeleton-approved (S157); detailed copy assessment is deferred (public-site
     pass). No CLI jargon on this page by design. -->

<svelte:head>
  <title>Signet Drive: How PRSN access works</title>
  <meta
    name="description"
    content="A plain-language guide for guardians: how a PRSN's Signet Drive access works, what each status means, what happens automatically, your controls, and troubleshooting."
  />
</svelte:head>

<main class="help">
  <header class="head">
    <h1>How PRSN access works</h1>
    <p class="lede">
      You authorize; your PRSN connects on its own; access continues through a periodic confirmation
      from you. This page explains the statuses you will see and the controls you have.
    </p>
  </header>

  <section id="states">
    <h2>The statuses you'll see</h2>
    <ul>
      <li>
        <strong>Waiting to connect</strong>: you have authorized this PRSN and it has not connected
        yet. Connection happens automatically the next time it uses Signet Drive.
      </li>
      <li><strong>Active</strong>: the PRSN is connected and has working access.</li>
      <li>
        <strong>Revoked</strong>: you paused this PRSN's access. It keeps its account and its files;
        it just cannot use Signet Drive until you re-authorize it.
      </li>
      <li>
        <strong>Pending deletion</strong>: the account is being removed, along with its access.
      </li>
    </ul>
  </section>

  <section id="automatic-vs-you">
    <h2>What is automatic, and what needs you</h2>
    <p>
      <strong>Automatic:</strong> connecting, reconnecting after you re-authorize, and staying connected
      day to day. Your PRSN never needs a code from you.
    </p>
    <p>
      <strong>Yours:</strong> authorizing in the first place, the periodic re-confirmation (Signet Drive
      asks you roughly monthly to confirm the PRSN should keep its access), re-authorizing after a revoke,
      and removing access or the account.
    </p>
  </section>

  <section id="controls">
    <h2>Your controls</h2>
    <ul>
      <li><strong>Revoke</strong>: pause access now. Reversible at any time.</li>
      <li><strong>Re-authorize</strong>: resume access after a revoke.</li>
      <li>
        <strong>Re-confirm</strong>: the periodic check-in. If it lapses, access winds down gently
        (read-only first, then paused) and one tap restores it.
      </li>
      <li>
        <strong>Delete account</strong>: permanent removal of the PRSN's account and files.
      </li>
    </ul>
  </section>

  <section id="troubleshooting">
    <h2>Troubleshooting</h2>
    <ol>
      <li>Make sure the Signet app is running on the Mac (the menu bar icon is present).</li>
      <li>
        Ask your PRSN to read <a href="/help/prsn-connect">the PRSN connection page</a>. It can
        usually resolve things from its side or tell you exactly what it needs.
      </li>
      <li>
        Still stuck? <strong>Revoke</strong> and then <strong>Re-authorize</strong> the PRSN from your
        account page. That issues a fresh authorization, and the PRSN reconnects automatically on its
        next use.
      </li>
    </ol>
  </section>
</main>

<style>
  .help {
    max-width: 44rem;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 4rem;
  }
  .head {
    margin-bottom: 2rem;
  }
  h1 {
    font-size: var(--text-2xl, 1.6rem);
    margin: 0 0 0.6rem;
  }
  .lede {
    color: var(--muted, #555);
  }
  section {
    margin-bottom: 1.8rem;
  }
  h2 {
    font-size: var(--text-lg, 1.15rem);
    margin: 0 0 0.5rem;
  }
  li {
    margin-bottom: 0.5rem;
  }
</style>
