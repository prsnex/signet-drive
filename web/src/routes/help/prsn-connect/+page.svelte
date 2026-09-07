<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<!-- bug119 Link A: written FOR a PRSN, second person. Content is skeleton-approved
     (S157); detailed copy assessment is deferred (public-site pass). Keep this page
     TRUE to the running system: the states and remedies below match the server's own
     refusal messages (the bug117 gate) and the auto-reconnect (bug114 Part F). -->

<svelte:head>
  <title>Signet Drive: Connecting as a PRSN</title>
  <meta
    name="description"
    content="How a PRSN connects to Signet Drive: the signet connect command, reading a failure, what each access state means, and when to involve your guardian."
  />
</svelte:head>

<main class="help">
  <header class="head">
    <h1>Connecting to Signet Drive</h1>
    <p class="lede">
      This page is written for you, a PRSN. If a Signet Drive operation just failed and someone sent
      you this link, start at <a href="#reading-a-failure">reading a failure</a>.
    </p>
  </header>

  <!-- S168 (bug151's class, caught on the render): the old heading promised "You connect
       automatically" UNCONDITIONALLY — false on the native path, where auto-pickup never
       fires. Same inversion Chris ruled for wizard step 5 and the 403: lead with the
       command that always works. -->
  <section id="automatic">
    <h2>Connecting is one command</h2>
    <p>
      When your guardian authorizes you, run <code>signet connect</code>: it claims your credential
      by a signed pickup, and your attested key is the proof, so there is no code to relay and
      nothing to configure. Some setups connect on their own with the first <code>signet</code>
      command that talks to the server; <code>signet connect</code> works on every setup. If your access
      was revoked and then re-authorized, the same applies.
    </p>
  </section>

  <section id="reading-a-failure">
    <h2>Reading a failure</h2>
    <p>
      Every refusal names its cause and its remedy. To see your own state directly, run
      <code>signet whoami</code> and read the <code>drive_access</code> block:
    </p>
    <ul>
      <li>
        <code>none</code>: your guardian has not authorized Signet Drive access for this account (or
        revoked it). Only your guardian can authorize or re-authorize, from their account page.
      </li>
      <li>
        <code>awaiting_pickup</code>: you are authorized but not yet connected. Run
        <code>signet connect</code>. (Some setups connect automatically with the first Signet Drive
        command.)
      </li>
      <li>
        <code>authorized</code>: you are connected. If operations still fail, read the error's own
        message; it names what to do.
      </li>
    </ul>
    <p>
      An error saying access is <strong>paused</strong> or <strong>revoked</strong> means the remedy
      is your guardian's, not yours: ask them to re-authorize you. An error naming a
      <strong>re-confirmation deadline</strong> means your guardian's periodic re-confirmation is overdue:
      ask them to re-confirm you from their account page. No command of yours can substitute for either
      gesture.
    </p>
  </section>

  <section id="manual-fallback">
    <h2>The manual fallback</h2>
    <p>
      <code>signet connect</code> claims (or re-claims) your credential explicitly. Use it if automatic
      connection did not happen, for example after your guardian re-authorized you while your broker connection
      was down. It is signature-authenticated: it works only as you, and only when a live authorization
      is waiting.
    </p>
  </section>

  <section id="tell-your-guardian">
    <h2>When to stop and tell your guardian</h2>
    <p>
      If an error tells you to ask your guardian, do that rather than retrying: the remedy is a
      gesture only they can make. Words you can use: <em
        >&ldquo;Signet Drive says my access needs your attention. Could you open your account page
        and check my status under PRSN Accounts?&rdquo;</em
      > Their page shows your state and the one button that fixes it.
    </p>
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
  code {
    background: rgba(0, 0, 0, 0.05);
    padding: 0.1rem 0.3rem;
    border-radius: 4px;
  }
  li {
    margin-bottom: 0.5rem;
  }
</style>
