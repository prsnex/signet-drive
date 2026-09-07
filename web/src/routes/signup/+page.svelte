<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import AuthCard from '$lib/components/AuthCard.svelte';
  import TextField from '$lib/components/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import { authDeps } from '$lib/deps';
  import { beginSignup } from '$lib/auth';
  import { friendlyAuthError } from '$lib/errors';
  import { normalizeHandle, validateHandle } from '$lib/handle';
  import Turnstile from '$lib/components/Turnstile.svelte';
  import { m } from '$lib/paraglide/messages.js';
  import { onMount } from 'svelte';

  // Cloudflare Turnstile sitekey — fetched at runtime from the server's public
  // config (Option C), never baked into the build, so one image serves every
  // environment. A non-empty sitekey → the widget renders and submit gates on a
  // solved token; empty/unreachable (dev default + the e2e) → no widget, signup
  // proceeds (the server's SIGNET_TURNSTILE_SECRET is the authoritative gate
  // either way). `configLoaded` guards the brief startup window so a token-less
  // submit can't race the fetch.
  let turnstileSitekey = $state('');
  let configLoaded = $state(false);

  onMount(async () => {
    try {
      const cfg = await authDeps().api.getPublicConfig();
      turnstileSitekey = cfg.turnstile_sitekey ?? '';
    } catch {
      // Config unreachable → render no widget; the server secret remains the gate.
      turnstileSitekey = '';
    } finally {
      configLoaded = true;
    }

    // Separate try: a Turnstile-config failure must not decide the gate, and a
    // gate failure must not disable the widget. Two questions, two answers.
    try {
      signupOpen = (await authDeps().api.getSignupStatus()).open;
    } catch {
      signupOpen = true; // see the note on `signupOpen`
    }
  });

  // ⛔ THE SIGNUP GATE (S206). `null` = not yet known. The form is NOT rendered
  // until we know, so a closed gate never flashes an inviting form first.
  // ⚠ ON FETCH FAILURE WE ASSUME OPEN. The server is the real gate and will refuse
  // a closed signup anyway; assuming CLOSED would turn a transient network blip into
  // "Signet Drive is not accepting anyone", which is a far worse lie to tell a
  // visitor than briefly showing a form whose submit is honestly refused.
  let signupOpen = $state<boolean | null>(null);

  let handle = $state('');
  let email = $state('');
  let busy = $state(false);
  let error = $state('');
  let handleError = $state('');
  let sent = $state(false);
  let turnstileToken = $state('');
  // Component handle for the Turnstile widget — lets us reset() it (a fresh,
  // single-use token) after a failed submit so the real error isn't masked (Bug015).
  let turnstileEl = $state<ReturnType<typeof Turnstile>>();

  // Clear the inline handle error as soon as the user edits the handle, so a
  // corrected value drops the red without waiting for the next submit.
  $effect(() => {
    void handle;
    handleError = '';
  });

  // Catch an invalid handle client-side (see $lib/handle — the mirror of the server's
  // validate_human_handle) so we never burn a single-use Turnstile token on it, and
  // the user sees the *specific* reason (the server flattens it to a generic
  // "invalid_request" by the time friendlyAuthError sees it).
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !configLoaded) return;
    if (turnstileSitekey && !turnstileToken) return;
    const trimmedHandle = normalizeHandle(handle);
    const problem = validateHandle(trimmedHandle);
    if (problem) {
      handleError =
        problem === 'reserved_ai' ? m.signup_handle_reserved_ai() : m.signup_handle_invalid();
      return; // don't consume the single-use Turnstile token on a bad handle
    }
    error = '';
    busy = true;
    try {
      await beginSignup(authDeps().api, {
        handle: trimmedHandle,
        email: email.trim(),
        turnstileToken: turnstileSitekey ? turnstileToken : undefined,
      });
      sent = true;
    } catch (err) {
      error = friendlyAuthError(err);
      // The server verifies Turnstile *before* the rest of the request, so a failed
      // submit has already consumed the single-use token. Reset the widget for a
      // fresh one (and re-gate submit on it) so the retry isn't masked by a dead
      // "verification failed" (Bug015).
      if (turnstileSitekey) {
        turnstileToken = '';
        turnstileEl?.reset();
      }
    } finally {
      busy = false;
    }
  }
</script>

{#if signupOpen === false}
  <AuthCard title={m.signup_paused_title()} subtitle={m.signup_paused_subtitle()}>
    {#snippet footer()}
      {m.signup_footer_have_account()} <a href="/signin">{m.signup_footer_sign_in()}</a>
    {/snippet}
  </AuthCard>
{:else if sent}
  <AuthCard title={m.signup_sent_title()} subtitle={m.signup_sent_subtitle({ email })}>
    <p class="muted">
      {m.signup_resend_prompt()}
      <button type="button" class="linkish" onclick={() => (sent = false)}
        >{m.signup_try_again()}</button
      >.
    </p>
    {#snippet footer()}
      {m.signup_footer_have_account()} <a href="/signin">{m.signup_footer_sign_in()}</a>
    {/snippet}
  </AuthCard>
{:else}
  <AuthCard title={m.signup_title()} subtitle={m.signup_subtitle()}>
    <form onsubmit={submit}>
      <TextField
        label={m.signup_username_label()}
        bind:value={handle}
        autocomplete="username"
        placeholder={m.signup_username_placeholder()}
        disabled={busy}
        error={handleError}
      />
      <TextField
        label={m.signup_email_label()}
        type="email"
        bind:value={email}
        autocomplete="email"
        placeholder={m.signup_email_placeholder()}
        disabled={busy}
      />
      {#if turnstileSitekey}
        <Turnstile
          sitekey={turnstileSitekey}
          onToken={(t) => (turnstileToken = t)}
          bind:this={turnstileEl}
        />
      {/if}
      {#if error}<p class="form-error">{error}</p>{/if}
      <Button
        type="submit"
        loading={busy}
        disabled={!configLoaded || (!!turnstileSitekey && !turnstileToken)}
      >
        {busy ? m.signup_sending() : m.signup_continue()}
      </Button>
    </form>
    {#snippet footer()}
      {m.signup_footer_have_account()} <a href="/signin">{m.signup_footer_sign_in()}</a>
    {/snippet}
  </AuthCard>
{/if}

<style>
  form {
    display: flex;
    flex-direction: column;
    gap: 1.05rem;
  }
  .muted {
    margin: 0;
    color: var(--muted);
    font-size: 0.92rem;
  }
  .linkish {
    border: 0;
    background: none;
    padding: 0;
    font: inherit;
    color: var(--accent);
    cursor: pointer;
    text-decoration: underline;
  }
  .form-error {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid #f0d9d7;
    border-radius: var(--radius-sm);
    font-size: 0.88rem;
  }
</style>
