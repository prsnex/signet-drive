<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  // Cloudflare Turnstile signup bot-check (D1). Renders the managed widget inside
  // its own iframe and reports the solved token to the parent via `onToken`; an
  // expiry or error clears it (onToken('')) so the parent re-gates submit. The
  // widget is only mounted when a sitekey is configured (the parent decides) — the
  // server's SIGNET_TURNSTILE_SECRET is the authoritative gate regardless. The CSP
  // already allows the challenges.cloudflare.com origin (svelte.config.js).
  import { onMount } from 'svelte';

  let { sitekey, onToken }: { sitekey: string; onToken: (token: string) => void } = $props();

  interface TurnstileApi {
    render(
      el: HTMLElement,
      opts: {
        sitekey: string;
        callback: (token: string) => void;
        'expired-callback'?: () => void;
        'error-callback'?: () => void;
      },
    ): string;
    reset(widgetId: string): void;
    remove(widgetId: string): void;
  }

  const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

  let container: HTMLDivElement;
  // Widget handle, set once the script loads + renders. Kept at component scope
  // (not inside onMount) so reset() can re-run the challenge after a failed submit.
  let widgetId: string | undefined;

  function getApi(): TurnstileApi | undefined {
    return (window as unknown as { turnstile?: TurnstileApi }).turnstile;
  }

  // Load the Turnstile script once (idempotent across remounts), resolving when
  // window.turnstile is available.
  function loadScript(): Promise<void> {
    if (getApi()) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const existing = document.querySelector<HTMLScriptElement>(`script[src="${SCRIPT_SRC}"]`);
      if (existing) {
        existing.addEventListener('load', () => resolve());
        existing.addEventListener('error', () => reject(new Error('turnstile script failed')));
        if (getApi()) resolve();
        return;
      }
      const s = document.createElement('script');
      s.src = SCRIPT_SRC;
      s.async = true;
      s.defer = true;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error('turnstile script failed'));
      document.head.appendChild(s);
    });
  }

  onMount(() => {
    loadScript()
      .then(() => {
        const api = getApi();
        if (!api || !container) return;
        widgetId = api.render(container, {
          sitekey,
          callback: (token: string) => onToken(token),
          'expired-callback': () => onToken(''),
          'error-callback': () => onToken(''),
        });
      })
      .catch(() => onToken(''));
    return () => {
      const api = getApi();
      if (api && widgetId !== undefined) api.remove(widgetId);
      widgetId = undefined;
    };
  });

  // Re-run the challenge for a fresh token. Turnstile tokens are single-use, so a
  // submit that consumes one (the server verifies before validating the rest of the
  // request) leaves a dead token; the parent calls this on a failed submit so the
  // retry isn't masked by a stale-token "verification failed" (Bug015). The widget's
  // existing `callback` delivers the new token via onToken.
  export function reset(): void {
    const api = getApi();
    if (api && widgetId !== undefined) api.reset(widgetId);
  }
</script>

<div bind:this={container} class="turnstile"></div>

<style>
  .turnstile {
    margin: 0.1rem 0;
    min-height: 65px;
  }
</style>
