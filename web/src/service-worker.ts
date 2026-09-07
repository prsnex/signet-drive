// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
/// <reference types="@sveltejs/kit" />
/// <reference no-default-lib="true"/>
/// <reference lib="esnext" />
/// <reference lib="webworker" />

/* bug193 (Download-Loop-Rewrite v03 §3c): the SW half of the streamed download.
 *
 * The page decrypts; this worker turns the verified-plaintext stream into a real
 * browser download: it answers `/__signet_dl/<id>` with a streaming
 * `Content-Disposition: attachment` response, and the BROWSER'S OWN download
 * manager writes the disk — every browser, no picker, no folder grant. The
 * Proton/Mega architecture, verified on current Safari/Chrome/Firefox by the
 * S176 spike (all four pre-registered criteria [MEASURED]).
 *
 * ⚠ SUPPLY IS PULL-DRIVEN END-TO-END (v03 invariant). ONE mode, every browser:
 *   'pump' — this worker requests EXACTLY ONE chunk per pull over a MessagePort.
 *            Measured consequence of getting this wrong: the spike's first pump
 *            had no backpressure, the page queued 2 GiB inside the SW, and
 *            Safari's SW memory limit killed the worker (download dead at 4 KiB).
 *
 * ⚠⚠ THE 'transfer' MODE IS DELETED (bug195, S177) — not parked, no knob. It
 * handed a native ReadableStream across realms and trusted the platform's own
 * backpressure. Measured: Chrome fetched an entire 512 MiB file with NOTHING
 * consuming it, while the page's own design predicted a park at ~2 chunks — our
 * writer was awaiting a queue that was not the queue filling. A bound we do not
 * own cannot be stated, and "benign in Chrome N" is unversioned trust. The pump's
 * credit counter is ours, is mutation-tested (chunks received may never exceed
 * pulls issued), and holds everywhere. Do not restore transfer mode as an
 * optimization: its cost advantage is one memcpy per 16 MiB chunk against
 * 100 ms–2 s of network, and its risk is bug179 in a place tests cannot see.
 *
 * ⚠ KEEPALIVE (v03, unconditional): the page pings for the whole transfer.
 * Firefox reaps an idle SW at ~30 s EVEN MID-RESPONSE — measured: the 2 GiB
 * paced arm died at 755 MB without the ping and completed with it. The 'ka'
 * message needs no handler body; its arrival is what resets the idle clock.
 *
 * §3f (SW update lifecycle): SvelteKit bakes `version` into this file, so every
 * release changes its bytes and the browser's own update check sees it.
 * skipWaiting + clients.claim: the new worker takes control IMMEDIATELY on
 * activation (Gus, complete-branch review — not "at the next reload"; the
 * comment must match the mechanism). An in-flight download is unaffected by
 * design: its response stream AND the page's keepalive both bind the CAPTURED
 * old-worker instance, which the browser keeps alive until its streams settle —
 * a download started under vN completes under vN even across a mid-download
 * deploy. Step 0 verifies THREE ends on this surface (server, bundle, SW) via
 * the 'version' message below. */

import { version } from '$service-worker';

import {
  PendingRegistry,
  RESERVED_DOWNLOAD_PREFIX,
  createPumpReceiverStream,
} from '$lib/sw-download';

const sw = self as unknown as ServiceWorkerGlobalScope;

sw.addEventListener('install', () => {
  void sw.skipWaiting();
});
sw.addEventListener('activate', (event) => {
  event.waitUntil(sw.clients.claim());
});

const PENDING_TTL_MS = 120_000;

/** Registered-but-not-yet-fetched downloads. The map and its reaping rule live in
 *  `$lib/sw-download` (PendingRegistry) so the rule is UNIT-TESTED rather than
 *  reasoned about inside a worker no test can load — the same extraction F-A's
 *  receiver earned, and bug195 (j) is the second finding to earn it.
 *
 *  ⚠ REAP ON SILENCE, NEVER ON AGE. See PendingRegistry for the spike-measured
 *  case (a download parked behind Safari's Allow prompt for minutes) that an
 *  age-based sweep destroyed. */
const pending = new PendingRegistry<ReadableStream<Uint8Array>>(PENDING_TTL_MS);

sw.addEventListener('message', (event: ExtendableMessageEvent) => {
  const data = event.data as
    | { type: 'ka'; id?: string }
    | { type: 'version' }
    | { type: 'dl-pump'; id: string; filename: string; plaintextBytes: number }
    | undefined;
  if (!data) return;
  switch (data.type) {
    case 'ka': {
      // Keepalive, doing two jobs: its ARRIVAL resets the browser's SW idle
      // clock (Firefox reaps an idle worker at ~30 s even mid-response), and its
      // `id` marks that entry's page as alive so the sweep cannot reap a download
      // parked behind a permission prompt (bug195 (j)).
      if (data.id) pending.touch(data.id, Date.now());
      return;
    }
    case 'version':
      // §3f: step 0's third end. The page asserts this equals the deployed release.
      event.source?.postMessage({ type: 'version', version });
      return;
    case 'dl-pump': {
      const port = event.ports[0];
      if (!port) return;
      pending.sweep(Date.now());
      // The pump stream (inbox + credit protocol) lives in $lib/sw-download so
      // F-A — terminals arriving while no pull is outstanding — is UNIT-TESTED
      // rather than reasoned about.
      pending.register(
        data.id,
        {
          stream: createPumpReceiverStream(port),
          filename: data.filename,
          plaintextBytes: data.plaintextBytes,
        },
        Date.now(),
      );
      event.source?.postMessage({ type: 'dl-ready', id: data.id, mode: 'pump' });
      return;
    }
  }
});

sw.addEventListener('fetch', (event: FetchEvent) => {
  const url = new URL(event.request.url);
  if (!url.pathname.startsWith(RESERVED_DOWNLOAD_PREFIX)) return; // one shared home for the namespace
  const match = url.pathname.slice(RESERVED_DOWNLOAD_PREFIX.length).match(/^([a-z0-9-]+)$/);
  if (!match) return; // everything else: straight to the network, untouched
  const entry = pending.take(match[1]);
  if (!entry) {
    event.respondWith(new Response('unknown download id', { status: 404 }));
    return;
  }
  // ⚠⚠ bug195 (k): THE CAUSAL SIGNAL. This is the one instant at which the browser
  // has actually taken the download off us — the entry is claimed and a streaming
  // attachment is about to be served. The page's success notice is gated on this
  // message, so a trigger that never arrives (a blocked navigation, a swept entry,
  // a worker replaced between ready and fetch) can no longer be reported as a save.
  // Broadcast rather than replying to a client id: a download request is not
  // reliably attributed to a client, so the page filters by its own id.
  const consumedId = match[1];
  // ⚠⚠ bug203 (S179): `includeUncontrolled: true` is load-bearing, not tidying.
  // This is the ONLY page-bound message that travels by BROADCAST rather than as a
  // reply to `event.source` — every other one (`version`, `dl-ready`) answers the
  // sender directly and therefore reaches an uncontrolled page for free. A default
  // `matchAll` returns only CONTROLLED clients, so on a hard-reloaded (uncontrolled)
  // page this signal would be the single thing that silently went missing — and it
  // is the causal signal the success claim and the bug198 fence both wait on. The
  // download would complete and the page would hang forever on `consumed`.
  void sw.clients
    .matchAll({ type: 'window', includeUncontrolled: true })
    .then((cs) => cs.forEach((c) => c.postMessage({ type: 'dl-consumed', id: consumedId })))
    .catch(() => undefined);
  // RFC 6266/5987 filename escaping: quotes/backslashes stripped from the plain
  // form, the UTF-8 form carried alongside for non-ASCII names.
  const plain = entry.filename.replace(/[\\"\r\n]/g, '_');
  const utf8 = encodeURIComponent(entry.filename);
  event.respondWith(
    new Response(entry.stream, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${plain}"; filename*=UTF-8''${utf8}`,
        // Gus F1: the PLAINTEXT length. The download manager shows real progress
        // and a mismatch marks truncation — which is only honest if the number
        // is the stream's own length, not the stored size.
        'Content-Length': String(entry.plaintextBytes),
        'X-Content-Type-Options': 'nosniff',
      },
    }),
  );
});
