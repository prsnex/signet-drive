// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// F4 (2026-09-21): the screen wake lock is gated on the transfer layer's own
// forecast, held for the batch, re-taken on visible, released at the end — and a
// no-op where the API is absent.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  UploadWakeLock,
  WAKE_LOCK_MIN_REMAINING_SECONDS,
  type WakeLockSentinelLike,
} from './wake-lock';

function fakeApi() {
  const sentinels: Array<WakeLockSentinelLike & { released: boolean }> = [];
  const api = {
    calls: 0,
    request: async () => {
      api.calls += 1;
      const s = {
        released: false,
        release: async () => {
          s.released = true;
        },
      };
      sentinels.push(s);
      return s;
    },
  };
  return { api, sentinels };
}

describe('F4 — the upload wake lock', () => {
  it('is requested the first time the forecast exceeds the gate, and only once', async () => {
    const { api } = fakeApi();
    const lock = new UploadWakeLock(api);
    lock.consider(null); // no rate measured yet
    lock.consider(WAKE_LOCK_MIN_REMAINING_SECONDS); // at the gate, not over it
    await Promise.resolve();
    expect(api.calls).toBe(0);
    expect(lock.held).toBe(false);
    lock.consider(WAKE_LOCK_MIN_REMAINING_SECONDS + 1);
    await new Promise((r) => setTimeout(r, 0));
    expect(api.calls).toBe(1);
    expect(lock.held).toBe(true);
    // Later reports, even with a shrinking ETA, neither re-request nor drop it.
    lock.consider(5);
    lock.consider(200);
    await new Promise((r) => setTimeout(r, 0));
    expect(api.calls).toBe(1);
    expect(lock.held).toBe(true);
  });

  it('is released at batch end, and a later visible transition does not take it again', async () => {
    const { api, sentinels } = fakeApi();
    const lock = new UploadWakeLock(api);
    lock.consider(300);
    await new Promise((r) => setTimeout(r, 0));
    expect(lock.held).toBe(true);
    await lock.release();
    expect(lock.held).toBe(false);
    expect(sentinels[0].released).toBe(true);
    lock.onVisible();
    await new Promise((r) => setTimeout(r, 0));
    expect(api.calls).toBe(1);
  });

  it('is re-taken on visible after the browser released it on hide', async () => {
    const { api, sentinels } = fakeApi();
    const lock = new UploadWakeLock(api);
    lock.consider(300);
    await new Promise((r) => setTimeout(r, 0));
    expect(api.calls).toBe(1);
    // The browser releases the sentinel when the page hides (spec behaviour).
    sentinels[0].released = true;
    expect(lock.held).toBe(false);
    lock.onVisible();
    await new Promise((r) => setTimeout(r, 0));
    expect(api.calls).toBe(2);
    expect(lock.held).toBe(true);
  });

  it('is a no-op without the API, and a refused request is not an error', async () => {
    const none = new UploadWakeLock(undefined);
    none.consider(1000);
    none.onVisible();
    await none.release();
    expect(none.held).toBe(false);
    const refusing = new UploadWakeLock({
      request: async () => Promise.reject(new Error('NotAllowedError')),
    });
    refusing.consider(1000);
    await new Promise((r) => setTimeout(r, 0));
    expect(refusing.held).toBe(false);
    expect(refusing.requests).toBe(1);
  });

  it('the store forwards page visibility to the upload controller and releases the lock with the batch', () => {
    // The transfer layer has no `document`; the store is the one place that
    // listens. Asserted statically, the way upload-phase.test.ts guards the bar.
    const store = readFileSync(
      fileURLToPath(new URL('./browser.svelte.ts', import.meta.url)),
      'utf8',
    );
    // F2 (2026-09-23): the seam moved one step — the store hands the BATCH the
    // document's current state and every change; the batch hands each open
    // file's controller both (upload-batch.ts). Both halves are pinned.
    const batch = store.slice(
      store.indexOf('new UploadBatch<File>('),
      store.indexOf("removeEventListener('pagehide'"),
    );
    expect(batch.length).toBeGreaterThan(0);
    expect(batch).toContain("addEventListener('visibilitychange'");
    expect(batch).toContain("initiallyVisible: document.visibilityState === 'visible'");
    expect(batch).toContain('batch.setVisibility(visible)');
    expect(batch).toContain('wakeLock.consider(');
    expect(batch).toContain('wakeLock.onVisible()');
    expect(batch).toContain("removeEventListener('visibilitychange'");
    expect(batch).toContain('wakeLock.release()');
    const scheduler = readFileSync(
      fileURLToPath(new URL('./upload-batch.ts', import.meta.url)),
      'utf8',
    );
    expect(scheduler).toContain('controller.initVisibility(this.visible)');
    expect(scheduler).toContain('entry.controller.setVisibility(visible)');
  });
});
