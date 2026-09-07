// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, it, expect } from 'vitest';
import { fetchAllPages } from './paginate';
import type { Page } from './paginate';

/** A stand-in item — `fetchAllPages` is generic and never inspects the shape. */
function acct(handle: string): { handle: string } {
  return { handle };
}

/** A server that hands out `pages` in order, keyed by the cursor it last issued. */
function pagedServer(pages: { handle: string }[][]) {
  const calls: (string | undefined)[] = [];
  const listPage = async (cursor?: string): Promise<Page<{ handle: string }>> => {
    calls.push(cursor);
    const i = cursor === undefined ? 0 : Number(cursor);
    return {
      items: pages[i],
      next_cursor: i + 1 < pages.length ? String(i + 1) : null,
    };
  };
  return { listPage, calls };
}

describe('fetchAllPages', () => {
  it('follows the cursor to exhaustion and returns every account', async () => {
    const { listPage, calls } = pagedServer([
      [acct('a'), acct('b')],
      [acct('c'), acct('d')],
      [acct('e')],
    ]);

    const all = await fetchAllPages(listPage);

    // The property that matters: EVERY account, not just the first page.
    expect(all.map((a) => a.handle)).toEqual(['a', 'b', 'c', 'd', 'e']);
    // …and it actually made the follow-up requests rather than stopping at one.
    expect(calls).toEqual([undefined, '1', '2']);
  });

  // ⛔ THE REGRESSION GUARD. A single-page fetch looks correct on a small
  // account list and silently under-reports on a large one — and the admin table
  // would then sort that fragment and present it as the ranking of all accounts.
  // If someone "simplifies" the loop away, this fails instead of shipping.
  it('does not stop at the first page when more remain', async () => {
    const { listPage } = pagedServer([[acct('first')], [acct('second')]]);

    const all = await fetchAllPages(listPage);

    expect(all).toHaveLength(2);
    expect(all.map((a) => a.handle)).toContain('second');
  });

  it('makes exactly one request when the first page is the whole list', async () => {
    const { listPage, calls } = pagedServer([[acct('only')]]);

    const all = await fetchAllPages(listPage);

    expect(all.map((a) => a.handle)).toEqual(['only']);
    expect(calls).toEqual([undefined]);
  });

  it('returns an empty list without a follow-up request', async () => {
    const { listPage, calls } = pagedServer([[]]);

    expect(await fetchAllPages(listPage)).toEqual([]);
    expect(calls).toEqual([undefined]);
  });

  // ⛔ Gus's C.4 arm: what passes every test above and is still wrong. The paged
  // fake always advances, so no test here could ever produce a server that
  // repeats a cursor — and that server would spin this loop forever with no
  // error and no ceiling. The guard turns an infinite hang into a failure the
  // pane can report.
  it('rejects a server that repeats its cursor instead of looping forever', async () => {
    let calls = 0;
    const listPage = async (): Promise<Page<{ handle: string }>> => {
      calls += 1;
      return { items: [acct('stuck')], next_cursor: 'same' };
    };

    await expect(fetchAllPages(listPage)).rejects.toThrow('made no progress');
    // Bounded: it stopped rather than spinning. Two calls — the first issues
    // 'same', the second returns it unchanged and trips the guard.
    expect(calls).toBe(2);
  });

  // A drain that dies mid-way must REJECT, so the caller leaves its done-flag
  // false and the sort headers stay disabled. Swallowing the error here would
  // hand the table a partial list wearing the shape of a complete one.
  it('propagates a mid-drain failure rather than returning a partial list', async () => {
    let call = 0;
    const listPage = async (): Promise<Page<{ handle: string }>> => {
      call += 1;
      if (call === 1) return { items: [acct('a')], next_cursor: '1' };
      throw new Error('network');
    };

    await expect(fetchAllPages(listPage)).rejects.toThrow('network');
  });
});
