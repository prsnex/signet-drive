// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

/** One page of a keyset-paginated listing: the items, plus where to resume. */
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

/** Fetch one page from a given cursor. `undefined` asks for the first page. */
export type FetchPage<T> = (cursor?: string) => Promise<Page<T>>;

/**
 * Fetch EVERY item of a keyset-paginated listing, following the cursor to
 * exhaustion.
 *
 * ⛔ THE FULL LIST IS A CORRECTNESS REQUIREMENT WHEREVER THE CALLER RENDERS OR
 * RANKS THE RESULT. A UI that lists one page and drops `next_cursor` does not
 * look broken: it renders real rows, the count of what it rendered is correct,
 * and the missing items simply are not there. That is bug241 — the web Drive
 * showed at most 50 files and 50 subfolders per folder, silently — and the same
 * shape would have made the admin accounts table rank one page and present it as
 * the ranking of every account.
 *
 * ⚠ NAMED BOUND, so a later reader inherits it rather than discovering it: this
 * is O(items ÷ page-size) SEQUENTIAL requests (server default 50, max 100). Fine
 * at launch volume. If a surface ever feels slow to open, the levers in order are
 * a larger page size, then server-side ordering with a per-column keyset cursor.
 * ⛔ Do NOT "fix" it by fetching a single page — that restores the defect this
 * function exists to prevent.
 *
 * Errors propagate. A caller that renders must present nothing stale as complete;
 * a partial list is never acceptable as a whole one.
 */
export async function fetchAllPages<T>(fetchPage: FetchPage<T>): Promise<T[]> {
  const all: T[] = [];
  let cursor: string | undefined;
  do {
    const page = await fetchPage(cursor);
    all.push(...page.items);
    const next = page.next_cursor ?? undefined;
    // ⛔ PROGRESS GUARD. A server that hands back the cursor it was given loops
    // here forever — no error, no ceiling, a tab that spins. ⚠ No fake that
    // always advances can produce it, which is why it needs its own arm.
    if (next !== undefined && next === cursor) {
      throw new Error('pagination cursor made no progress');
    }
    cursor = next;
  } while (cursor);
  return all;
}
