// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import type { AdminAccount, ListAdminAccountsResponse } from './api';
import { fetchAllPages } from './paginate';

/** The one call `fetchAllAccounts` needs — narrowed so tests can supply a fake. */
export type ListAccountsPage = (cursor?: string) => Promise<ListAdminAccountsResponse>;

/**
 * Fetches EVERY admin account, following the server's cursor to exhaustion.
 *
 * ⛔ THE FULL LIST IS A CORRECTNESS REQUIREMENT, NOT A CONVENIENCE. The admin
 * table sorts client-side, and a sort over a partial list is a confident lie: it
 * ranks whatever happens to be loaded and presents that as the ranking of all
 * accounts. That is right at 11 accounts and wrong at 3,000 — wrong in the
 * direction that looks fine.
 *
 * The drain, its bound, and the no-progress guard live in `fetchAllPages`
 * (`paginate.ts`) — ONE drain shared with the Drive's listings, whose identical
 * defect was bug241. This adapts the accounts response shape onto it.
 *
 * Errors propagate: the caller discards what arrived, leaves its done-flag false,
 * and the sort headers stay disabled. A partial list is never presented as
 * complete.
 */
export async function fetchAllAccounts(listPage: ListAccountsPage): Promise<AdminAccount[]> {
  return fetchAllPages(async (cursor) => {
    const page = await listPage(cursor);
    return { items: page.accounts, next_cursor: page.next_cursor };
  });
}
