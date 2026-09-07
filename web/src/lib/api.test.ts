// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { createApiClient, downloadBackstopMs } from './api';

interface FetchCall {
  url: string;
  init: RequestInit | undefined;
}

/** A recording fake `fetch` — captures calls and returns the handler's Response. */
function fakeFetch(handler: (url: string, init: RequestInit | undefined) => Response): {
  fetch: typeof fetch;
  calls: FetchCall[];
} {
  const calls: FetchCall[] = [];
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    return handler(url, init);
  };
  return { fetch: fetchImpl as unknown as typeof fetch, calls };
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const bodyOf = (call: FetchCall): unknown => JSON.parse(call.init?.body as string);

describe('api client', () => {
  it('parses a JSON 2xx response and sends a credentialed POST', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, { ceremony_id: 'c1', options: { publicKey: {} } }),
    );
    const res = await createApiClient({ fetch }).beginSignin('a@test.example');
    expect(res.ceremony_id).toBe('c1');
    expect(calls[0].url).toBe('/v1/auth/passkey/begin');
    expect(calls[0].init?.method).toBe('POST');
    expect(calls[0].init?.credentials).toBe('include');
    expect(bodyOf(calls[0])).toEqual({ email: 'a@test.example' });
  });

  it('returns undefined for 204 / 202 without parsing a body', async () => {
    const { fetch: f204 } = fakeFetch(() => new Response(null, { status: 204 }));
    await expect(
      createApiClient({ fetch: f204 }).keysInitialize({
        kem_pubkey: 'x',
        kem_pq_pubkey: 'y',
        wrapped_kem_privkey_blob: {},
      }),
    ).resolves.toBeUndefined();

    const { fetch: f202 } = fakeFetch(() => new Response(null, { status: 202 }));
    await expect(
      createApiClient({ fetch: f202 }).beginSignup({ handle: 'h', email: 'a@test.example' }),
    ).resolves.toBeUndefined();
  });

  it('maps the {error:{code,message}} envelope to SignetApiError', async () => {
    const { fetch } = fakeFetch(() =>
      json(400, { error: { code: 'prf_not_supported', message: 'no PRF' } }),
    );
    await expect(createApiClient({ fetch }).beginSignin('a@test.example')).rejects.toMatchObject({
      name: 'SignetApiError',
      code: 'prf_not_supported',
      status: 400,
      message: 'no PRF',
    });
  });

  it('falls back gracefully on a non-JSON error body', async () => {
    const { fetch } = fakeFetch(
      () => new Response('upstream boom', { status: 502, statusText: 'Bad Gateway' }),
    );
    await expect(createApiClient({ fetch }).beginSignin('a@test.example')).rejects.toMatchObject({
      name: 'SignetApiError',
      status: 502,
      code: 'unknown_error',
    });
  });

  it('begin-signup maps turnstileToken -> turnstile_token; verify-email url-encodes the token', async () => {
    const { fetch, calls } = fakeFetch((url) =>
      url.startsWith('/v1/accounts/verify-email')
        ? json(200, { account_id: 'a1', handle: 'h' })
        : new Response(null, { status: 202 }),
    );
    const api = createApiClient({ fetch });
    await api.beginSignup({ handle: 'alice', email: 'a@test.example', turnstileToken: 'tok' });
    expect(bodyOf(calls[0])).toEqual({
      handle: 'alice',
      email: 'a@test.example',
      turnstile_token: 'tok',
    });
    await api.verifyEmail('ab cd&ef');
    expect(calls[1].url).toBe('/v1/accounts/verify-email?token=ab%20cd%26ef');
  });

  it('getPublicConfig GETs /v1/config and returns the turnstile sitekey', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { turnstile_sitekey: '0xSITEKEY' }));
    const res = await createApiClient({ fetch }).getPublicConfig();
    expect(res.turnstile_sitekey).toBe('0xSITEKEY');
    expect(calls[0].url).toBe('/v1/config');
    expect(calls[0].init?.method).toBe('GET');
  });

  it('getPublicConfig surfaces a null sitekey (bot-check unconfigured)', async () => {
    const { fetch } = fakeFetch(() => json(200, { turnstile_sitekey: null }));
    const res = await createApiClient({ fetch }).getPublicConfig();
    expect(res.turnstile_sitekey).toBeNull();
  });

  it('updateFile PATCHes /v1/files/{id} with the body', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, { file_id: 'f1', folder_id: 'd1', encrypted_name: { ct: 'x' } }),
    );
    const res = await createApiClient({ fetch }).updateFile('f1', { encrypted_name: { ct: 'x' } });
    expect(res.file_id).toBe('f1');
    expect(calls[0].url).toBe('/v1/files/f1');
    expect(calls[0].init?.method).toBe('PATCH');
    expect(bodyOf(calls[0])).toEqual({ encrypted_name: { ct: 'x' } });
  });

  it('updateFolder PATCHes /v1/folders/{id} with the body', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { folder_id: 'd1' }));
    await createApiClient({ fetch }).updateFolder('d1', { parent_folder_id: 'd2' });
    expect(calls[0].url).toBe('/v1/folders/d1');
    expect(calls[0].init?.method).toBe('PATCH');
    expect(bodyOf(calls[0])).toEqual({ parent_folder_id: 'd2' });
  });

  it('deleteFile / deleteFolder DELETE /v1/{files,folders}/{id} (204, no body)', async () => {
    const { fetch: ff, calls: fc } = fakeFetch(() => new Response(null, { status: 204 }));
    await expect(createApiClient({ fetch: ff }).deleteFile('f1')).resolves.toBeUndefined();
    expect(fc[0].url).toBe('/v1/files/f1');
    expect(fc[0].init?.method).toBe('DELETE');

    const { fetch: df, calls: dc } = fakeFetch(() => new Response(null, { status: 204 }));
    await expect(createApiClient({ fetch: df }).deleteFolder('d1')).resolves.toBeUndefined();
    expect(dc[0].url).toBe('/v1/folders/d1');
    expect(dc[0].init?.method).toBe('DELETE');
  });

  it('deleteFilesBatch / deleteFoldersBatch DELETE the collection with ids and parse {deleted}', async () => {
    const { fetch: ff, calls: fc } = fakeFetch(() => json(200, { deleted: 2 }));
    const filesRes = await createApiClient({ fetch: ff }).deleteFilesBatch(['a', 'b']);
    expect(filesRes.deleted).toBe(2);
    expect(fc[0].url).toBe('/v1/files');
    expect(fc[0].init?.method).toBe('DELETE');
    expect(bodyOf(fc[0])).toEqual({ file_ids: ['a', 'b'] });

    const { fetch: df, calls: dc } = fakeFetch(() => json(200, { deleted: 1 }));
    const foldersRes = await createApiClient({ fetch: df }).deleteFoldersBatch(['d']);
    expect(foldersRes.deleted).toBe(1);
    expect(dc[0].url).toBe('/v1/folders');
    expect(bodyOf(dc[0])).toEqual({ folder_ids: ['d'] });
  });

  it('getQuota GETs /v1/me/quota', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { bytes_used: 5, bytes_quota: 100 }));
    const res = await createApiClient({ fetch }).getQuota();
    expect(res).toEqual({ bytes_used: 5, bytes_quota: 100 });
    expect(calls[0].url).toBe('/v1/me/quota');
    expect(calls[0].init?.method).toBe('GET');
  });

  it('getRecipientKey GETs /v1/recipients/{handle} (url-encoded)', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, {
        handle: 'bo b',
        account_type: 'human',
        kem_pubkey: 'k',
        kem_pubkey_fingerprint: 'fp',
      }),
    );
    const res = await createApiClient({ fetch }).getRecipientKey('bo b');
    expect(res.kem_pubkey).toBe('k');
    expect(calls[0].url).toBe('/v1/recipients/bo%20b');
    expect(calls[0].init?.method).toBe('GET');
  });

  it('createShareFolder POSTs /v1/share-folders with the body', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, {
        folder_id: 'f',
        root_folder_id: 'f',
        folder_type: 'share',
        encrypted_name: {},
        recipients: [],
      }),
    );
    await createApiClient({ fetch }).createShareFolder({
      encrypted_name: { ct: 'n' },
      owner_metadata_key_wrap: { ct: 'mk' },
    });
    expect(calls[0].url).toBe('/v1/share-folders');
    expect(calls[0].init?.method).toBe('POST');
    expect(bodyOf(calls[0])).toEqual({
      encrypted_name: { ct: 'n' },
      owner_metadata_key_wrap: { ct: 'mk' },
    });
  });

  it('createInvitation POSTs the folder invitations path with the wraps', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, { invitation_id: 'i', token: 't', expires_at: 1 }),
    );
    const body = {
      recipient_handle: 'bob',
      permission: 'read_write',
      pre_computed_wraps: { metadata_key_wrap: {}, file_dek_wraps: [] },
    };
    const res = await createApiClient({ fetch }).createInvitation('fold1', body);
    expect(res.token).toBe('t');
    expect(calls[0].url).toBe('/v1/share-folders/fold1/invitations');
    expect(bodyOf(calls[0])).toEqual(body);
  });

  it('preview + accept hit /v1/invitations/{token}', async () => {
    const { fetch: pf, calls: pc } = fakeFetch(() =>
      json(200, {
        inviter_handle: 'chris',
        permission: 'read_only',
        file_count: 3,
        expires_at: 1,
        accepted_at: null,
      }),
    );
    const preview = await createApiClient({ fetch: pf }).previewInvitation('tok');
    expect(preview.file_count).toBe(3);
    expect(pc[0].url).toBe('/v1/invitations/tok');
    expect(pc[0].init?.method).toBe('GET');

    const { fetch: af, calls: ac } = fakeFetch(() =>
      json(200, { share_folder_id: 'f', permission: 'read_only', files_granted: 3 }),
    );
    await createApiClient({ fetch: af }).acceptInvitation('tok');
    expect(ac[0].url).toBe('/v1/invitations/tok/accept');
    expect(ac[0].init?.method).toBe('POST');
  });

  it('removeRecipient DELETEs the recipient; leaveShareFolder POSTs leave', async () => {
    const { fetch: rf, calls: rc } = fakeFetch(() => new Response(null, { status: 204 }));
    await createApiClient({ fetch: rf }).removeRecipient('fold1', 'rec1');
    expect(rc[0].url).toBe('/v1/share-folders/fold1/recipients/rec1');
    expect(rc[0].init?.method).toBe('DELETE');

    const { fetch: lf, calls: lc } = fakeFetch(() => new Response(null, { status: 204 }));
    await createApiClient({ fetch: lf }).leaveShareFolder('fold1');
    expect(lc[0].url).toBe('/v1/share-folders/fold1/leave');
    expect(lc[0].init?.method).toBe('POST');
  });

  it('listFolders + listFiles thread the cursor', async () => {
    const { fetch: ff, calls: fc } = fakeFetch(() => json(200, { folders: [], next_cursor: null }));
    await createApiClient({ fetch: ff }).listFolders('parent1', 'cur1');
    expect(fc[0].url).toBe('/v1/folders?parent_folder_id=parent1&cursor=cur1');

    const { fetch: lf, calls: lc } = fakeFetch(() => json(200, { files: [], next_cursor: null }));
    await createApiClient({ fetch: lf }).listFiles('fold1', 'cur2');
    expect(lc[0].url).toBe('/v1/folders/fold1/files?cursor=cur2');
  });

  it('listSharedWithMe GETs /v1/shared-with-me (bug130)', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { folders: [] }));
    const res = await createApiClient({ fetch }).listSharedWithMe();
    expect(res.folders).toEqual([]);
    expect(calls[0].url).toBe('/v1/shared-with-me');
    expect(calls[0].init?.method).toBe('GET');
  });

  // --- C5 admin dashboard -----------------------------------------------------

  it('listConfig GETs /v1/admin/config; updateConfig PATCHes the key with {value}', async () => {
    const { fetch: cf, calls: cc } = fakeFetch(() => json(200, { config: [] }));
    await createApiClient({ fetch: cf }).listConfig();
    expect(cc[0].url).toBe('/v1/admin/config');
    expect(cc[0].init?.method).toBe('GET');

    const { fetch: uf, calls: uc } = fakeFetch(() =>
      json(200, { key: 'session_idle_timeout_hours', value: '30', value_type: 'integer' }),
    );
    const updated = await createApiClient({ fetch: uf }).updateConfig(
      'session_idle_timeout_hours',
      '30',
    );
    expect(updated.value).toBe('30');
    expect(uc[0].url).toBe('/v1/admin/config/session_idle_timeout_hours');
    expect(uc[0].init?.method).toBe('PATCH');
    expect(bodyOf(uc[0])).toEqual({ value: '30' });
  });

  it('getTransparencyStatus GETs /v1/admin/transparency-status', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, { log_size: 7, last_computed: null, last_committed: null, recent_roots: [] }),
    );
    const res = await createApiClient({ fetch }).getTransparencyStatus();
    expect(res.log_size).toBe(7);
    expect(calls[0].url).toBe('/v1/admin/transparency-status');
    expect(calls[0].init?.method).toBe('GET');
  });

  it('listAdminAccounts GETs /v1/admin/accounts and threads the cursor', async () => {
    const { fetch: nf, calls: nc } = fakeFetch(() =>
      json(200, { accounts: [], next_cursor: null }),
    );
    await createApiClient({ fetch: nf }).listAdminAccounts();
    expect(nc[0].url).toBe('/v1/admin/accounts');

    const { fetch: cf, calls: cc } = fakeFetch(() =>
      json(200, { accounts: [], next_cursor: null }),
    );
    await createApiClient({ fetch: cf }).listAdminAccounts('cur1');
    expect(cc[0].url).toBe('/v1/admin/accounts?cursor=cur1');
  });

  it('createGrant POSTs /v1/admin/grants with the body', async () => {
    const { fetch, calls } = fakeFetch(() =>
      json(200, { grant_id: 'g1', granted_account_id: 'a1', granted_until: 1, revoked_at: null }),
    );
    const res = await createApiClient({ fetch }).createGrant({
      granted_account_id: 'a1',
      duration_days: 365,
      note: 'vip',
    });
    expect(res.grant_id).toBe('g1');
    expect(calls[0].url).toBe('/v1/admin/grants');
    expect(calls[0].init?.method).toBe('POST');
    expect(bodyOf(calls[0])).toEqual({ granted_account_id: 'a1', duration_days: 365, note: 'vip' });
  });

  it('extendGrant POSTs the extend path with {duration_days}; revokeGrant DELETEs the grant', async () => {
    const { fetch: ef, calls: ec } = fakeFetch(() =>
      json(200, { grant_id: 'g1', granted_until: 2 }),
    );
    await createApiClient({ fetch: ef }).extendGrant('g1', 30);
    expect(ec[0].url).toBe('/v1/admin/grants/g1/extend');
    expect(ec[0].init?.method).toBe('POST');
    expect(bodyOf(ec[0])).toEqual({ duration_days: 30 });

    const { fetch: rf, calls: rc } = fakeFetch(() => json(200, { grant_id: 'g1', revoked_at: 99 }));
    const revoked = await createApiClient({ fetch: rf }).revokeGrant('g1');
    expect(revoked.revoked_at).toBe(99);
    expect(rc[0].url).toBe('/v1/admin/grants/g1');
    expect(rc[0].init?.method).toBe('DELETE');
  });
});

describe('downloadBackstopMs (W4/W5 — the download absolute ceiling)', () => {
  // The no-progress gap detects a DEAD flow. It cannot bound a live-but-trickling
  // one, because one byte just under the gap IS progress and the gap correctly
  // allows it. Every other transfer path caps that residual absolutely (the
  // governor ceiling on upload, `response_backstop` on the CLI download); the web
  // download capped it with nothing (W4).
  //
  // And the bound must be DERIVED. Reusing the per-read gap value as an atomic
  // total — which the no-body fallback briefly did — is a §1 violation strictly
  // worse than the 120 s constant W3 removed: 20 s over a whole chunk is ~2 Mbps
  // at 5 MiB and ~27 Mbps at 64 MiB (W5).

  it('scales with the requested range — not a constant', () => {
    const small = downloadBackstopMs(5 * 1024 * 1024);
    const large = downloadBackstopMs(64 * 1024 * 1024);
    expect(large).toBeGreaterThan(small);
    // 64 MiB at 0.5 Mbps is ~17 minutes of honest transfer; x4 generosity.
    expect(large).toBeGreaterThan(60 * 60 * 1000);
  });

  it('is strictly monotonic in bytes above the floor', () => {
    const a = downloadBackstopMs(32 * 1024 * 1024);
    const b = downloadBackstopMs(64 * 1024 * 1024);
    const c = downloadBackstopMs(128 * 1024 * 1024);
    expect(b).toBeGreaterThan(a);
    expect(c).toBeGreaterThan(b);
  });

  it('floors a trivially small range (rate-free, so a constant is legitimate)', () => {
    expect(downloadBackstopMs(1024)).toBe(300_000);
    expect(downloadBackstopMs(0)).toBe(300_000);
  });

  it('is clamped below the setTimeout limit — an over-limit delay fires INSTANTLY (W6)', () => {
    // setTimeout takes a signed 32-bit delay: above 2**31-1 ms a browser fires the
    // callback immediately rather than never, inverting the backstop from a
    // last-resort ceiling into an instant abort that fails every attempt.
    const SET_TIMEOUT_MAX = 2 ** 31 - 1;
    for (const bytes of [64 * 1024 * 1024, 34 * 1024 ** 3, Number.MAX_SAFE_INTEGER]) {
      expect(downloadBackstopMs(bytes)).toBeLessThan(SET_TIMEOUT_MAX);
    }
    // Clamped to the same 24 h the CLI transport uses, so the two surfaces agree.
    expect(downloadBackstopMs(Number.MAX_SAFE_INTEGER)).toBe(86_400_000);
  });

  it('never sits at or below a whole-chunk gap value — the W5 regression pin', () => {
    // If this ever fails, someone has reintroduced a flat total on the download
    // path. 20 s was the value W5 wrongly used as an atomic deadline.
    for (const bytes of [5 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024]) {
      expect(downloadBackstopMs(bytes)).toBeGreaterThan(20_000);
      // And comfortably above the 120 s constant W3 removed, at every real size.
      expect(downloadBackstopMs(bytes)).toBeGreaterThan(120_000);
    }
  });
});
