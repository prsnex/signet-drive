// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  AcceptInvitationResponse,
  AttestationVerificationResponse,
  BatchDeleteResponse,
  CompleteMultipartBody,
  CreateFolderBody,
  CreateInvitationBody,
  CreateInvitationResponse,
  CreateShareFolderBody,
  DownloadUrlResponse,
  DriveApi,
  FileView,
  FolderView,
  InitiateMultipartBody,
  InitiateMultipartResponse,
  InvitationPreview,
  ListFilesResponse,
  ListFoldersResponse,
  ListPrsnsResponse,
  LogReceipt,
  MeResponse,
  MetadataKeyWrapResponse,
  PendingInvitationsResponse,
  QuotaResponse,
  RecipientKey,
  RecipientsResponse,
  ServerInfoResponse,
  ShareFolderView,
  SharedWithMeResponse,
  UpdateFileBody,
  UpdateFolderBody,
  UploadFileBody,
  WrappedDekResponse,
} from './api';
import type { Session } from './auth';
import {
  b64uDecode,
  b64uEncode,
  decryptName,
  fingerprint,
  fingerprintRaw,
  hybridRfp,
  hybridUnwrapDek,
  hybridUnwrapMetadataKey,
  initMlkem,
  mlkemKeygen,
  openChunk,
  parseHybridWrapEnvelope,
  utf8Encode,
  type NameEnvelope,
} from './crypto';
import type { JsonObject } from './crypto/jcs';
import { formatBytes } from './format';
import { receiptSigningInput, verificationSigningInput } from './recipient_verify';
import { generateKemKeypair, importKemPrivateNonExtractable } from './kem';
import {
  DEFAULT_DOWNLOAD_RETRY_ATTEMPTS,
  DOWNLOAD_RETRY_ATTEMPTS_MAX,
  Drive,
  UploadCancelledError,
  UploadController,
  WEB_MAX_DOWNLOAD_CONCURRENCY,
  WEB_MAX_UPLOAD_PREPARE_AHEAD,
  capacityRefusal,
  downloadConcurrency,
  downloadRetryAttempts,
  plaintextLength,
  uploadPrepareAhead,
  uuidToBytes,
} from './drive';
import { RelayBusyError, StallError } from './transfer';
import { SignetApiError, type ResumeMultipartResponse } from './api';

beforeAll(async () => {
  await initMlkem(
    readFileSync(
      fileURLToPath(new URL('./crypto/mlkem-wasm/signet_crypto_wasm_bg.wasm', import.meta.url)),
    ),
  );
});

// A faithful in-memory DriveApi: stores exactly the opaque JSON the client sends
// and returns it, mirroring the server's root_folder_id inheritance + the
// single self-wrap read path — enough to exercise the crypto round-trips.
class FakeDrive implements DriveApi {
  private folders = new Map<string, FolderView>();
  private metaWraps = new Map<string, unknown>();
  private files = new Map<
    string,
    {
      view: FileView;
      ciphertext: string;
      wraps: { recipient_account_id: string; wrapped_dek: unknown }[];
      multipart?: { chunks: number; chunkSize: number };
    }
  >();
  // In-flight multipart uploads — a tiny in-memory "bucket": upload_id -> parts.
  private uploads = new Map<
    string,
    { fileId: string; body: InitiateMultipartBody; parts: Map<number, Uint8Array> }
  >();

  async createFolder(body: CreateFolderBody): Promise<FolderView> {
    const rootFolderId = body.parent_folder_id
      ? (this.folders.get(body.parent_folder_id)?.root_folder_id ?? body.parent_folder_id)
      : body.folder_id;
    const view: FolderView = {
      folder_id: body.folder_id,
      parent_folder_id: body.parent_folder_id ?? null,
      root_folder_id: rootFolderId,
      folder_type: 'private',
      encrypted_name: body.encrypted_name,
      created_at: 1_700_000_000,
      modified_at: 1_700_000_000,
    };
    this.folders.set(body.folder_id, view);
    if (body.owner_metadata_key_wrap !== undefined) {
      this.metaWraps.set(body.folder_id, body.owner_metadata_key_wrap);
    }
    return view;
  }

  async listFolders(parentFolderId?: string): Promise<ListFoldersResponse> {
    const folders = [...this.folders.values()].filter(
      (f) => (f.parent_folder_id ?? undefined) === parentFolderId,
    );
    return { folders, next_cursor: null };
  }

  async listFiles(folderId: string): Promise<ListFilesResponse> {
    const files = [...this.files.values()]
      .map((f) => f.view)
      .filter((v) => v.folder_id === folderId);
    return { files, next_cursor: null };
  }

  async uploadFile(fileId: string, body: UploadFileBody): Promise<FileView> {
    const view: FileView = {
      file_id: fileId,
      folder_id: body.folder_id,
      encrypted_name: body.encrypted_name,
      size_bytes: b64uDecode(body.ciphertext).length,
      etag: 'fake-etag',
      algorithm: body.algorithm,
      created_at: 1_700_000_000,
      modified_at: 1_700_000_000,
    };
    this.files.set(fileId, { view, ciphertext: body.ciphertext, wraps: body.wrapped_deks });
    return view;
  }

  async downloadFileBytes(fileId: string): Promise<Uint8Array<ArrayBuffer>> {
    const f = this.files.get(fileId);
    if (!f) throw new Error('file not found');
    return b64uDecode(f.ciphertext);
  }

  // --- multipart transport: a faithful in-memory bucket --------------------
  async initiateMultipart(
    fileId: string,
    body: InitiateMultipartBody,
  ): Promise<InitiateMultipartResponse> {
    const uploadId = crypto.randomUUID();
    this.uploads.set(uploadId, { fileId, body, parts: new Map() });
    const part_urls = Array.from({ length: body.chunk_count }, (_, i) => ({
      part_number: i + 1,
      url: `fake://${uploadId}/part/${i + 1}`,
    }));
    // Small knobs so the bug047 resilience tests run fast (attempts=2 → the
    // first retry is immediate, no backoff sleeps).
    return {
      upload_id: uploadId,
      part_urls,
      expires_at: 1_700_003_600,
      part_retry_attempts: 2,
      stall_timeout_seconds: 5,
      // bug178 phase 2 (S174): serve the seal-ahead knob at its SEEDED value, so
      // every existing upload test — including the resume and stall-injection
      // cases that REBUILD THE QUEUE mid-flight — exercises the PIPELINED path.
      // A staleness bug then surfaces in tests that already exist.
      governor: {
        upload_prepare_ahead: this.uploadPrepareAheadServed,
        concurrency_upload: this.uploadConcurrencyServed,
      },
    };
  }

  /** What the server serves as upload seal-ahead (S174). 1 = the seeded value;
   *  0 exercises the retraction position. */
  uploadPrepareAheadServed: number | undefined = 1;
  /** F4: what the server serves as upload send concurrency. `undefined` keeps
   *  every existing test on the serial path (the resolver's off-position); the
   *  fan-out tests set 4. */
  uploadConcurrencyServed: number | undefined = undefined;

  /** bug047 fault injection: part_number → how many of its next PUT attempts
   *  stall (each consumed attempt throws StallError, the real watchdog's
   *  rejection shape). */
  readonly stallBudget = new Map<number, number>();
  /** Row 18: parts that answer `503 relay-at-capacity` N times before landing. */
  readonly busyBudget = new Map<number, number>();

  async putPart(url: string, chunk: Uint8Array): Promise<string> {
    const match = /^fake:\/\/(.+)\/part\/(\d+)$/.exec(url);
    if (!match) throw new Error('bad part url');
    const partNumber = Number(match[2]);
    const stallsLeft = this.stallBudget.get(partNumber) ?? 0;
    if (stallsLeft > 0) {
      this.stallBudget.set(partNumber, stallsLeft - 1);
      throw new StallError('injected stall');
    }
    const busyLeft = this.busyBudget.get(partNumber) ?? 0;
    if (busyLeft > 0) {
      this.busyBudget.set(partNumber, busyLeft - 1);
      throw new RelayBusyError(1);
    }
    const upload = this.uploads.get(match[1]);
    if (!upload) throw new Error('no such upload');
    upload.parts.set(partNumber, new Uint8Array(chunk));
    return `etag-${match[1]}-${match[2]}`;
  }

  async resumeMultipart(_fileId: string, uploadId: string): Promise<ResumeMultipartResponse> {
    const upload = this.uploads.get(uploadId);
    if (!upload) throw new SignetApiError(404, 'not_found', 'no such upload');
    const uploaded_parts = [...upload.parts.keys()]
      .sort((a, b) => a - b)
      .map((n) => ({ part_number: n, etag: `etag-${uploadId}-${n}` }));
    const part_urls = Array.from({ length: upload.body.chunk_count }, (_, i) => i + 1)
      .filter((n) => !upload.parts.has(n))
      .map((n) => ({ part_number: n, url: `fake://${uploadId}/part/${n}` }));
    return {
      uploaded_parts,
      part_urls,
      wrapped_dek: upload.body.wrapped_deks[0].wrapped_dek,
      chunk_size: upload.body.chunk_size,
      chunk_count: upload.body.chunk_count,
      expires_at: 1_700_007_200,
      part_retry_attempts: 2,
      stall_timeout_seconds: 5,
      // bug178 phase 2 (S174): serve the seal-ahead knob at its SEEDED value, so
      // every existing upload test — including the resume and stall-injection
      // cases that REBUILD THE QUEUE mid-flight — exercises the PIPELINED path.
      // A staleness bug then surfaces in tests that already exist.
      governor: {
        upload_prepare_ahead: this.uploadPrepareAheadServed,
        concurrency_upload: this.uploadConcurrencyServed,
      },
    };
  }

  /** bug050 fault injection: fail the next `count` completeMultipart calls
   *  with this HTTP status (500 = transient → the upload must pause
   *  resumably; 404 = definitive → the caller's abort path). */
  failCompleteBudget: { count: number; status: number; code: string } | null = null;

  async completeMultipart(
    fileId: string,
    uploadId: string,
    body: CompleteMultipartBody,
  ): Promise<FileView> {
    if (this.failCompleteBudget && this.failCompleteBudget.count > 0) {
      this.failCompleteBudget.count -= 1;
      const { status, code } = this.failCompleteBudget;
      throw new SignetApiError(status, code, 'injected finalize failure');
    }
    const upload = this.uploads.get(uploadId);
    if (!upload) throw new Error('no such upload');
    const ordered = [...body.parts].sort((a, b) => a.part_number - b.part_number);
    const buffers = ordered.map((p) => upload.parts.get(p.part_number) ?? new Uint8Array(0));
    const total = buffers.reduce((n, b) => n + b.length, 0);
    const assembled = new Uint8Array(total);
    let offset = 0;
    for (const b of buffers) {
      assembled.set(b, offset);
      offset += b.length;
    }
    const view: FileView = {
      file_id: fileId,
      folder_id: upload.body.folder_id,
      encrypted_name: upload.body.encrypted_name,
      size_bytes: assembled.length,
      etag: 'fake-etag',
      algorithm: upload.body.algorithm,
      created_at: 1_700_000_000,
      modified_at: 1_700_000_000,
    };
    this.files.set(fileId, {
      view,
      ciphertext: b64uEncode(assembled),
      wraps: upload.body.wrapped_deks,
      multipart: { chunks: upload.body.chunk_count, chunkSize: upload.body.chunk_size },
    });
    this.uploads.delete(uploadId);
    return view;
  }

  async abortMultipart(_fileId: string, uploadId: string): Promise<void> {
    this.uploads.delete(uploadId);
  }

  /** Test accessor: in-flight (un-completed, un-aborted) multipart uploads. */
  uploadsInFlight(): number {
    return this.uploads.size;
  }

  /** bug178 (S174): what the server serves as download concurrency.
   *
   *  ⭐ Defaults to the RULED 4 rather than 1 on purpose, so every existing
   *  download test in this suite — the byte-identical round trips, the crossover
   *  cases — exercises the CONCURRENT path. A chunk-ordering bug then surfaces as
   *  corrupt output in tests that already exist, instead of needing a bespoke
   *  test to notice it. Set to 1 to exercise the retraction position. */
  downloadConcurrencyServed: number | undefined = 4;

  /** S184: how many times a download URL was issued for the current download.
   *  ⭐ The whole point of the expiry fix is that this can exceed 1 — the
   *  pre-fix client destructured the URL once and reused it until S3 403'd. */
  downloadUrlCalls = 0;

  /** S184: seconds from NOW at which the issued URL expires. `null` = the old
   *  far-future fixture (no refresh should ever trigger). A small positive value
   *  models a URL that dies before a large download finishes. */
  downloadUrlTtlSecs: number | null = null;

  /** S184: the URL the most recent Range GET actually used — the direct evidence
   *  that fetches migrated to a refreshed URL rather than merely that a refresh
   *  call happened. */
  lastRangeUrl = '';

  async getDownloadUrl(fileId: string): Promise<DownloadUrlResponse> {
    const f = this.files.get(fileId);
    if (!f) throw new Error('file not found');
    this.downloadUrlCalls += 1;
    return {
      // ⚠ The URL must DIFFER per issue, or a test cannot tell a refreshed URL
      // from a cached one — the live defect was ten retries carrying the
      // identical X-Amz-Signature.
      download_url: `fake://file/${fileId}#issue=${this.downloadUrlCalls}`,
      size_bytes: f.view.size_bytes,
      multipart_chunks: f.multipart?.chunks ?? null,
      chunk_size: f.multipart?.chunkSize ?? null,
      // ⚠ RELATIVE TO NOW, mirroring the server (`expires_at = now +
      // DOWNLOAD_URL_TTL_SECS`, multipart.rs:1377). This was a hardcoded
      // `1_700_003_600` — **November 2023**, i.e. already expired — and nothing
      // noticed because no code READ the field until the S184 expiry fix. A dead
      // fixture value is invisible exactly as long as nothing consumes it.
      expires_at: Math.floor(Date.now() / 1000) + (this.downloadUrlTtlSecs ?? 3600),
      concurrency: this.downloadConcurrencyServed,
      download_part_retry_attempts: this.downloadRetryServed,
    };
  }

  /** bug209 (S181): what the server serves as the per-chunk attempt budget.
   *  `undefined` models a pre-0060 server, which must land on the compiled default. */
  downloadRetryServed: number | undefined = undefined;

  /** bug209 (S181): make the next N Range GETs fail with the VERBATIM signature
   *  measured on deployed v0.5.44 — a bare `TypeError` whose message is exactly
   *  "Load failed". Set by the wiring test; zero for every other test. */
  failNextRanges = 0;
  rangeAttempts = 0;

  async getRange(url: string, start: number, end: number): Promise<Uint8Array<ArrayBuffer>> {
    // ⚠ The `#issue=N` fragment models a re-presigned URL (S184): a refreshed URL
    // must be DISTINGUISHABLE from the original, or a test cannot tell a refresh
    // from a cache hit. It is not part of the file id.
    const match = /^fake:\/\/file\/([^#]+)(?:#.*)?$/.exec(url);
    if (!match) throw new Error('bad download url');
    const f = this.files.get(match[1]);
    if (!f) throw new Error('file not found');
    this.rangeAttempts += 1;
    this.lastRangeUrl = url;
    if (this.failNextRanges > 0) {
      this.failNextRanges -= 1;
      throw new TypeError('Load failed');
    }
    return b64uDecode(f.ciphertext).slice(start, end + 1);
  }

  async getWrappedDek(fileId: string): Promise<WrappedDekResponse> {
    const f = this.files.get(fileId);
    if (!f) throw new Error('file not found');
    return { wrapped_dek: f.wraps[0].wrapped_dek };
  }

  async getMetadataKeyWrap(folderId: string): Promise<MetadataKeyWrapResponse> {
    const wrapped_key = this.metaWraps.get(folderId);
    if (wrapped_key === undefined) throw new Error('no metadata-key wrap');
    return { wrapped_key };
  }

  async updateFolder(folderId: string, body: UpdateFolderBody): Promise<FolderView> {
    const view = this.folders.get(folderId);
    if (!view) throw new Error('folder not found');
    if (body.encrypted_name !== undefined) view.encrypted_name = body.encrypted_name;
    if (body.parent_folder_id !== undefined) view.parent_folder_id = body.parent_folder_id;
    return view;
  }

  async updateFile(fileId: string, body: UpdateFileBody): Promise<FileView> {
    const f = this.files.get(fileId);
    if (!f) throw new Error('file not found');
    if (body.encrypted_name !== undefined) f.view.encrypted_name = body.encrypted_name;
    if (body.folder_id !== undefined) f.view.folder_id = body.folder_id;
    return f.view;
  }

  async deleteFile(fileId: string): Promise<void> {
    this.files.delete(fileId);
  }

  async deleteFolder(folderId: string): Promise<void> {
    this.folders.delete(folderId);
  }

  async deleteFilesBatch(fileIds: string[]): Promise<BatchDeleteResponse> {
    let deleted = 0;
    for (const id of fileIds) if (this.files.delete(id)) deleted += 1;
    return { deleted };
  }

  async deleteFoldersBatch(folderIds: string[]): Promise<BatchDeleteResponse> {
    let deleted = 0;
    for (const id of folderIds) if (this.folders.delete(id)) deleted += 1;
    return { deleted };
  }

  async getQuota(): Promise<QuotaResponse> {
    let bytes_used = 0;
    for (const f of this.files.values()) bytes_used += f.view.size_bytes;
    return { bytes_used, bytes_quota: 10_737_418_240 };
  }

  async getMe(): Promise<MeResponse> {
    return {
      account_id: crypto.randomUUID(),
      account_type: 'human',
      handle: 'tester',
      paid_until: 0,
      created_at: 0,
      read_only: false,
      needs_activation: false,
      trial_card_added: false,
      has_passkey: true,
      max_upload_size_bytes: 2_147_483_648,
    };
  }

  // C3 sharing.
  readonly recipients = new Map<string, RecipientKey>();
  lastInvitation: CreateInvitationBody['pre_computed_wraps'] | null = null;
  /** The folder owner id `listRecipients` reports (Bug038). Set to the session
   *  account in these tests (the uploader owns its folders), so the upload's
   *  owner-wrap is skipped as self. */
  ownerAccountId = '';

  async getRecipientKey(handle: string): Promise<RecipientKey> {
    const recipient = this.recipients.get(handle);
    if (!recipient) throw new Error('no such recipient');
    return recipient;
  }

  // --- the verified-source identity layer (F-DOWNGRADE(b)) -------------------
  // A REAL ES256 "server key" signs the attestation responses + receipts, so
  // the client verification exercises real signatures (tamper -> fail); the
  // ML-DSA-87 entry is a placeholder, faithful to the web bound (presence
  // checked structurally, bytes verified on the CLI/server lineages).
  private serverKey: CryptoKeyPair | null = null;
  private serverPubB64 = '';
  private readonly logReceipts = new Map<string, LogReceipt>(); // `${purpose}:${fp}`
  private readonly attestations = new Map<string, AttestationVerificationResponse>();
  private logEntries = 0;

  // Public so tests can model a LYING-but-correctly-signing server
  // (the F-PIN1 threat actor); production code never sees this class.
  async serverSign(input: Uint8Array): Promise<string> {
    if (!this.serverKey) {
      this.serverKey = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify'],
      );
      this.serverPubB64 = b64uEncode(
        new Uint8Array(await crypto.subtle.exportKey('raw', this.serverKey.publicKey)),
      );
    }
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.serverKey.privateKey,
      input as BufferSource,
    );
    return b64uEncode(new Uint8Array(sig));
  }

  async getServerInfo(): Promise<ServerInfoResponse> {
    await this.serverSign(new Uint8Array(0)); // ensure the key exists
    return {
      current_signing_keys: [
        { key_id: 'srv-es', purpose: 'attestation_verification', public_key: this.serverPubB64 },
        { key_id: 'srv-pq', purpose: 'attestation_verification_pq', public_key: 'cGxhY2Vob2xkZXI' },
      ],
    };
  }

  /** Append a key to the fake transparency log: a dual-era §10a receipt whose
   *  ES256 signature is real (over the exact receiptSigningInput bytes). */
  async logKey(accountId: string, fp: string, purpose: string): Promise<LogReceipt> {
    this.logEntries += 1;
    const unsigned: JsonObject = {
      v: 1,
      type: 'signet-pubkey-log-receipt',
      entry_id: this.logEntries,
      entry_version: 2,
      account_id: accountId,
      key_purpose: purpose,
      algorithm: purpose === 'kem_pq' ? 'ML-KEM-1024' : 'ECDH-ES+A256KW',
      public_key_fingerprint: fp,
      entry_hash: 'aa',
      log_size_at_insertion: this.logEntries,
      issued_at: 1_700_000_000,
      max_merge_delay_seconds: 86_400,
      server_key_id: 'srv-es',
      server_pq_key_id: 'srv-pq',
    };
    const receipt: LogReceipt = {
      ...unsigned,
      server_signature: await this.serverSign(receiptSigningInput(unsigned)),
      server_signature_mldsa87: 'cGxhY2Vob2xkZXI',
    };
    this.logReceipts.set(`${purpose}:${fp}`, receipt);
    return receipt;
  }

  async getLogReceipt(fingerprint_: string, purpose: string): Promise<LogReceipt> {
    const receipt = this.logReceipts.get(`${purpose}:${fingerprint_}`);
    if (!receipt) throw new Error('no log receipt for that fingerprint and purpose');
    return receipt;
  }

  /** Mint a dual-shaped §9 verification response for a PRSN bundle (real
   *  ES256 over the exact verificationSigningInput bytes + the four inline
   *  receipts) and return its attestation_id. */
  async attestPrsn(bundle: RecipientKey): Promise<string> {
    const attestationId = crypto.randomUUID();
    const attestation: JsonObject = {
      attestation_id: attestationId,
      subject_account_id: bundle.account_id,
      subject_handle: bundle.handle,
      subject_signing_pubkey_fingerprint: 'fp-sign',
      subject_signing_pq_pubkey_fingerprint: 'fp-sign-pq',
      subject_kem_pubkey: bundle.kem_pubkey,
      subject_kem_pubkey_fingerprint: bundle.kem_pubkey_fingerprint,
      subject_kem_pq_pubkey: bundle.kem_pq_pubkey ?? null,
      subject_kem_pq_pubkey_fingerprint: bundle.kem_pq_pubkey_fingerprint ?? null,
      rfp:
        bundle.kem_pq_pubkey != null
          ? await hybridRfp(b64uDecode(bundle.kem_pubkey), b64uDecode(bundle.kem_pq_pubkey))
          : null,
      status: 'active',
      created_at: 1_700_000_000,
      expires_at: null,
      key_protection: 'secure_enclave',
      prsn_sharing_capability: 'read_only',
    };
    const signedAt = 1_700_000_100;
    const response: AttestationVerificationResponse = {
      attestation,
      server_key_id: 'srv-es',
      server_signature: await this.serverSign(
        verificationSigningInput(attestation, 'srv-es', signedAt),
      ),
      server_pq_key_id: 'srv-pq',
      server_signature_mldsa87: 'cGxhY2Vob2xkZXI',
      signed_at: signedAt,
      subject_signing_pubkey_receipt: await this.logKey(bundle.account_id, 'fp-sign', 'signing'),
      subject_kem_pubkey_receipt: await this.logKey(
        bundle.account_id,
        bundle.kem_pubkey_fingerprint,
        'kem',
      ),
      subject_signing_pq_pubkey_receipt: await this.logKey(
        bundle.account_id,
        'fp-sign-pq',
        'signing_pq',
      ),
      subject_kem_pq_pubkey_receipt:
        bundle.kem_pq_pubkey_fingerprint != null
          ? await this.logKey(bundle.account_id, bundle.kem_pq_pubkey_fingerprint, 'kem_pq')
          : undefined,
    };
    this.attestations.set(attestationId, response);
    return attestationId;
  }

  async getAttestationVerification(id: string): Promise<AttestationVerificationResponse> {
    const response = this.attestations.get(id);
    if (!response) throw new Error('no such attestation');
    return response;
  }

  /** Register a fully-identity-backed HUMAN recipient (bundle + both §10a
   *  receipts) — the standard fixture for the receipt-sourced path. */
  async registerHuman(bundle: RecipientKey): Promise<void> {
    this.recipients.set(bundle.handle, bundle);
    await this.logKey(bundle.account_id, bundle.kem_pubkey_fingerprint, 'kem');
    if (bundle.kem_pq_pubkey_fingerprint != null) {
      await this.logKey(bundle.account_id, bundle.kem_pq_pubkey_fingerprint, 'kem_pq');
    }
  }

  /** Register a fully-identity-backed PRSN recipient (bundle + attestation) —
   *  the standard fixture for the attestation-sourced path. */
  async registerPrsn(bundle: RecipientKey): Promise<void> {
    const attestationId = await this.attestPrsn(bundle);
    this.recipients.set(bundle.handle, { ...bundle, attestation_id: attestationId });
  }

  async createShareFolder(body: CreateShareFolderBody): Promise<ShareFolderView> {
    const folderId = body.folder_id ?? crypto.randomUUID();
    const view: FolderView = {
      folder_id: folderId,
      parent_folder_id: null,
      root_folder_id: folderId,
      folder_type: 'share',
      encrypted_name: body.encrypted_name,
      created_at: 1_700_000_000,
      modified_at: 1_700_000_000,
    };
    this.folders.set(folderId, view);
    this.metaWraps.set(folderId, body.owner_metadata_key_wrap);
    return {
      folder_id: folderId,
      root_folder_id: folderId,
      folder_type: 'share',
      encrypted_name: body.encrypted_name,
      recipients: [],
    };
  }

  async listInvitations(): Promise<PendingInvitationsResponse> {
    return { invitations: [] };
  }

  async cancelInvitation(): Promise<void> {}

  async listRecipients(): Promise<RecipientsResponse> {
    // The owner is reported separately (Bug038). In these tests owner == the
    // uploader, so the upload loop skips it as self (no keys are read for self).
    return {
      recipients: [],
      owner: {
        recipient_account_id: this.ownerAccountId,
        handle: 'owner',
        account_type: 'human',
        kem_pubkey: null,
        kem_pubkey_fingerprint: null,
        permission: 'owner',
        is_mandatory_guardian: false,
      },
    };
  }

  async createInvitation(
    _folderId: string,
    body: CreateInvitationBody,
  ): Promise<CreateInvitationResponse> {
    this.lastInvitation = body.pre_computed_wraps;
    return { invitation_id: crypto.randomUUID(), token: 'invite-token', expires_at: 1_700_003_600 };
  }

  async previewInvitation(): Promise<InvitationPreview> {
    return {
      inviter_handle: 'owner',
      permission: 'read_write',
      file_count: this.lastInvitation?.file_dek_wraps.length ?? 0,
      expires_at: 1_700_003_600,
      accepted_at: null,
    };
  }

  async acceptInvitation(): Promise<AcceptInvitationResponse> {
    return { share_folder_id: crypto.randomUUID(), permission: 'read_write', files_granted: 0 };
  }

  removeRecipient(): Promise<void> {
    return Promise.resolve();
  }

  leaveShareFolder(): Promise<void> {
    return Promise.resolve();
  }

  async listSharedWithMe(): Promise<SharedWithMeResponse> {
    return { folders: [] };
  }

  async listPrsns(): Promise<ListPrsnsResponse> {
    return { prsns: [] };
  }
}

async function newSession(): Promise<Session> {
  const kem = await generateKemKeypair();
  const kemPrivateKey = await importKemPrivateNonExtractable(kem.privatePkcs8);
  // A session always carries a hybrid identity (signup generates it; sign-in
  // refuses a session without one) — self-wraps go hybrid.
  const mlkem = await mlkemKeygen();
  return {
    accountId: crypto.randomUUID(),
    kemPrivateKey,
    kemPubkeyX963: b64uEncode(kem.publicX963),
    mlkemSeed: mlkem.seed,
    kemPqPubkeyEk: b64uEncode(mlkem.ek),
    // The Drive data plane never reads the wrap blob (rotation does); a
    // placeholder satisfies the Session shape.
    wrappedKemPrivkeyBlob: { v: 1, alg: 'A256GCM', iv: '', ct: '', tag: '' },
  };
}

describe('uuidToBytes', () => {
  it('parses a UUID into its 16 raw bytes', () => {
    const bytes = uuidToBytes('00112233-4455-6677-8899-aabbccddeeff');
    expect(Array.from(bytes)).toEqual([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
      0xff,
    ]);
  });

  it('rejects a non-UUID', () => {
    expect(() => uuidToBytes('not-a-uuid')).toThrow();
  });
});

describe('Drive (data-plane crypto orchestration)', () => {
  let session: Session;
  let api: FakeDrive;
  let drive: Drive;

  beforeEach(async () => {
    session = await newSession();
    api = new FakeDrive();
    api.ownerAccountId = session.accountId;
    drive = new Drive(api, session);
  });

  it('round-trips a top-level folder name through the metadata-key chain', async () => {
    const folder = await drive.createFolder('Project Aurora');
    // A fresh Drive has an empty cache, so it must fetch + unwrap the metadata key.
    const reader = new Drive(api, session);
    expect(await reader.folderName(folder)).toBe('Project Aurora');
  });

  it('round-trips a nested folder name under the root metadata key', async () => {
    const root = await drive.createFolder('Work');
    const child = await drive.createFolder('notes', {
      folderId: root.folder_id,
      rootFolderId: root.folder_id,
    });
    expect(child.parent_folder_id).toBe(root.folder_id);
    const reader = new Drive(api, session);
    expect(await reader.folderName(child)).toBe('notes');
  });

  it('round-trips file content + name through upload then download', async () => {
    const folder = await drive.createFolder('Docs');
    const content = utf8Encode('the quick brown fox');
    const file = await drive.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'fox.txt',
      new Blob([content]),
    );

    const reader = new Drive(api, session);
    const downloaded = await reader.downloadFile(file.file_id);
    expect(Array.from(downloaded)).toEqual(Array.from(content));
    expect(await reader.fileName(file, folder.folder_id)).toBe('fox.txt');
  });

  it('round-trips a multi-chunk file through the §4.2 multipart transport', async () => {
    // An 8-byte chunk size forces several chunks from a small payload, so the
    // chunked seal → part PUT → complete → Range-GET → chunked open path is fully
    // exercised without a large fixture.
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Big');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 43 bytes -> 6 chunks
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'pangram.txt',
      new Blob([content]),
    );
    // Stored size is the plaintext plus the §4.2 per-chunk header+tag overhead.
    expect(file.size_bytes).toBeGreaterThan(content.length);

    // The reader uses the default chunk size — download is driven by the server's
    // returned chunk metadata, not the client's setting.
    const reader = new Drive(api, session);
    const downloaded = await reader.downloadFile(file.file_id);
    expect(Array.from(downloaded)).toEqual(Array.from(content));
  });

  it('F4: a page suspension with parts in flight — the errors land BEFORE the visibility event, and no stored part is re-sent', async () => {
    // The record (09-17/18, three suspensions): the four in-flight PUTs' bytes
    // reached storage, the page froze before their 200s arrived, and on wake
    // they surfaced as network errors and were re-sent — 4 × 5 MiB per wake.
    // The order of those errors against `visibilitychange` is the browser's;
    // this test takes the harder order: the errors FIRST, the visibility event
    // after. The retries must park, the wake must refresh from the server's
    // `uploaded_parts`, and the four stored parts must NOT be re-sent.
    api.uploadConcurrencyServed = 4;
    const realPutPart = api.putPart.bind(api);
    const realResume = api.resumeMultipart.bind(api);
    try {
      const chunked = new Drive(api, session, 8);
      const folder = await chunked.createFolder('Sleep');
      const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 43 bytes -> 6 parts
      const controller = new UploadController();
      const putCalls = new Map<number, number>();
      const sequence: string[] = [];
      let hiddenSet = false;
      api.putPart = async (...args: Parameters<typeof api.putPart>) => {
        const n = Number(args[0].split('/part/')[1]);
        putCalls.set(n, (putCalls.get(n) ?? 0) + 1);
        sequence.push(`put:${n}`);
        if (n <= 4 && putCalls.get(n) === 1) {
          // Stored on the server, then the page is suspended before the 200
          // reaches the script: on wake the connection is gone.
          await realPutPart(...args);
          await new Promise((r) => setTimeout(r, 5)); // let all four workers enter
          if (!hiddenSet) {
            hiddenSet = true;
            controller.setVisibility(false);
          }
          throw new SignetApiError(0, 'network', 'connection lost while the page was suspended');
        }
        return realPutPart(...args);
      };
      api.resumeMultipart = async (...args: Parameters<typeof api.resumeMultipart>) => {
        sequence.push('resume');
        return realResume(...args);
      };
      const reports: number[] = [];
      const done = chunked.uploadFile(
        { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
        'sleep.txt',
        new Blob([content]),
        (p) => reports.push(p.suspensions),
        controller,
      );
      // While hidden: the four retries do NOT park (fold 1). Each sees the page
      // was hidden during its attempt, so ONE refresh runs (shared), the four
      // stored parts are skipped, and the batch carries on — no re-send.
      await new Promise((r) => setTimeout(r, 40));
      expect(controller.isVisible).toBe(false);
      for (const n of [1, 2, 3, 4]) expect(putCalls.get(n)).toBe(1);
      // Wake (in the real browser this may land before or after those errors;
      // here it lands after, the harder order).
      controller.setVisibility(true);
      const file = await done;
      // The refresh ran exactly once for this hide, before any PUT after it;
      // parts 1–4 were sent exactly once (never re-sent); 5 and 6 once each.
      const resumeAt = sequence.indexOf('resume');
      expect(resumeAt).toBeGreaterThan(0);
      expect(
        sequence
          .slice(resumeAt + 1)
          .filter((s) => ['put:1', 'put:2', 'put:3', 'put:4'].includes(s)),
      ).toEqual([]);
      for (const n of [1, 2, 3, 4, 5, 6]) expect(putCalls.get(n)).toBe(1);
      expect(sequence.filter((s) => s === 'resume')).toHaveLength(1);
      expect(Math.max(...reports)).toBe(1); // one suspension, counted once, stated to the panel
      expect(file.size_bytes).toBeGreaterThan(content.length);
      const reader = new Drive(api, session);
      expect(Array.from(await reader.downloadFile(file.file_id))).toEqual(Array.from(content));
    } finally {
      api.putPart = realPutPart;
      api.resumeMultipart = realResume;
      api.uploadConcurrencyServed = undefined;
    }
  });

  it('F4 (third arm): hidden but only throttled — a NON-stored part fails and its retry proceeds with no visibility event', async () => {
    // Gus, fold 1: a background tab that is merely throttled must keep
    // re-sending on its own. The page hides with a part in flight; that part
    // genuinely fails (nothing stored); the retry refreshes once (the server
    // reports nothing for it) and sends it again — without anyone looking.
    const realPutPart = api.putPart.bind(api);
    const realResume = api.resumeMultipart.bind(api);
    try {
      const chunked = new Drive(api, session, 8);
      const folder = await chunked.createFolder('Throttled');
      const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 6 parts, serial
      const controller = new UploadController();
      let resumes = 0;
      const putCalls = new Map<number, number>();
      api.putPart = async (...args: Parameters<typeof api.putPart>) => {
        const n = Number(args[0].split('/part/')[1]);
        putCalls.set(n, (putCalls.get(n) ?? 0) + 1);
        if (n === 3 && putCalls.get(3) === 1) {
          controller.setVisibility(false); // hidden while part 3 is in flight
          throw new SignetApiError(0, 'network', 'dropped, nothing stored');
        }
        return realPutPart(...args);
      };
      api.resumeMultipart = async (...args: Parameters<typeof api.resumeMultipart>) => {
        resumes += 1;
        return realResume(...args);
      };
      const reports: number[] = [];
      const file = await chunked.uploadFile(
        { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
        'throttled.txt',
        new Blob([content]),
        (p) => reports.push(p.suspensions),
        controller,
      );
      expect(controller.isVisible).toBe(false); // nobody looked; the upload finished anyway
      expect(putCalls.get(3)).toBe(2); // sent, failed, sent again
      expect(resumes).toBe(1); // one refresh for the hidden interval
      for (const n of [1, 2, 4, 5, 6]) expect(putCalls.get(n)).toBe(1);
      expect(file.size_bytes).toBeGreaterThan(content.length);
    } finally {
      api.putPart = realPutPart;
      api.resumeMultipart = realResume;
    }
  });

  it('F4 (hidden start): a batch begun while the page is hidden counts its wake', async () => {
    // Gus, fold 2: no hide transition ever happens, so the controller must
    // start from the document's state; shown with parts in flight, that is a
    // wake — counted once, refreshed once.
    const realPutPart = api.putPart.bind(api);
    const realResume = api.resumeMultipart.bind(api);
    try {
      const chunked = new Drive(api, session, 8);
      const folder = await chunked.createFolder('HiddenStart');
      const content = utf8Encode('the quick brown fox jumps over the lazy dog');
      const controller = new UploadController();
      controller.initVisibility(false);
      let resumes = 0;
      api.putPart = async (...args: Parameters<typeof api.putPart>) => {
        await new Promise((r) => setTimeout(r, 15));
        return realPutPart(...args);
      };
      api.resumeMultipart = async (...args: Parameters<typeof api.resumeMultipart>) => {
        resumes += 1;
        return realResume(...args);
      };
      const reports: number[] = [];
      const done = chunked.uploadFile(
        { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
        'hidden-start.txt',
        new Blob([content]),
        (p) => reports.push(p.suspensions),
        controller,
      );
      await new Promise((r) => setTimeout(r, 20)); // a part is in flight
      controller.setVisibility(true);
      await done;
      expect(Math.max(...reports)).toBe(1);
      expect(resumes).toBe(1);
    } finally {
      api.putPart = realPutPart;
      api.resumeMultipart = realResume;
    }
  });

  it('F1: a FRESH Drive plans its first file at the 5 MiB floor — 20 MB is 4 parts, and the initiate declares it', async () => {
    // Before F1 a fresh page's first file was planned at the 16 MiB default and a
    // 20 MB file went as one 16 MiB stream (2:10 measured on the travel link, the
    // cancel that produced bug F3). The planner is what `uploadFile` calls, and
    // the initiate body is what the server stores, so both are asserted.
    const fresh = new Drive(api, session);
    expect(fresh.uploadPlan(20_000_000)).toMatchObject({
      chunkSize: 5 * 1024 * 1024,
      chunkCount: 4,
    });
    // A real upload of 6 MiB: two parts at the floor, declared to the server.
    const folder = await fresh.createFolder('First');
    const content = new Uint8Array(6 * 1024 * 1024);
    content[0] = 7;
    const file = await fresh.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'first.bin',
      new Blob([content]),
    );
    const stored = await api.getDownloadUrl(file.file_id);
    expect(stored.chunk_size).toBe(5 * 1024 * 1024);
    expect(stored.multipart_chunks).toBe(2);
  });

  // ⭐ KNOB RULE 4 (bug178, S174): the retraction position must produce IDENTICAL
  // bytes, not merely "work". This is the 2 a.m. path — an operator sets the knob
  // to 1 and the product must behave exactly as it did before S174.
  // ⚠ The mock serves 4 by default, so every OTHER download test in this file
  // already exercises the concurrent path; this is the arm that proves the two
  // configurations agree.
  it('download retraction to N=1 yields the same bytes as the concurrent path', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Retract');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 6 chunks
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'retract.txt',
      new Blob([content]),
    );

    const reader = new Drive(api, session);
    api.downloadConcurrencyServed = 4;
    const concurrent = await reader.downloadFile(file.file_id);
    api.downloadConcurrencyServed = 1;
    const serial = await reader.downloadFile(file.file_id);
    api.downloadConcurrencyServed = undefined; // an older server
    const legacy = await reader.downloadFile(file.file_id);

    expect(Array.from(serial)).toEqual(Array.from(content));
    expect(Array.from(concurrent)).toEqual(Array.from(serial));
    expect(Array.from(legacy)).toEqual(Array.from(serial));

    api.downloadConcurrencyServed = 4; // restore for the rest of the suite
  });

  // ⭐⭐ S184 — THE PRE-SIGNED URL EXPIRES MID-DOWNLOAD, and the client could not
  // see it happen.
  //
  // Observed live on a 100 GB web download: `DOWNLOAD_URL_TTL_SECS` is 3600
  // (server `multipart.rs:54`) whose comment claims the client "re-requests a
  // fresh URL if a very large download outlives the window" — nothing did.
  // Past expiry every Range GET returned S3 403, and because S3 omits CORS
  // headers on errors the browser surfaced `TypeError: Failed to fetch` with NO
  // status ⇒ **expiry is indistinguishable from a network blip here**, so all ten
  // retries re-fetched a dead URL carrying the identical X-Amz-Signature.
  //
  // ⚠ A wall-clock TTL over a `bytes ÷ rate` quantity declares a MINIMUM
  // BANDWIDTH (§B-3.4, the bug060 class): 100 GB in 3600 s demands ~222 Mbps.
  // The CLI/web pair is the control — same file, same bucket, same TTL: CLI
  // finished in 1,242 s and PASSED, web needed ~4,160 s and died at ~87%.
  //
  // ⇒ The fix refreshes PROACTIVELY on the clock, because the error is invisible.
  // This test reproduces the PRECONDITION (a URL that expires mid-download),
  // which no prior test did — §B-5.8: a green suite is evidence only about what
  // it reproduced.
  it('S184: a download URL nearing expiry is RE-PRESIGNED, and fetches migrate to it', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Expiry');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 6 chunks
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'expiry.txt',
      new Blob([content]),
    );

    const reader = new Drive(api, session);

    // Control arm FIRST: a far-future expiry must NOT trigger a refresh, or the
    // test would pass on a client that re-presigns unconditionally — which would
    // be a per-chunk API call on every download.
    api.downloadUrlTtlSecs = null;
    api.downloadUrlCalls = 0;
    const calm = await reader.downloadFile(file.file_id);
    expect(Array.from(calm)).toEqual(Array.from(content));
    expect(api.downloadUrlCalls).toBe(1);

    // Live arm: a URL already inside the refresh margin must be re-issued, and
    // the Range GETs must actually USE the new one.
    api.downloadUrlTtlSecs = 60; // inside URL_REFRESH_MARGIN_SECS (300)
    api.downloadUrlCalls = 0;
    api.lastRangeUrl = '';
    const expiring = await reader.downloadFile(file.file_id);

    expect(Array.from(expiring)).toEqual(Array.from(content));
    expect(api.downloadUrlCalls).toBeGreaterThan(1);
    // ⭐ The load-bearing assertion: a refresh that nothing consumes is theatre.
    expect(api.lastRangeUrl).not.toContain('#issue=1');

    // Forced-refresh arm (Gus's backstop): a FAR-FUTURE expiry means the proactive
    // path never fires, yet a single failed attempt must STILL force a re-presign
    // on retry — the defence that survives a wrong clock, because an expired-URL
    // 403 is indistinguishable from a network blip. Without it, tonight's trace
    // (ten retries on the identical dead signature) is what happens.
    api.downloadUrlTtlSecs = null; // far future ⇒ proactive refresh must NOT fire
    api.downloadConcurrencyServed = 1; // serial, so the one forced failure is deterministic
    api.downloadUrlCalls = 0;
    api.lastRangeUrl = '';
    api.failNextRanges = 1; // one chunk's first attempt fails → retry
    const recovered = await reader.downloadFile(file.file_id);

    expect(Array.from(recovered)).toEqual(Array.from(content));
    expect(api.failNextRanges).toBe(0); // the injected failure was consumed
    expect(api.downloadUrlCalls).toBeGreaterThan(1); // the retry forced a re-presign
    expect(api.lastRangeUrl).not.toContain('#issue=1'); // and the retry used the fresh URL

    api.downloadConcurrencyServed = 4; // restore for the rest of the suite
  });

  // ⭐⭐ bug209 (S181) — THE WIRING TEST, and it exists because its absence was
  // caught by mutation rather than by review.
  //
  // The first cut of this fix had tests for `downloadRetryAttempts()` and for
  // `transferWithRetry`, both passing, and **reverting the call site to a
  // hardcoded `attempts: 3` still left all 410 green**. Nothing exercised the wire
  // between the served response and the retry loop — ROOTS §B-3.10's "a green
  // suite can be pointed at the path you REPLACED". ⚠ That is the same defect
  // shape as bug209 itself: a value documented in one place and compiled in
  // another, with no test spanning the gap.
  //
  // This test spans it: it can only pass if the SERVED number actually reaches
  // `transferWithRetry`.
  it('the SERVED retry budget reaches the download loop (mutation-caught wiring)', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Retry');
    // ⚠⚠ EXACTLY ONE CHUNK, and that is load-bearing. The failure injection is
    // global, so on a multi-chunk file the injected failures SPREAD across
    // concurrent chunks and no single chunk ever exceeds 3 attempts — which would
    // let the old compiled budget pass this test. Caught by writing it wrong first:
    // a 19-byte body gave 3 chunks and 7 attempts instead of 5.
    const content = utf8Encode('wire'); // 4 bytes < the 8-byte chunk size => 1 chunk
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'retry.txt',
      new Blob([content]),
    );

    const reader = new Drive(api, session);

    // Serve 6 and fail the first 4 Range GETs with the verbatim S181 signature.
    // ⚠ 4 consecutive failures EXCEEDS the old compiled budget of 3, so this
    // download can only complete if the served 6 was read.
    api.downloadRetryServed = 6;
    api.failNextRanges = 4;
    api.rangeAttempts = 0;
    // ⭐ R2 (Gus, S181): the single-chunk premise asserted as a NAMED PRECONDITION,
    // not left implicit in the fixture. If someone edits the content and it becomes
    // multi-chunk, THIS breaks — loudly and by name — instead of the test quietly
    // continuing to pass while measuring something weaker (failures diluted across
    // concurrent chunks, which is exactly how the first draft was wrong).
    let observedTotalChunks = -1;
    const recovered = await reader.downloadFile(file.file_id, (p) => {
      observedTotalChunks = p.totalChunks;
    });
    expect(observedTotalChunks).toBe(1); // PRECONDITION: all failures hit one budget
    expect(Array.from(recovered)).toEqual(Array.from(content));
    expect(api.rangeAttempts).toBe(5); // 4 failures + the success

    // ⛔ The other direction: a served budget too small for the same failure run
    // must still FAIL. Without this arm the test would pass for a client that
    // ignored the knob and simply retried forever.
    api.downloadRetryServed = 2;
    api.failNextRanges = 4;
    await expect(reader.downloadFile(file.file_id)).rejects.toThrow();

    // A pre-0060 server omits the field: the compiled default (10) must carry the
    // same 4-failure run that the old hardcoded 3 could not.
    api.downloadRetryServed = undefined;
    api.failNextRanges = 4;
    const legacy = await reader.downloadFile(file.file_id);
    expect(Array.from(legacy)).toEqual(Array.from(content));

    api.failNextRanges = 0; // restore for the rest of the suite
    // ⚠ 30 s, not the 5 s default: this test drives the REAL jittered backoff
    // (`downloadFile` exposes no sleep hook), and 4 failures cost up to
    // 0 + 1 + 2 + 4 s per arm by `backoffMs`. The slowness is the schedule under
    // test, not a hang — and mocking it away would remove the thing that makes the
    // budget mean anything.
  }, 30_000);

  // bug193 (S176): the DISCRIMINATOR between the old rounds loop and the sliding
  // window. A slow HEAD stalls both identically (bounded memory + an in-order
  // sink permit nothing else), so the test gates chunk 1: the rounds loop would
  // refuse to start chunks 4 and 5 until chunk 1 lands (the whole round joins);
  // the window writes chunk 0, slides, and starts them while 1 still hangs.
  it('bug193: the window slides past a slow non-head chunk instead of joining a round', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Slide');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 6 chunks @ 8
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'slide.txt',
      new Blob([content]),
    );

    const reader = new Drive(api, session);
    api.downloadConcurrencyServed = 4;
    const realGetRange = api.getRange.bind(api);
    const startedChunks: number[] = [];
    const onDisk = 8 + 34; // plaintext chunk + MULTIPART_CHUNK_OVERHEAD
    let releaseGated!: () => void;
    const gate = new Promise<void>((resolve) => (releaseGated = resolve));
    api.getRange = async (url: string, start: number, end: number) => {
      const index = Math.floor(start / onDisk);
      startedChunks.push(index);
      if (index === 1) await gate; // chunk 1 hangs until the window proves itself
      return realGetRange(url, start, end);
    };
    try {
      const downloadDone = reader.downloadFile(file.file_id);
      // While chunk 1 is gated, writing chunk 0 advances the head once, so the
      // window admits chunk 4 — and MUST NOT admit chunk 5 (started-but-unwritten
      // is capped at n, which is the memory bound). Both directions are the test:
      // the rounds loop starts neither; an unbounded pipeline starts both.
      const deadline = Date.now() + 2000;
      while (!startedChunks.includes(4) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 1));
      }
      // Let any (incorrect) further scheduling surface before we release.
      await new Promise((r) => setTimeout(r, 20));
      const startedWhileGated = [...startedChunks];
      releaseGated();
      const downloaded = await downloadDone;

      expect(startedWhileGated).toContain(4); // the window slid past the barrier
      expect(startedWhileGated).not.toContain(5); // ...but honored the bound
      // The round-trip is undisturbed: the reorder head delivered in order.
      expect(Array.from(downloaded)).toEqual(Array.from(content));
      // Every chunk started exactly once — the cursor hands out no duplicates.
      expect([...startedChunks].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5]);
    } finally {
      api.getRange = realGetRange;
      api.downloadConcurrencyServed = 4;
    }
  });

  // Gus F1 (v03): the one plaintext↔stored derivation site. Serving the stored
  // size as Content-Length would end every SW download "short" by 34 × chunks.
  it('plaintextLength strips exactly the per-chunk envelope overhead', () => {
    // 3 chunks stored: 2 full (8 + 34) + 1 partial (3 + 34) = 121 stored, 19 plain.
    expect(plaintextLength(121, 3)).toBe(19);
    expect(plaintextLength(34 + 5, 1)).toBe(5);
  });

  it('reports live upload progress (bytes + parts) via the onProgress callback', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Prog');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 43 bytes -> 6 chunks
    const calls: Array<[number, number, number, number]> = [];
    // F3: the in-flight count and the MEASURED rate ride the same reports. The
    // fake bucket answers instantly, which would make every observed rate
    // non-credible (0 ms) and `measured` never true; a 3 ms delay per part keeps
    // the timing real without slowing the suite.
    const realPutPart = api.putPart.bind(api);
    api.putPart = async (...args: Parameters<typeof api.putPart>) => {
      await new Promise((r) => setTimeout(r, 3));
      return realPutPart(...args);
    };
    const f3: Array<[number, number | null, number | null]> = [];
    await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'p.txt',
      new Blob([content]),
      (p) => {
        calls.push([p.completedParts, p.totalParts, p.sentBytes, p.totalBytes]);
        f3.push([p.inFlightParts, p.measuredRateBytesPerSec, p.etaSeconds]);
      },
    );
    api.putPart = realPutPart;
    // F3: the first report has nothing in flight and NO rate (the bootstrap seed
    // never leaks as a measurement); a report exists with a part in flight before
    // any part completed and still no rate; the last report has nothing in flight
    // and a measured rate with a zero ETA.
    expect(f3[0]).toEqual([0, null, null]);
    const silentStretch = f3.findIndex((r, i) => r[0] > 0 && calls[i][0] === 0);
    expect(silentStretch).toBeGreaterThan(0);
    expect(f3[silentStretch][1]).toBeNull();
    expect(f3.at(-1)?.[0]).toBe(0);
    expect(f3.at(-1)?.[1]).not.toBeNull();
    expect(f3.at(-1)?.[2]).toBe(0);
    // The initial 0-state, then a tick per landed part: completedParts climbs
    // to 6 and sentBytes tracks accounted plaintext (8 per full part, 3 for
    // the last), never regressing, never past totalBytes (bug046: the bar is
    // BYTES-based, so a slow upload visibly moves).
    expect(calls[0]).toEqual([0, 6, 0, 43]);
    expect(calls.at(-1)).toEqual([6, 6, 43, 43]);
    for (let i = 1; i < calls.length; i++) {
      expect(calls[i][0]).toBeGreaterThanOrEqual(calls[i - 1][0]);
      expect(calls[i][2]).toBeGreaterThanOrEqual(calls[i - 1][2]);
      expect(calls[i][2]).toBeLessThanOrEqual(43);
    }
  });

  it('bug061: reports live download progress (chunks + bytes) via the onProgress callback', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('DlProg');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog'); // 43 bytes -> 6 chunks
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'd.txt',
      new Blob([content]),
    );
    const total = file.size_bytes; // on-disk (ciphertext + §4.2 overhead)

    const reader = new Drive(api, session);
    const calls: Array<[number, number, number, number]> = [];
    const downloaded = await reader.downloadFile(file.file_id, (p) =>
      calls.push([p.completedChunks, p.totalChunks, p.receivedBytes, p.totalBytes]),
    );
    // The fix must not disturb the round-trip.
    expect(Array.from(downloaded)).toEqual(Array.from(content));
    // The initial 0-state (once the totals are known), then a tick per
    // fetched-and-opened chunk: completedChunks climbs to 6 and receivedBytes
    // tracks on-disk bytes actually pulled — never regressing, never past the
    // total (the honest read-path analog of the bug046 upload bar).
    expect(calls[0]).toEqual([0, 6, 0, total]);
    expect(calls.at(-1)).toEqual([6, 6, total, total]);
    for (let i = 1; i < calls.length; i++) {
      expect(calls[i][0]).toBeGreaterThanOrEqual(calls[i - 1][0]);
      expect(calls[i][2]).toBeGreaterThanOrEqual(calls[i - 1][2]);
      expect(calls[i][2]).toBeLessThanOrEqual(total);
    }
  });

  it('bug047: a stalled part PUT retries on a fresh attempt and the upload completes', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Stall');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    // Part 3's first attempt stalls; the (immediate) second attempt succeeds
    // within the served attempts=2 budget.
    api.stallBudget.set(3, 1);
    let retriesSeen = 0;
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'stall.txt',
      new Blob([content]),
      (p) => {
        retriesSeen = Math.max(retriesSeen, p.retries);
      },
    );
    expect(retriesSeen).toBe(1);
    const reader = new Drive(api, session);
    const downloaded = await reader.downloadFile(file.file_id);
    expect(Array.from(downloaded)).toEqual(Array.from(content));
  });

  it('bug179: downloadFileTo STREAMS each verified chunk to the sink and commits once', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Stream');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'stream.txt',
      new Blob([content]),
    );

    const written: number[] = [];
    let closed = 0;
    let aborted = 0;
    const received: number[] = [];
    await new Drive(api, session).downloadFileTo(file.file_id, {
      write: async (chunk) => {
        written.push(chunk.length);
        for (const b of chunk) received.push(b);
        // ⭐ The structural guarantee behind the memory claim: commit has NOT
        // happened while chunks are still arriving, so nothing is being held
        // back to be concatenated at the end.
        expect(closed).toBe(0);
      },
      close: async () => {
        closed += 1;
      },
      abort: async () => {
        aborted += 1;
      },
    });

    // Delivered in pieces, not one buffer — the whole point of bug179.
    expect(written.length).toBeGreaterThan(1);
    expect(Array.from(received)).toEqual(Array.from(content));
    // Committed exactly once, and never discarded on the success path.
    expect(closed).toBe(1);
    expect(aborted).toBe(0);
  });

  it('bug179: a download that fails part-way ABORTS the sink and never commits', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Fail');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'fail.txt',
      new Blob([content]),
    );

    let closed = 0;
    let aborted = 0;
    let writes = 0;
    // Fail the sink itself on the 2nd chunk — a mid-stream failure after real
    // bytes have already been handed over, which is exactly the state that used
    // to leave a valid-but-short file on the CLI (bug180).
    const boom = new Error('disk went away');
    await expect(
      new Drive(api, session).downloadFileTo(file.file_id, {
        write: async () => {
          writes += 1;
          if (writes === 2) throw boom;
        },
        close: async () => {
          closed += 1;
        },
        abort: async () => {
          aborted += 1;
        },
      }),
    ).rejects.toThrow('disk went away');

    // ⚠ THE ASSERTION THAT IS THE FIX: discarded, never committed.
    expect(aborted).toBe(1);
    expect(closed).toBe(0);
  });

  it('bug179 negative control: a cleanup failure does not mask the real error', async () => {
    // ⚠ Without this, `abort` could throw and replace the caller's diagnosis
    // with a confusing secondary failure — the download reason is what the user
    // is owed.
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Mask');
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'mask.txt',
      new Blob([utf8Encode('the quick brown fox jumps over the lazy dog')]),
    );
    await expect(
      new Drive(api, session).downloadFileTo(file.file_id, {
        write: async () => {
          throw new Error('the REAL failure');
        },
        close: async () => {},
        abort: async () => {
          throw new Error('cleanup also failed');
        },
      }),
    ).rejects.toThrow('the REAL failure');
  });

  it('row 18 (bug075): a 503 relay-at-capacity surfaces as waitingForCapacitySeconds, and CLEARS on progress', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Busy');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    // Part 2 is refused twice for capacity, then lands.
    api.busyBudget.set(2, 2);
    const waiting: (number | null)[] = [];
    let retriesSeen = 0;
    const file = await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'busy.txt',
      new Blob([content]),
      (p) => {
        waiting.push(p.waitingForCapacitySeconds);
        retriesSeen = Math.max(retriesSeen, p.retries);
      },
    );

    // 1. The state was REACHED and carries the server's own Retry-After. Before
    //    row 18 the hook fired and nothing consumed it, so the bar simply froze.
    expect(waiting).toContain(1);

    // 2. ⭐ THE DISCRIMINATING HALF: it CLEARS. A waiting flag that latches
    //    would leave a healthy upload permanently claiming to be blocked —
    //    which is bug075's own shape (a state a person cannot read) with the
    //    sign flipped. The last report must be null, and only completed
    //    progress may clear it.
    expect(waiting.at(-1)).toBeNull();

    // 3. A capacity refusal is NOT a retry. Conflating them would spend the
    //    part-retry budget on the server's own rationing and inflate the
    //    user-visible retry count (`filelist_upload_retrying`) on a healthy
    //    transfer. (S185: that string no longer claims a network cause — the
    //    copy asserted a diagnosis the client cannot make — but the count it
    //    shows must still not move on a capacity refusal.)
    expect(retriesSeen).toBe(0);

    // 4. The file is intact — the state is cosmetic, never a transfer change.
    const reader = new Drive(api, session);
    const downloaded = await reader.downloadFile(file.file_id);
    expect(Array.from(downloaded)).toEqual(Array.from(content));
    // ⚠ Real time, not fake timers: the client genuinely sleeps the server's
    // Retry-After, and that sleep IS the behaviour under test. The injected
    // wait is 1 s (x2 refusals) rather than mocked away, so this exercises the
    // production path; hence the raised budget.
  }, 10_000);

  it('row 18 negative control: an upload that is never refused NEVER reports a waiting state', async () => {
    // ⚠ Without this, test 1 could pass on an implementation that reports
    // "waiting" unconditionally. This is what makes the assertion above mean
    // something (ROOTS: the negative control is what makes a test a test).
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Clean');
    const seen: (number | null)[] = [];
    await chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'clean.txt',
      new Blob([utf8Encode('the quick brown fox jumps over the lazy dog')]),
      (p) => seen.push(p.waitingForCapacitySeconds),
    );
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((v) => v === null)).toBe(true);
  });

  it('bug047: an exhausted part PAUSES resumably; resume re-syncs with the server and completes', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Pause');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    // Part 2 stalls past the whole attempts=2 budget → the upload must pause.
    api.stallBudget.set(2, 99);
    const controller = new UploadController();
    let paused = false;
    let pausedAtParts = -1;
    const uploadPromise = chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'pause.txt',
      new Blob([content]),
      (p) => {
        if (p.paused) {
          paused = true;
          pausedAtParts = p.completedParts;
        }
      },
      controller,
    );
    await vi.waitFor(() => expect(paused).toBe(true));
    expect(pausedAtParts).toBe(1); // part 1 landed; part 2 is the blocker
    expect(controller.isPaused).toBe(true);

    // The window clears; the user resumes. The drive re-syncs through
    // /resume (the stored part 1 is skipped, fresh URLs for 2..6) and finishes.
    api.stallBudget.delete(2);
    controller.resume();
    const file = await uploadPromise;

    const reader = new Drive(api, session);
    const downloaded = await reader.downloadFile(file.file_id);
    expect(Array.from(downloaded)).toEqual(Array.from(content));
  });

  it('bug047: cancelling a paused upload aborts it and frees the fake bucket', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Cancel');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    api.stallBudget.set(2, 99);
    const controller = new UploadController();
    let paused = false;
    const uploadPromise = chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'cancel.txt',
      new Blob([content]),
      (p) => {
        if (p.paused) paused = true;
      },
      controller,
    );
    await vi.waitFor(() => expect(paused).toBe(true));
    controller.cancel();
    await expect(uploadPromise).rejects.toBeInstanceOf(UploadCancelledError);
    // The in-flight upload was aborted (the fake's abortMultipart removes it).
    expect(api.uploadsInFlight()).toBe(0);
    api.stallBudget.clear();
  });

  it('bug050: a transient finalize failure PAUSES resumably — a fully-transferred upload is never aborted', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('Finalize');
    const content = utf8Encode('the quick brown fox jumps over the lazy dog');
    api.failCompleteBudget = { count: 1, status: 500, code: 'internal' };
    const controller = new UploadController();
    let paused = false;
    let pausedAtParts = -1;
    const uploadPromise = chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'finalize.txt',
      new Blob([content]),
      (p) => {
        if (p.paused) {
          paused = true;
          pausedAtParts = p.completedParts;
        }
      },
      controller,
    );
    await vi.waitFor(() => expect(paused).toBe(true));
    // The pause happened at the FINALIZE: every part was already stored, and
    // the upload is still alive server-side — NOT aborted (the pre-bug050
    // behavior destroyed a fully-transferred upload here).
    expect(pausedAtParts).toBe(6);
    expect(api.uploadsInFlight()).toBe(1);

    // Resume re-drives /resume (every part stored, none to send) → the part
    // loop is a no-op → the finalize re-runs and completes byte-correct.
    controller.resume();
    const file = await uploadPromise;
    expect(api.uploadsInFlight()).toBe(0);
    const downloaded = await new Drive(api, session).downloadFile(file.file_id);
    expect(Array.from(downloaded)).toEqual(Array.from(content));
  });

  it('bug050: a definitive finalize verdict (404 — the upload was swept) still throws and aborts', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('FinalizeGone');
    const content = utf8Encode('gone');
    api.failCompleteBudget = { count: 1, status: 404, code: 'not_found' };
    const controller = new UploadController();
    const uploadPromise = chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'gone.txt',
      new Blob([content]),
      undefined,
      controller,
    );
    await expect(uploadPromise).rejects.toMatchObject({ status: 404 });
    // Definitive verdicts keep the prompt abort — the reservation is freed.
    expect(api.uploadsInFlight()).toBe(0);
  });

  it('bug212 G2: a 409 finalize verdict (a merge may be running) parks WITHOUT aborting — the DEK survives', async () => {
    const chunked = new Drive(api, session, 8);
    const folder = await chunked.createFolder('FinalizeConflict');
    const content = utf8Encode('merging');
    // 409 is the server's conflict class: resume's Absent/Unknown/OverDeclared
    // arms, the CAS-loss, an abort refusal — every state where a merge MAY still
    // land. The client must NOT abort into that window: the server-side probe
    // would see the not-yet-materialised object, reclaim the row, and the merge
    // would orphan (the bug212 DEK cascade). So the pending upload is left for
    // resume or the sweep to finalize forward, never torn down here.
    api.failCompleteBudget = { count: 1, status: 409, code: 'version_conflict' };
    const controller = new UploadController();
    const uploadPromise = chunked.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'merging.txt',
      new Blob([content]),
      undefined,
      controller,
    );
    await expect(uploadPromise).rejects.toMatchObject({ status: 409 });
    expect(api.uploadsInFlight()).toBe(1);
  });

  it('renames a folder by re-encrypting the name under the same metadata key', async () => {
    const folder = await drive.createFolder('Work');
    const renamed = await drive.renameFolder(folder, 'Work (archived)');
    // A fresh reader decrypts the new name from the re-encrypted envelope.
    const reader = new Drive(api, session);
    expect(await reader.folderName(renamed)).toBe('Work (archived)');
  });

  it('renames a file under its root metadata key', async () => {
    const folder = await drive.createFolder('Docs');
    const file = await drive.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'draft.txt',
      new Blob([utf8Encode('hi')]),
    );
    const renamed = await drive.renameFile(file, folder.folder_id, 'final.txt');
    const reader = new Drive(api, session);
    expect(await reader.fileName(renamed, folder.folder_id)).toBe('final.txt');
  });

  it('moves a file within the same root without re-encrypting the name', async () => {
    const root = await drive.createFolder('Root');
    const sub = await drive.createFolder('sub', {
      folderId: root.folder_id,
      rootFolderId: root.folder_id,
    });
    const file = await drive.uploadFile(
      { folderId: root.folder_id, rootFolderId: root.folder_id, shareFolder: false },
      'note.txt',
      new Blob([utf8Encode('x')]),
    );
    const moved = await drive.moveFile(file.file_id, sub.folder_id);
    expect(moved.folder_id).toBe(sub.folder_id);
    // The §7.3 AAD binds root + file id (both unchanged), so the name still opens.
    const reader = new Drive(api, session);
    expect(await reader.fileName(moved, root.folder_id)).toBe('note.txt');
  });

  it('deletes a file', async () => {
    const folder = await drive.createFolder('Trash');
    const file = await drive.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'gone.txt',
      new Blob([utf8Encode('bye')]),
    );
    await drive.deleteFile(file.file_id);
    const { files } = await drive.listFiles(folder.folder_id);
    expect(files).toHaveLength(0);
  });

  it('reports quota usage that grows as files are uploaded', async () => {
    const folder = await drive.createFolder('Q');
    expect((await drive.quota()).bytes_used).toBe(0);
    await drive.uploadFile(
      { folderId: folder.folder_id, rootFolderId: folder.folder_id, shareFolder: false },
      'a.bin',
      new Blob([utf8Encode('0123456789')]),
    );
    const after = await drive.quota();
    expect(after.bytes_used).toBeGreaterThan(0);
    expect(after.bytes_quota).toBe(10_737_418_240);
  });

  it('shares a folder: a HUMAN recipient (receipt-sourced) unwraps the metadata key + every file DEK', async () => {
    // A hybrid human recipient, identity-backed by §10a log receipts (the
    // F-DOWNGRADE(b) human path — humans have no attestation).
    const recipientKem = await generateKemKeypair();
    const recipientPriv = await importKemPrivateNonExtractable(recipientKem.privatePkcs8);
    const recipientMlkem = await mlkemKeygen();
    await api.registerHuman({
      handle: 'bob',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });

    // Owner creates a share folder and uploads two files.
    const folder = await drive.createShareFolder('Project Aurora');
    const target = {
      folderId: folder.folder_id,
      rootFolderId: folder.folder_id,
      shareFolder: true,
    };
    const fileA = await drive.uploadFile(target, 'a.txt', new Blob([utf8Encode('alpha')]));
    const fileB = await drive.uploadFile(target, 'b.txt', new Blob([utf8Encode('bravo')]));

    // A fresh owner session invites bob — exercises recovering the owner's own
    // metadata-key wrap, then re-wrapping the metadata key + each DEK to bob.
    const owner2 = new Drive(api, session);
    await owner2.inviteToShareFolder(target, 'bob', 'read_write');

    // The recipient, with only their private key + the staged wraps, recovers the
    // metadata key (→ names) and each file's DEK (→ content).
    const wraps = api.lastInvitation;
    if (!wraps) throw new Error('no invitation was captured');
    const rootBytes = uuidToBytes(folder.folder_id);
    // Mandatory hybrid write: the staged wraps are hybrid for a human too.
    const metadataKey = await hybridUnwrapMetadataKey(
      recipientPriv,
      recipientMlkem.seed,
      parseHybridWrapEnvelope(wraps.metadata_key_wrap),
      recipientKem.publicX963,
      recipientMlkem.ek,
      rootBytes,
    );

    expect(wraps.file_dek_wraps).toHaveLength(2);
    const recovered = new Map<string, string>();
    for (const fdw of wraps.file_dek_wraps) {
      const dek = await hybridUnwrapDek(
        recipientPriv,
        recipientMlkem.seed,
        parseHybridWrapEnvelope(fdw.wrap),
        recipientKem.publicX963,
        recipientMlkem.ek,
      );
      // The shared files are single-chunk (§4.2): fetch the whole object + open chunk 0.
      const { download_url, size_bytes } = await api.getDownloadUrl(fdw.file_id);
      const envelope = await api.getRange(download_url, 0, size_bytes - 1);
      const content = await openChunk(dek, uuidToBytes(fdw.file_id), 0, 1, envelope);
      recovered.set(fdw.file_id, new TextDecoder().decode(content));
    }
    expect(recovered.get(fileA.file_id)).toBe('alpha');
    expect(recovered.get(fileB.file_id)).toBe('bravo');

    // The recovered metadata key also decrypts the file names.
    const nameA = await decryptName(
      metadataKey,
      rootBytes,
      uuidToBytes(fileA.file_id),
      fileA.encrypted_name as NameEnvelope,
    );
    expect(nameA).toBe('a.txt');
  });

  it('shares to a HYBRID recipient: wraps go hybrid and the recipient unwraps them (§9.2)', async () => {
    // A hybrid recipient: classical P-256 pair + ML-KEM identity, full bundle.
    const recipientKem = await generateKemKeypair();
    const recipientPriv = await importKemPrivateNonExtractable(recipientKem.privatePkcs8);
    const recipientMlkem = await mlkemKeygen();
    await api.registerPrsn({
      handle: 'hlin-ai',
      account_type: 'prsn',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });

    const folder = await drive.createShareFolder('PQ Share');
    const target = {
      folderId: folder.folder_id,
      rootFolderId: folder.folder_id,
      shareFolder: true,
    };
    const file = await drive.uploadFile(target, 'secret.txt', new Blob([utf8Encode('hybrid!')]));
    await drive.inviteToShareFolder(target, 'hlin-ai', 'read_only');

    const wraps = api.lastInvitation;
    if (!wraps) throw new Error('no invitation was captured');
    const rootBytes = uuidToBytes(folder.folder_id);

    // The staged wraps MUST be hybrid (the §9.2 writer discipline) …
    const metaEnv = parseHybridWrapEnvelope(wraps.metadata_key_wrap);
    expect(metaEnv.alg).toBe('ECDH-ES+ML-KEM-1024+A256KW');
    // … and the recipient (ECDH private key + ML-KEM seed) unwraps them.
    const metadataKey = await hybridUnwrapMetadataKey(
      recipientPriv,
      recipientMlkem.seed,
      metaEnv,
      recipientKem.publicX963,
      recipientMlkem.ek,
      rootBytes,
    );
    const dekEnv = parseHybridWrapEnvelope(wraps.file_dek_wraps[0].wrap);
    const dek = await hybridUnwrapDek(
      recipientPriv,
      recipientMlkem.seed,
      dekEnv,
      recipientKem.publicX963,
      recipientMlkem.ek,
    );
    const { download_url, size_bytes } = await api.getDownloadUrl(file.file_id);
    const envelope = await api.getRange(download_url, 0, size_bytes - 1);
    const content = await openChunk(dek, uuidToBytes(file.file_id), 0, 1, envelope);
    expect(new TextDecoder().decode(content)).toBe('hybrid!');

    const name = await decryptName(
      metadataKey,
      rootBytes,
      uuidToBytes(file.file_id),
      file.encrypted_name as NameEnvelope,
    );
    expect(name).toBe('secret.txt');
  });

  it('N6: refuses to wrap for a half-stripped hybrid bundle — never falls back classical', async () => {
    // The shape a PQ-stripping attacker leaves: the classical half intact, the
    // PQ fingerprint present but the key removed (or vice versa). §9.2: the
    // writer must ERROR, not silently produce a classical wrap.
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    api.recipients.set('mallory', {
      handle: 'mallory',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    const folder = await drive.createShareFolder('N6');
    const target = {
      folderId: folder.folder_id,
      rootFolderId: folder.folder_id,
      shareFolder: true,
    };
    await expect(drive.inviteToShareFolder(target, 'mallory', 'read_only')).rejects.toThrow(
      /half-stripped/,
    );
    // The key-without-fingerprint direction refuses the same way.
    api.recipients.set('mallory', {
      handle: 'mallory',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
    });
    await expect(drive.inviteToShareFolder(target, 'mallory', 'read_only')).rejects.toThrow(
      /half-stripped/,
    );
    // A tampered PQ key (fingerprint mismatch) also refuses.
    const wrong = new Uint8Array(recipientMlkem.ek);
    wrong[0] ^= 1;
    api.recipients.set('mallory', {
      handle: 'mallory',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(wrong),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    await expect(drive.inviteToShareFolder(target, 'mallory', 'read_only')).rejects.toThrow(
      /fingerprint mismatch/,
    );
  });

  it('rejects a recipient key whose fingerprint does not match (P-011)', async () => {
    const recipientKem = await generateKemKeypair();
    api.recipients.set('mallory', {
      handle: 'mallory',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: 'not-the-real-fingerprint',
    });
    await expect(drive.recipientKey('mallory')).rejects.toThrow();
  });

  it('F-DOWNGRADE(a): refuses a FULLY-stripped bundle — never a classical wrap', async () => {
    // The harvest-now downgrade: a directory response with the whole PQ pair
    // removed presents as a "legitimate classical recipient". The writer must
    // refuse outright — there is no legitimate classical identity at v1.
    const recipientKem = await generateKemKeypair();
    api.recipients.set('mallory', {
      handle: 'mallory',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
    });
    await expect(drive.recipientKey('mallory')).rejects.toThrow(/refusing a classical-only/);
  });

  it('F-DOWNGRADE(b): rejects bundle keys that differ from the attested keys (substitution)', async () => {
    // Mint an honest attestation for one keypair, then serve a directory
    // bundle carrying a DIFFERENT (coherent, fingerprint-valid) keypair under
    // the same attestation — the substitution the verified source exists to
    // catch.
    const honest = await generateKemKeypair();
    const honestMlkem = await mlkemKeygen();
    const accountId = crypto.randomUUID();
    await api.registerPrsn({
      handle: 'subst-ai',
      account_type: 'prsn',
      account_id: accountId,
      kem_pubkey: b64uEncode(honest.publicX963),
      kem_pubkey_fingerprint: await fingerprint(honest.publicX963),
      kem_pq_pubkey: b64uEncode(honestMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(honestMlkem.ek),
    });
    const attacker = await generateKemKeypair();
    const registered = api.recipients.get('subst-ai');
    if (!registered) throw new Error('fixture missing');
    api.recipients.set('subst-ai', {
      ...registered,
      kem_pubkey: b64uEncode(attacker.publicX963),
      kem_pubkey_fingerprint: await fingerprint(attacker.publicX963),
    });
    await expect(drive.recipientKey('subst-ai')).rejects.toThrow(/substitution/);
  });

  it('F-DOWNGRADE(b): rejects a human key with no transparency-log receipt', async () => {
    // A coherent hybrid bundle whose keys were never logged: without a
    // server-signed receipt binding key -> account, the key is not a wrap
    // target (an unlogged key is exactly what a substituting server would
    // hand out to stay invisible to watchers).
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    api.recipients.set('ghost', {
      handle: 'ghost',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    await expect(drive.recipientKey('ghost')).rejects.toThrow(/no verifiable kem log receipt/);
  });

  it('F-DOWNGRADE(b): rejects a receipt that binds the key to a DIFFERENT account', async () => {
    // The key IS logged — but for someone else's account. Wrapping to it
    // would hand the content to whoever holds that identity.
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    await api.registerHuman({
      handle: 'carol',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    const registered = api.recipients.get('carol');
    if (!registered) throw new Error('fixture missing');
    api.recipients.set('carol', { ...registered, account_id: crypto.randomUUID() });
    await expect(drive.recipientKey('carol')).rejects.toThrow(/DIFFERENT account/);
  });

  it("rejects a directory row whose account_type contradicts the handle's -ai rule", async () => {
    // The classification comes from the handle (schema invariant); a server
    // claiming a PRSN handle is "human" is trying to route it around the
    // attestation-status check.
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    await api.registerHuman({
      handle: 'eve-ai',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    await expect(drive.recipientKey('eve-ai')).rejects.toThrow(/handle says otherwise/);
  });

  it('F-PIN1: refuses a bundle answering for a DIFFERENT handle than the user named', async () => {
    // The lying-directory walk: the user asks for `friend-ai`; the server
    // answers with a fully coherent, genuinely-receipted HUMAN bundle for
    // `mallory`. Pre-pin, classification followed the echo (human), the
    // receipts verified, and the wrap went to mallory's keys. The echo is
    // not the request.
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    await api.registerHuman({
      handle: 'mallory',
      account_type: 'human',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    const mallory = api.recipients.get('mallory');
    if (!mallory) throw new Error('fixture missing');
    api.recipients.set('friend-ai', mallory);
    await expect(drive.recipientKey('friend-ai')).rejects.toThrow(/substitution/);
  });

  it('F-PIN1 sibling: refuses a correctly-signed attestation with NO subject_handle', async () => {
    // The §9 schema guarantees subject_handle; a lying server that OMITS it
    // (signing the doctored object correctly with its real key) must be
    // refused — absence is not an older shape, and skip-if-absent would let
    // the omission bypass the handle binding.
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    await api.registerPrsn({
      handle: 'nameless-ai',
      account_type: 'prsn',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    const bundle = api.recipients.get('nameless-ai');
    if (!bundle?.attestation_id) throw new Error('fixture missing');
    const response = await api.getAttestationVerification(bundle.attestation_id);
    const doctored = { ...(response.attestation as JsonObject) };
    delete doctored.subject_handle;
    response.attestation = doctored;
    response.server_signature = await api.serverSign(
      verificationSigningInput(doctored, response.server_key_id, response.signed_at),
    );
    await expect(drive.recipientKey('nameless-ai')).rejects.toThrow(/no subject_handle/);
  });

  it('rejects a tampered attestation (the ES256 signature covers every field)', async () => {
    // Flip one signed field (the status) in the served response: the web
    // bound's ES256 verify over the JCS canonical bytes must catch it.
    const recipientKem = await generateKemKeypair();
    const recipientMlkem = await mlkemKeygen();
    await api.registerPrsn({
      handle: 'tamper-ai',
      account_type: 'prsn',
      account_id: crypto.randomUUID(),
      kem_pubkey: b64uEncode(recipientKem.publicX963),
      kem_pubkey_fingerprint: await fingerprint(recipientKem.publicX963),
      kem_pq_pubkey: b64uEncode(recipientMlkem.ek),
      kem_pq_pubkey_fingerprint: await fingerprintRaw(recipientMlkem.ek),
    });
    const bundle = api.recipients.get('tamper-ai');
    if (!bundle?.attestation_id) throw new Error('fixture missing');
    const response = await api.getAttestationVerification(bundle.attestation_id);
    (response.attestation as Record<string, unknown>).status = 'revoked';
    await expect(drive.recipientKey('tamper-ai')).rejects.toThrow(
      /server signature does not verify/,
    );
  });
});

// bug070 — the pre-upload capacity check.
//
// The server already refuses both grounds at `multipart::initiate`, before a byte
// reaches object storage. What was missing was refusing FIRST, and the guard that
// existed compared `File.size` (plaintext) against a ceiling the server applies to
// ciphertext — so a file within `34 x chunkCount` of the ceiling passed the client
// and was rejected by the server.
describe('bug070 pre-upload capacity', () => {
  // ── The PARITY VECTORS ───────────────────────────────────────────────────────
  // These seven cases are asserted VERBATIM-IDENTICALLY by the CLI
  // (`commands.rs::capacity_refusal_parity_vectors`). Same numbers, same verdicts.
  // Change one side and the other must change in the same commit, the way the
  // bug048 name rule is pinned across names.ts / names.rs.
  const PARITY: Array<{
    declared: number;
    ceiling: number | null;
    remaining: number | null;
    allowed: boolean;
    why: string;
  }> = [
    { declared: 100, ceiling: 100, remaining: 1000, allowed: true, why: 'exactly at the ceiling' },
    {
      declared: 101,
      ceiling: 100,
      remaining: 1000,
      allowed: false,
      why: 'one byte over the ceiling',
    },
    { declared: 100, ceiling: 1000, remaining: 100, allowed: true, why: 'exactly fills the pool' },
    { declared: 101, ceiling: 1000, remaining: 100, allowed: false, why: 'one byte over the pool' },
    {
      declared: 101,
      ceiling: 100,
      remaining: 100,
      allowed: false,
      why: 'ceiling is checked first',
    },
    {
      declared: 5000,
      ceiling: null,
      remaining: 1000,
      allowed: false,
      why: 'no ceiling known, pool still applies',
    },
    {
      declared: 5000,
      ceiling: 10000,
      remaining: null,
      allowed: true,
      why: 'quota read failed → fail OPEN',
    },
  ];

  it.each(PARITY)(
    'parity vector: declared=$declared ceiling=$ceiling remaining=$remaining → allowed=$allowed ($why)',
    ({ declared, ceiling, remaining, allowed }) => {
      const refusal = capacityRefusal(
        [{ name: 'f.bin', storedSize: declared }],
        ceiling,
        remaining,
      );
      expect(refusal === null).toBe(allowed);
    },
  );

  it('refuses a batch whose files each fit but whose SUM does not', () => {
    // The face-(b) case: today the web uploads a batch serially, so this would send
    // files one by one until one failed — quota honoured, nothing corrupted, and no
    // warning that the batch could never complete.
    const refusal = capacityRefusal(
      [
        { name: 'a.bin', storedSize: 60 },
        { name: 'b.bin', storedSize: 60 },
      ],
      1000,
      100,
    );
    expect(refusal).not.toBeNull();
    expect(refusal).toContain('these 2 files');
    // Each file alone would have been allowed — proving the sum is what refused it.
    expect(capacityRefusal([{ name: 'a.bin', storedSize: 60 }], 1000, 100)).toBeNull();
  });

  // bug070 follow-up (1): the verb used to live in the shared `detail` string, so the
  // subject changed between branches and the verb could not — "these 3 files needs".
  it('agrees subject and verb in BOTH the single and the plural branch', () => {
    const one = capacityRefusal([{ name: 'a.bin', storedSize: 200 }], 1000, 100);
    expect(one).toContain('this upload needs');
    expect(one).not.toContain('files need');

    const many = capacityRefusal(
      [
        { name: 'a.bin', storedSize: 60 },
        { name: 'b.bin', storedSize: 60 },
        { name: 'c.bin', storedSize: 60 },
      ],
      1000,
      100,
    );
    expect(many).toContain('these 3 files need ');
    // The exact defect, pinned so it cannot come back.
    expect(many).not.toContain('files needs');
  });

  // bug070 follow-up (2): `formatBytes` rounds, so a genuine near-miss refusal rendered
  // as "needs 2.0 GB but only 2.0 GB is available" — true, and reading as a
  // contradiction at the moment the user is told no. These two values are chosen so
  // they render IDENTICALLY; the shortfall is what has to carry the meaning.
  it('stays coherent when needed and remaining round to the same string', () => {
    const remaining = 2 * 1024 ** 3; // exactly 2 GiB  → "2.0 GB"
    const needed = remaining + 10 * 1024 ** 2; // +10 MiB      → also "2.0 GB"

    const refusal = capacityRefusal([{ name: 'big.bin', storedSize: needed }], null, remaining);

    expect(refusal).not.toBeNull();
    // The precondition that makes this test meaningful: the two figures are
    // indistinguishable once formatted. If formatBytes ever gains precision this
    // assertion fails loudly rather than the test quietly becoming vacuous.
    expect(formatBytes(needed)).toBe(formatBytes(remaining));
    // ...and the sentence is still coherent, because the shortfall is never zero here.
    expect(refusal).toContain('10 MB more than');
    expect(refusal).not.toMatch(/needs 2\.0 GB but only 2\.0 GB/);
  });

  it('uploadPlan reports STORED size, matching the CLI chunk_plan vectors exactly', () => {
    // Identical numbers to `chunk_plan_matches_the_web_overhead_model` in
    // cli/src/commands.rs: (plaintext, chunk) → (chunks, stored).
    // `uploadPlan` reads only the chunk size and the governor — never the api or
    // the session — so stubs are honest here rather than lazy.
    const planner = new Drive(undefined as never, undefined as never, 16);
    expect(planner.uploadPlan(0)).toMatchObject({ chunkCount: 1, storedSize: 34 });
    expect(planner.uploadPlan(16)).toMatchObject({ chunkCount: 1, storedSize: 16 + 34 });
    expect(planner.uploadPlan(17)).toMatchObject({ chunkCount: 2, storedSize: 17 + 2 * 34 });
    expect(planner.uploadPlan(100)).toMatchObject({ chunkCount: 7, storedSize: 100 + 7 * 34 });
  });

  it('a file at the ceiling in STORED terms is refused when its plaintext alone would pass', () => {
    // The (c) boundary, stated as the defect: plaintext 100 <= ceiling 100, but the
    // stored size is 134, so the server would reject what the old guard allowed.
    // `uploadPlan` reads only the chunk size and the governor — never the api or
    // the session — so stubs are honest here rather than lazy.
    const planner = new Drive(undefined as never, undefined as never, 16);
    const { storedSize } = planner.uploadPlan(100);
    expect(storedSize).toBeGreaterThan(100);
    expect(capacityRefusal([{ name: 'edge.bin', storedSize }], 100, 1_000_000)).not.toBeNull();
  });
});

describe('download retry budget (bug209, S181)', () => {
  // ⚠ KNOB RULE 4 with a DELIBERATE DIFFERENCE from downloadConcurrency below.
  // There is no safe "off" for a retry budget: 0 or 1 attempts would turn every
  // transient blip into a user-visible failure. So anything unusable lands on the
  // compiled DEFAULT (10), not on the minimum.
  //
  // ⚠⚠ AND NOT ON THE OLD 3 — this is emphatically NOT "behave as the client always
  // did" (Gus, S181 F1; that is what this comment used to say, and it described
  // behaviour the code does not implement). The client always did 3, and 3 is the
  // budget the measured ~42% Safari failure rate came from. **Falling back to the
  // old value would preserve the defect as the fallback.** The old behaviour is the
  // defect, not a refuge.
  //
  // ⭐ Knob rule 4 still holds and is EXERCISED, not declared: the off-position is
  // covered by the clamp cases here and by the wiring test's absent arm. What was
  // wrong was only the label on it.
  it('falls back to the compiled default rather than to the minimum', () => {
    expect(downloadRetryAttempts(undefined)).toBe(DEFAULT_DOWNLOAD_RETRY_ATTEMPTS); // pre-0060 server
    expect(downloadRetryAttempts(Number.NaN)).toBe(DEFAULT_DOWNLOAD_RETRY_ATTEMPTS);
    expect(downloadRetryAttempts(Number.POSITIVE_INFINITY)).toBe(DEFAULT_DOWNLOAD_RETRY_ATTEMPTS);
    // ⛔ The explicit anti-regression: absent must NOT resolve to the old budget.
    expect(downloadRetryAttempts(undefined)).not.toBe(3);
  });

  it('reads a served value', () => {
    expect(downloadRetryAttempts(10)).toBe(10);
    expect(downloadRetryAttempts(6)).toBe(6);
  });

  // ⚠ An unclamped served value keeps a doomed chunk retrying instead of failing
  // honestly — the same reasoning that clamps concurrency, pointed at time rather
  // than memory.
  it('clamps both ends', () => {
    expect(downloadRetryAttempts(0)).toBe(1);
    expect(downloadRetryAttempts(-5)).toBe(1);
    expect(downloadRetryAttempts(9999)).toBe(DOWNLOAD_RETRY_ATTEMPTS_MAX);
    expect(downloadRetryAttempts(7.9)).toBe(7); // floored, never rounded up
  });

  // ⭐ The number is a DIAL POSITION, not a discovered constant (Chris, S181).
  // What this pins is the property it was chosen for: it must exceed a browser's
  // per-host connection pool depth (~6 in Safari) so a fully stale pool cannot
  // exhaust it, and it must match the upload budget served since migration 0036.
  it('defaults above a browser connection-pool depth, matching the upload budget', () => {
    expect(DEFAULT_DOWNLOAD_RETRY_ATTEMPTS).toBe(10);
    expect(DEFAULT_DOWNLOAD_RETRY_ATTEMPTS).toBeGreaterThan(6);
  });
});

describe('download concurrency (bug178, S174)', () => {
  // ⭐ KNOB RULE 4 — the off-position is EXERCISED, not declared. Every way of
  // not getting a usable value must land on strictly-serial, which is exactly
  // the pre-S174 behaviour.
  it('falls back to serial rather than guessing', () => {
    expect(downloadConcurrency(undefined)).toBe(1); // an older server omits it
    expect(downloadConcurrency(1)).toBe(1); // the retraction position
    expect(downloadConcurrency(0)).toBe(1);
    expect(downloadConcurrency(-5)).toBe(1);
    expect(downloadConcurrency(Number.NaN)).toBe(1);
    expect(downloadConcurrency(Number.POSITIVE_INFINITY)).toBe(1);
  });

  // ⚠ The served value cannot raise the real ceiling. In-flight memory is
  // N x chunk on a surface already carrying bug179's measured 489 MiB peak.
  it("clamps to the compiled ceiling, which is lower than the CLI's", () => {
    expect(downloadConcurrency(4)).toBe(4);
    expect(downloadConcurrency(9999)).toBe(WEB_MAX_DOWNLOAD_CONCURRENCY);
    expect(WEB_MAX_DOWNLOAD_CONCURRENCY).toBeLessThan(8); // the CLI ceiling
  });

  it('floors fractional values instead of producing a fractional round size', () => {
    expect(downloadConcurrency(3.9)).toBe(3);
  });
});

describe('upload seal-ahead (bug178 phase 2, S174)', () => {
  // ⭐ KNOB RULE 4, upload half. The off-position is 0, not 1 — the knobs count
  // different things (chunks-at-once vs parts-sealed-ahead), so a shared default
  // would be wrong for one of them.
  it('falls back to serial seal-then-send rather than guessing', () => {
    expect(uploadPrepareAhead(undefined)).toBe(0); // an older server omits it
    expect(uploadPrepareAhead(0)).toBe(0); // the retraction position
    expect(uploadPrepareAhead(-2)).toBe(0);
    expect(uploadPrepareAhead(Number.NaN)).toBe(0);
    expect(uploadPrepareAhead(Number.POSITIVE_INFINITY)).toBe(0);
  });

  // ⚠ In-flight memory is (1 + prepareAhead) x chunk, on a surface already
  // carrying bug179's measured 489 MiB peak — so the compiled ceiling is the
  // real bound, and it is tighter than the CLI's 4.
  // ⚠ The clamp must not over-promise: this surface pipelines EXACTLY ONE part
  // ahead, so a ceiling above 1 would advertise a depth the loop never reaches.
  it('clamps to exactly one, which is what the loop actually pipelines', () => {
    expect(uploadPrepareAhead(1)).toBe(1); // the seeded value
    expect(uploadPrepareAhead(9999)).toBe(1);
    expect(WEB_MAX_UPLOAD_PREPARE_AHEAD).toBe(1);
  });

  it('floors fractional values rather than preparing a fraction of a part', () => {
    expect(uploadPrepareAhead(1.9)).toBe(1);
    expect(uploadPrepareAhead(0.9)).toBe(0);
  });
});
