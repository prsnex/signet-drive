// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

// F-DOWNGRADE(b) — verified-source recipient keys, the WEB half (PQR D2;
// Spec §9.2/§8.5/§9.3; the CLI half is `cli/src/recipient_verify.rs`).
//
// A writer must wrap to the recipient's *attested / transparency-logged* keys,
// never to a bare directory response an attacker-controlled server could
// substitute. Every third-party recipient resolution routes through
// [`verifiedRecipient`], which:
//
// 1. runs the bundle-shape verification ([`verifyRecipientBundle`]: P-011
//    classical fingerprint + §8.5 raw-ek fingerprint + the half-strip AND
//    full-strip refusals — mandatory hybrid write, F-DOWNGRADE(a));
// 2. classifies the recipient FROM THE HANDLE (the schema invariant — 1-Pager
//    Resolved #1 — that PRSN handles end in `-ai` and human handles cannot),
//    so the classification comes from what the user named, not a
//    server-supplied field; the server's `account_type` is cross-checked as a
//    tamper signal;
// 3. verifies the keys against the recipient's identity record — a PRSN's §9
//    attestation-verification response, a human's §10a log receipts.
//
// THE WEB'S VERIFICATION BOUND (structural, Gus-affirmed — D2 affirmation §2):
// the web verifies the **ES256 half + the §8.5 `rfp` pair-commitment** of each
// identity record. There is no wasm ML-DSA in v1 (the affirmed §5.2 ruling),
// so the ML-DSA-87 half of the dual signature is verified on the CLI/server
// lineages, not here — but its *presence* is still enforced structurally
// (a §9 response or dual-era receipt with the PQ fields stripped is refused;
// on receipts the anti-strip binding makes a strip break the ES256 signature
// itself). In the D2 clock framing: downgrade (harvest-clock) is fully closed
// here by mandatory hybrid write, which needs no ML-DSA; substitution
// (forgery-clock, never PQR-specific) is forced through server-signed,
// append-only, watcher-visible records — the trust model's verifiability
// layer, with the CLI as the stronger dual-verifying surface by design.

import {
  SignetApiError,
  type AttestationVerificationResponse,
  type DriveApi,
  type LogReceipt,
  type ServerInfoResponse,
} from './api';
import { b64uDecode, hexDecode, hexEncode, type Bytes } from './crypto/bytes';
import { EpochChangedError, IntegrityError, InvalidInputError } from './crypto/errors';
import { hybridRfp } from './crypto/hybrid_wrap';
import { toCanonicalBytes, type JsonObject, type JsonValue } from './crypto/jcs';
import { fingerprint, fingerprintRaw } from './crypto/pubkey';
import { vrfVerify } from './crypto/vrf';

/** A verified wrap target: the P-011 classical key + the fingerprint-verified
 *  ML-KEM half (mandatory under F-DOWNGRADE(a) for every third-party
 *  recipient; optional only for the self-target, which is hybrid always). */
export interface VerifiedRecipient {
  pubkey: Bytes;
  pqPubkey?: Bytes;
}

/** The shape every recipient-key-bearing API response shares. */
export interface RecipientKeyBundle {
  handle?: string | null;
  account_type?: string | null;
  account_id?: string | null;
  recipient_account_id?: string | null;
  /** The epoch the server answered under; from epoch 2 the account's VRF proof
   *  beside its id, named in pairs (design §10.6). */
  epoch?: number | null;
  account_vrf_proof?: string | null;
  recipient_account_vrf_proof?: string | null;
  attestation_id?: string | null;
  kem_pubkey?: string | null;
  kem_pubkey_fingerprint?: string | null;
  kem_pq_pubkey?: string | null;
  kem_pq_pubkey_fingerprint?: string | null;
}

/** Verify a recipient's hybrid key bundle (shape layer). Classical: the P-011
 *  fingerprint check. PQ (§9.2/N6): a present pair must be a length-exact ek
 *  matching its `fingerprint_raw` fingerprint; a HALF-stripped pair refuses.
 *  F-DOWNGRADE(a): a FULLY-stripped bundle (no PQ pair at all) ALSO refuses —
 *  every v1 identity is hybrid, so "no ML-KEM key" is the harvest-now
 *  downgrade, not a legitimate classical recipient. (The web retains no
 *  classical-write gate at all: browsers are cross-OS already, so the future
 *  non-Mac custody rationale that keeps the CLI's hard-off `classical-write`
 *  feature does not exist here.) */
export async function verifyRecipientBundle(
  r: RecipientKeyBundle,
  who: string,
): Promise<VerifiedRecipient> {
  if (!r.kem_pubkey || !r.kem_pubkey_fingerprint) {
    throw new InvalidInputError(`${who} has no current encryption key`);
  }
  const pubkey = b64uDecode(r.kem_pubkey);
  if ((await fingerprint(pubkey)) !== r.kem_pubkey_fingerprint) {
    throw new IntegrityError(`${who} KEM-key fingerprint mismatch`);
  }
  const pqKey = r.kem_pq_pubkey ?? null;
  const pqFp = r.kem_pq_pubkey_fingerprint ?? null;
  if (pqKey === null && pqFp === null) {
    throw new IntegrityError(
      `${who} has no published ML-KEM key: refusing a classical-only wrap ` +
        `(mandatory hybrid write, PQR §9.2 — a PQ-less bundle is a stripped ` +
        `directory response)`,
    );
  }
  if (pqKey === null || pqFp === null) {
    throw new IntegrityError(`${who} hybrid KEM bundle is half-stripped`);
  }
  const pqPubkey = b64uDecode(pqKey);
  if (pqPubkey.length !== 1568) {
    throw new InvalidInputError(`${who} ML-KEM key must be 1568 bytes`);
  }
  if ((await fingerprintRaw(pqPubkey)) !== pqFp) {
    throw new IntegrityError(`${who} ML-KEM-key fingerprint mismatch`);
  }
  return { pubkey, pqPubkey };
}

type IdentityApi = Pick<DriveApi, 'getServerInfo' | 'getAttestationVerification' | 'getLogReceipt'>;

/** The server verification keys the writer checks identity records against —
 *  one `/v1/server-info` fetch per operation (shared across an upload's whole
 *  recipient loop). The active ML-DSA-87 key must be PUBLISHED (its absence is
 *  a downgrade signal — this deployment is post-7c by construction), though
 *  the web verifies only the ES256 half (module docs).
 *
 *  The same read anchors the operation's transparency-log epoch and, from
 *  epoch 2, the VRF key receipts are bound under (design §10.6). The key comes
 *  from `/v1/server-info` (Gus's ruling, on Bob's reason): the web's binding
 *  trusts the server for the VRF key, as it already does for inclusion, an
 *  accepted limit; sender protection against a split VRF key is the CLI's,
 *  which pins it from the public file. */
export class ServerTrust {
  private info: ServerInfoResponse | undefined;
  /** The FIRST read's epoch and VRF key: one operation binds under one epoch,
   *  so a key-rotation re-fetch (`keyById`) never moves them. */
  private anchored: { epoch: number; vrfPublicKey: string | undefined } | undefined;

  constructor(private readonly api: IdentityApi) {}

  private async fetch(): Promise<ServerInfoResponse> {
    if (!this.info) {
      this.info = await this.api.getServerInfo();
      if (!findByPurpose(this.info, 'attestation_verification_pq')) {
        throw new IntegrityError(
          'server publishes no active ML-DSA-87 verification key: refusing to ' +
            'treat its identity records as trustworthy (MF-2 downgrade signal)',
        );
      }
      this.anchored ??= {
        epoch: this.info.translog?.epoch ?? 1,
        vrfPublicKey: this.info.translog?.vrf_public_key ?? undefined,
      };
    }
    return this.info;
  }

  /** The served epoch this operation anchored (1 before the first cut). */
  async epoch(): Promise<number> {
    await this.fetch();
    return this.anchored!.epoch;
  }

  /** What a receipt for `accountId` must name from epoch 2: the epoch, and the
   *  index the account's VRF proof yields under the anchored VRF key. `null`
   *  in epoch 1, where the account id (or the attestation) binds. A missing
   *  key or proof, or a proof that does not verify, binds nothing. */
  async indexFor(
    accountId: string,
    proof: string | null | undefined,
    who: string,
  ): Promise<{ epoch: number; index: string } | null> {
    const epoch = await this.epoch();
    if (epoch < 2) return null;
    const key = this.anchored!.vrfPublicKey;
    if (!key) {
      throw new IntegrityError(
        `server-info names epoch ${epoch} but no VRF key: cannot bind ${who}'s keys to the log`,
      );
    }
    if (!proof) {
      throw new IntegrityError(
        `${who}: no VRF proof for the account in epoch ${epoch} — cannot bind its keys to the log`,
      );
    }
    let index: Bytes;
    try {
      index = await vrfVerify(
        strictHex(key, 32, 'VRF key'),
        uuidBytes(accountId, who),
        strictHex(proof, 80, 'VRF proof'),
      );
    } catch (e) {
      throw new IntegrityError(
        `${who}: the account's VRF proof does not verify under the epoch's key — ` +
          `substitution (${e instanceof Error ? e.message : e})`,
      );
    }
    return { epoch, index: hexEncode(index) };
  }

  /** An ES256 signing key by id (current or retired — a response or receipt
   *  may be signed by a since-rotated key). Re-fetches once on a miss. */
  async keyById(keyId: string): Promise<Bytes> {
    const cached = findById(await this.fetch(), keyId);
    if (cached) return b64uDecode(cached.public_key);
    this.info = undefined;
    const fresh = findById(await this.fetch(), keyId);
    if (fresh) return b64uDecode(fresh.public_key);
    throw new IntegrityError(`server-info has no signing key with id ${keyId}`);
  }
}

/** Run an operation's epoch-bound reads, and once more from a fresh
 *  `/v1/server-info` when the server's epoch moved under the first attempt
 *  (design §10.4; the CLI's `once_more_on_epoch_change`). Each attempt makes
 *  its own `ServerTrust` and only reads: the caller wraps and writes after this
 *  returns. On the retry nothing is caught: a refusal met again stays an
 *  EpochChangedError ("The service was updating. Please try again."), and a
 *  part naming another epoch again is an IntegrityError, since it then
 *  contradicts a fresh read. */
export async function onceMoreOnEpochChange<T>(attempt: () => Promise<T>): Promise<T> {
  try {
    return await attempt();
  } catch (e) {
    if (!(e instanceof EpochChangedError)) throw e;
  }
  try {
    return await attempt();
  } catch (e) {
    if (e instanceof EpochChangedError && !e.refusal) throw new IntegrityError(e.message);
    throw e;
  }
}

/** A 410 `epoch_retired` or 404 `epoch_unknown` in the server's error envelope:
 *  the epoch this operation anchored is not the served one any more. */
function isEpochRefusal(e: unknown): e is SignetApiError {
  return (
    e instanceof SignetApiError &&
    ((e.status === 410 && e.code === 'epoch_retired') ||
      (e.status === 404 && e.code === 'epoch_unknown'))
  );
}

/** A receipt answers for one epoch: its `epoch`, or 1 when it names none (the
 *  shape before epoch 2). Another means the epoch moved under the operation. */
function checkReceiptEpoch(receipt: LogReceipt, epoch: number, who: string, purpose: string) {
  const named = receipt['epoch'] ?? 1;
  if (named !== epoch) {
    throw new EpochChangedError(
      `${who}: the ${purpose} receipt answers for epoch ${String(named)}, but the anchored ` +
        `epoch is ${epoch}`,
      false,
    );
  }
}

/** Lowercase hex of exactly `len` bytes, or an IntegrityError. */
function strictHex(hex: string, len: number, what: string): Bytes {
  if (!new RegExp(`^[0-9a-fA-F]{${len * 2}}$`).test(hex)) {
    throw new IntegrityError(`${what} is not ${len} bytes of hex`);
  }
  return hexDecode(hex.toLowerCase());
}

/** A UUID's 16 raw bytes (the VRF input's account id). */
function uuidBytes(uuid: string, who: string): Bytes {
  const hex = uuid.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new IntegrityError(`${who}: the account id is not a UUID`);
  }
  return hexDecode(hex.toLowerCase());
}

function findById(info: ServerInfoResponse, keyId: string) {
  return [...(info.current_signing_keys ?? []), ...(info.retired_signing_keys ?? [])].find(
    (k) => k.key_id === keyId,
  );
}

function findByPurpose(info: ServerInfoResponse, purpose: string) {
  return (info.current_signing_keys ?? []).find((k) => k.purpose === purpose);
}

/** The caller's trust regime for the bundle's `handle` field (F-PIN1): every
 *  call site declares which regime it is in, so a user-typed name is always
 *  pinned and a server-listed row is *visibly* unpinned.
 *
 *  - `{ userNamed }`: the caller holds the handle the USER typed. The bundle's
 *    echoed handle MUST match — otherwise a lying directory can answer a
 *    request for `x-ai` with a coherent bundle for a different (attacker)
 *    identity and route classification around the `-ai` invariant.
 *  - `'server-listed'`: the bundle came from server state with no user-typed
 *    name to pin against (a share-recipients row). The identity record still
 *    binds keys→account; set membership was established at invite time
 *    through the pinned path. */
export type HandleExpectation = { userNamed: string } | 'server-listed';

/** Resolve + fully verify a third-party recipient from any recipient-key-
 *  bearing response object — the single entry point for every third-party
 *  wrap on the web (see the module docs). */
export async function verifiedRecipient(
  trust: ServerTrust,
  api: IdentityApi,
  bundle: RecipientKeyBundle,
  expectation: HandleExpectation,
  who: string,
): Promise<VerifiedRecipient> {
  // Identity first, keys second (mirroring the CLI exactly): a bundle
  // answering for the wrong handle is refused before any of its key material
  // is evaluated.
  const handle = bundle.handle;
  if (!handle) {
    throw new IntegrityError(
      `${who}: recipient bundle carries no handle — cannot classify for ` +
        `verified-source key resolution`,
    );
  }
  // F-PIN1: the echo is not the request. Classification below runs on the
  // BUNDLE's handle; when the caller holds a user-typed name, the two must
  // be the same string before that handle is trusted for anything.
  if (expectation !== 'server-listed' && handle !== expectation.userNamed) {
    throw new IntegrityError(
      `${who}: asked the directory for '${expectation.userNamed}' but the ` +
        `bundle answers for '${handle}' — refusing (substitution)`,
    );
  }

  const recipient = await verifyRecipientBundle(bundle, who);

  const isPrsn = handle.endsWith('-ai');
  const claimed = bundle.account_type;
  if (claimed && (claimed === 'prsn') !== isPrsn) {
    throw new IntegrityError(
      `${who}: the server calls '${handle}' a ${claimed}, but the handle says ` +
        `otherwise (PRSN handles end in -ai) — refusing`,
    );
  }
  const accountId = bundle.account_id ?? bundle.recipient_account_id;
  if (!accountId) {
    throw new IntegrityError(
      `${who}: recipient bundle carries no account id — cannot bind the keys ` +
        `to an identity record`,
    );
  }
  // The account id and, from epoch 2, its VRF proof, named in pairs (§10.6).
  const proof = bundle.account_id ? bundle.account_vrf_proof : bundle.recipient_account_vrf_proof;

  // The bundle answers for the anchored epoch, or the epoch moved under the
  // operation: it is read before the trust (design §10.4). An absent `epoch`
  // is epoch 1, since the server omits the field while epoch 1 is served
  // (Bob, at unit 3), so a bundle read before a serve shows as the move it is.
  const epoch = await trust.epoch();
  const named = bundle.epoch ?? 1;
  if (named !== epoch) {
    throw new EpochChangedError(
      `${who}: the recipient bundle names epoch ${bundle.epoch ?? '1 (absent)'}, but the ` +
        `anchored epoch is ${epoch}`,
      false,
    );
  }

  if (isPrsn) {
    await verifyAgainstAttestation(trust, api, bundle, recipient, accountId, handle, who);
  } else {
    await verifyAgainstReceipts(trust, api, bundle, accountId, proof, who);
  }
  return recipient;
}

/** PRSN recipients: the §9 attestation-verification response — ES256-verified
 *  over the JCS canonical bytes, PQ-shape-checked, status-checked,
 *  rfp-recomputed, subject-bound — byte-compared against the bundle. */
async function verifyAgainstAttestation(
  trust: ServerTrust,
  api: IdentityApi,
  bundle: RecipientKeyBundle,
  recipient: VerifiedRecipient,
  accountId: string,
  handle: string,
  who: string,
): Promise<void> {
  const attestationId = bundle.attestation_id;
  if (!attestationId) {
    throw new IntegrityError(
      `${who}: '${handle}' is a PRSN but its bundle names no attestation — ` +
        `cannot verified-source the wrap keys`,
    );
  }
  const response = await api.getAttestationVerification(attestationId);
  const attestation = await verifyVerificationResponse(trust, response, who);

  const status = str(attestation, 'status');
  if (status !== 'active') {
    throw new IntegrityError(`${who}: '${handle}' attestation is ${status ?? 'malformed'}`);
  }
  if (str(attestation, 'subject_account_id')?.toLowerCase() !== accountId.toLowerCase()) {
    throw new IntegrityError(
      `${who}: attestation subject is a DIFFERENT account than the directory row — substitution`,
    );
  }
  // The §9 object always carries subject_handle (the server builds it
  // unconditionally) — absence is a malformed or doctored record. Required,
  // and it must name THIS handle.
  const subjectHandle = str(attestation, 'subject_handle');
  if (!subjectHandle) {
    throw new IntegrityError(
      `${who}: attestation carries no subject_handle — refusing (the §9 schema ` +
        `guarantees the field)`,
    );
  }
  if (subjectHandle !== handle) {
    throw new IntegrityError(
      `${who}: attestation subject handle '${subjectHandle}' does not match '${handle}'`,
    );
  }

  const attKem = b64uDecode(required(attestation, 'subject_kem_pubkey', who));
  const attKemPqB64 = str(attestation, 'subject_kem_pq_pubkey');
  if (!attKemPqB64) {
    throw new IntegrityError(
      `${who}: '${handle}' attestation carries no ML-KEM key: refusing a ` +
        `classical-only wrap (mandatory hybrid write, PQR §9.2)`,
    );
  }
  const attKemPq = b64uDecode(attKemPqB64);

  // §8.5: recompute the rfp pair-commitment over the attested pair.
  const rfp = await hybridRfp(attKem, attKemPq);
  if (str(attestation, 'rfp') !== rfp) {
    throw new IntegrityError(
      `${who}: recomputed rfp does not match the attestation's pair-commitment`,
    );
  }

  // The keys we are about to wrap to must BE the attested ones.
  if (!bytesEqual(recipient.pubkey, attKem) || !bytesEqual(recipient.pqPubkey, attKemPq)) {
    throw new IntegrityError(
      `${who}: directory bundle keys differ from the attested keys — substitution`,
    );
  }

  // The inline §10a receipts: present for all four attested keys, each
  // ES256-verified + shape-checked (ties the attested keys into the log). From
  // epoch 2 each must sit under the subject's index; the proof is read from
  // INSIDE the signed object (§10.6).
  const index = await trust.indexFor(accountId, str(attestation, 'subject_account_vrf_proof'), who);
  await verifyInlineReceipts(trust, response, attestation, index, who);
}

/** Human recipients: no attestation exists — the verified source is the §10a
 *  log receipt for EACH half of the hybrid KEM pair, bound to the recipient's
 *  account (D2 affirmation §1): by `account_id` in epoch 1, by the account's
 *  VRF index from epoch 2 (§10.6). Key-currency note: a receipt proves the key
 *  was LOGGED for the account, not that it is current — moot for humans in v1
 *  (the KEM identity is set-once); PRSN currency is the attestation path's
 *  status check, which is why classification comes from the handle. */
async function verifyAgainstReceipts(
  trust: ServerTrust,
  api: IdentityApi,
  bundle: RecipientKeyBundle,
  accountId: string,
  proof: string | null | undefined,
  who: string,
): Promise<void> {
  const epoch = await trust.epoch();
  const binding: ReceiptBinding = (await trust.indexFor(accountId, proof, who)) ?? { accountId };
  const pairs: [string | null | undefined, string][] = [
    [bundle.kem_pubkey_fingerprint, 'kem'],
    [bundle.kem_pq_pubkey_fingerprint, 'kem_pq'],
  ];
  for (const [fp, purpose] of pairs) {
    if (!fp) {
      throw new InvalidInputError(`${who} bundle missing ${purpose} fingerprint`);
    }
    let receipt: LogReceipt;
    try {
      // At the anchored epoch: a server that has since served another refuses
      // it, and the operation re-reads (design §10.4).
      receipt = await api.getLogReceipt(fp, purpose, epoch);
    } catch (e) {
      if (isEpochRefusal(e)) {
        throw new EpochChangedError(
          `the server's epoch changed during this operation (${e.code}: ${e.message})`,
          true,
        );
      }
      throw new IntegrityError(
        `${who}: no verifiable ${purpose} log receipt for the offered key — ` +
          `an unlogged key is not a wrap target (${e instanceof Error ? e.message : e})`,
      );
    }
    // A receipt naming another epoch than the one asked for is the server
    // contradicting its own parameter, not a race: the binding refuses it.
    await verifyOneReceipt(trust, receipt, fp, binding, purpose, who);
  }
}

/** What a receipt must name to bind a key to its account: the account id in
 *  epoch 1, the epoch and index from epoch 2; `null` where a server-signed
 *  attestation already carries the epoch-1 binding. */
type ReceiptBinding = { accountId: string } | { epoch: number; index: string } | null;

/** Verify a §9 attestation-verification response at the web bound: ES256 over
 *  the canonical bytes + the PQ siblings' structural presence (MF-2 shape —
 *  the ML-DSA bytes verify on the CLI/server lineages). Returns the signed
 *  `attestation` object. */
async function verifyVerificationResponse(
  trust: ServerTrust,
  response: AttestationVerificationResponse,
  who: string,
): Promise<JsonObject> {
  const attestation = response.attestation as JsonObject | undefined;
  const serverKeyId = response.server_key_id;
  const signedAt = response.signed_at;
  if (!attestation || typeof serverKeyId !== 'string' || typeof signedAt !== 'number') {
    throw new InvalidInputError(`${who}: malformed verification response`);
  }
  const signingInput = verificationSigningInput(attestation, serverKeyId, signedAt);
  const serverPub = await trust.keyById(serverKeyId);
  if (!(await verifyEs256(serverPub, signingInput, b64uDecode(response.server_signature)))) {
    throw new IntegrityError(`${who}: server signature does not verify`);
  }
  // MF-2, the web's structural half: the dual-signature siblings must be
  // PRESENT — an ES256-only response from this post-7c server is a downgrade.
  if (!response.server_pq_key_id || !response.server_signature_mldsa87) {
    throw new IntegrityError(
      `${who}: ES256-only verification response rejected — the server has a ` +
        `published ML-DSA-87 key, so the §9 response MUST be dual-signed (MF-2/N9)`,
    );
  }
  return attestation;
}

/** The four inline §10a receipts of a hybrid §9 response — all REQUIRED on
 *  the write path, each verified at the web bound. */
async function verifyInlineReceipts(
  trust: ServerTrust,
  response: AttestationVerificationResponse,
  attestation: JsonObject,
  index: { epoch: number; index: string } | null,
  who: string,
): Promise<void> {
  // The §9 response is read before the trust and takes no epoch, so each
  // receipt must answer for the anchored one, or the epoch moved (§10.4).
  const epoch = await trust.epoch();
  const receipts: [string, string, string][] = [
    ['subject_signing_pubkey_receipt', 'subject_signing_pubkey_fingerprint', 'signing'],
    ['subject_kem_pubkey_receipt', 'subject_kem_pubkey_fingerprint', 'kem'],
    ['subject_signing_pq_pubkey_receipt', 'subject_signing_pq_pubkey_fingerprint', 'signing_pq'],
    ['subject_kem_pq_pubkey_receipt', 'subject_kem_pq_pubkey_fingerprint', 'kem_pq'],
  ];
  for (const [receiptField, fpField, purpose] of receipts) {
    const receipt = response[receiptField] as LogReceipt | undefined;
    const assertedFp = attestation[fpField];
    if (!receipt || typeof assertedFp !== 'string') {
      throw new IntegrityError(
        `${who}: attestation response is missing its ${purpose} transparency ` +
          `receipt — the write path requires the full receipt set`,
      );
    }
    checkReceiptEpoch(receipt, epoch, who, purpose);
    // In epoch 1 the attestation (server-signed) binds the keys to the subject
    // account; from epoch 2 each receipt must also sit under its index.
    await verifyOneReceipt(trust, receipt, assertedFp, index, purpose, who);
  }
}

/** Verify one §10a receipt at the web bound: fingerprint + purpose (+ account
 *  when the receipt is the sole identity binding), the ES256 signature over
 *  the JCS canonical bytes, and the MF-2 anti-strip shape (a receipt naming a
 *  server PQ key must carry the ML-DSA co-signature — its id sits INSIDE the
 *  ES256-signed bytes, so a strip breaks the classical verify too). */
async function verifyOneReceipt(
  trust: ServerTrust,
  receipt: LogReceipt,
  assertedFp: string,
  binding: ReceiptBinding,
  purpose: string,
  who: string,
): Promise<void> {
  if (receipt['public_key_fingerprint'] !== assertedFp) {
    throw new IntegrityError(
      `${who}: ${purpose} receipt fingerprint does not match the asserted public key`,
    );
  }
  if (receipt['key_purpose'] !== purpose) {
    throw new IntegrityError(`${who}: ${purpose} receipt has an unexpected key_purpose`);
  }
  if (binding !== null && 'accountId' in binding) {
    const receiptAccount = receipt['account_id'];
    if (
      typeof receiptAccount !== 'string' ||
      receiptAccount.toLowerCase() !== binding.accountId.toLowerCase()
    ) {
      throw new IntegrityError(
        `${who}: ${purpose} receipt binds the key to a DIFFERENT account — a ` +
          `logged key that is not this recipient's is a substitution`,
      );
    }
  } else if (binding !== null) {
    const receiptIndex = receipt['account_index'];
    if (
      receipt['epoch'] !== binding.epoch ||
      typeof receiptIndex !== 'string' ||
      receiptIndex.toLowerCase() !== binding.index
    ) {
      throw new IntegrityError(
        `${who}: ${purpose} receipt is not under the account's index in epoch ` +
          `${binding.epoch} — a logged key that is not this recipient's is a substitution`,
      );
    }
  }
  const sigB64 = receipt['server_signature'];
  const keyId = receipt['server_key_id'];
  if (typeof sigB64 !== 'string' || typeof keyId !== 'string') {
    throw new IntegrityError(`${who}: ${purpose} receipt is missing its server signature`);
  }
  // The signing input = the receipt with EVERY server_signature* field
  // removed (§8.7 — both halves sign the identical bytes).
  const unsigned: JsonObject = {};
  for (const [k, v] of Object.entries(receipt)) {
    if (k === 'server_signature' || k === 'server_signature_mldsa87') continue;
    unsigned[k] = v as JsonValue;
  }
  const signingInput = receiptSigningInput(unsigned);
  const serverPub = await trust.keyById(keyId);
  if (!(await verifyEs256(serverPub, signingInput, b64uDecode(sigB64)))) {
    throw new IntegrityError(`${who}: ${purpose} receipt signature does not verify`);
  }
  // MF-2 receipt shape: a receipt whose SIGNED object names a PQ key must
  // carry the co-signature (verified cryptographically on the CLI lineage).
  if (unsigned['server_pq_key_id'] !== undefined && !receipt['server_signature_mldsa87']) {
    throw new IntegrityError(
      `${who}: ${purpose} receipt names a server PQ key but carries no ` +
        `ML-DSA-87 co-signature (MF-2)`,
    );
  }
}

// --- signing-base framings (ports of crypto/src/attest.rs / translog.rs) ------

const VERIFY_PREFIX = 'signet-server-attestation-verify-v1\n';
const RECEIPT_PREFIX = 'signet-pubkey-log-receipt-v1\n';

/** Envelope §9: `prefix ‖ JCS(attestation) ‖ \n ‖ server_key_id ‖ \n ‖
 *  str(signed_at)` — the exact bytes both signature halves sign
 *  (`crypto/src/attest.rs::verification_signing_input`). */
export function verificationSigningInput(
  attestation: JsonObject,
  serverKeyId: string,
  signedAt: number,
): Uint8Array {
  const canonical = toCanonicalBytes(attestation);
  const tail = new TextEncoder().encode(`\n${serverKeyId}\n${signedAt}`);
  const out = new Uint8Array(VERIFY_PREFIX.length + canonical.length + tail.length);
  out.set(new TextEncoder().encode(VERIFY_PREFIX), 0);
  out.set(canonical, VERIFY_PREFIX.length);
  out.set(tail, VERIFY_PREFIX.length + canonical.length);
  return out;
}

/** Envelope §10a: `prefix ‖ JCS(receipt-without-signatures)` — the exact bytes
 *  both halves sign (`crypto/src/translog.rs::receipt_signing_input`). */
export function receiptSigningInput(receiptWithoutSignatures: JsonObject): Uint8Array {
  const canonical = toCanonicalBytes(receiptWithoutSignatures);
  const out = new Uint8Array(RECEIPT_PREFIX.length + canonical.length);
  out.set(new TextEncoder().encode(RECEIPT_PREFIX), 0);
  out.set(canonical, RECEIPT_PREFIX.length);
  return out;
}

/** ES256 (raw r‖s, 64 B) over `message` with an X9.63 uncompressed P-256 key —
 *  WebCrypto's native ECDSA formats for both. */
async function verifyEs256(
  pubX963: Bytes,
  message: Uint8Array,
  signature: Bytes,
): Promise<boolean> {
  if (pubX963.length !== 65 || signature.length !== 64) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    pubX963 as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature as BufferSource,
    message as BufferSource,
  );
}

function str(obj: JsonObject, field: string): string | undefined {
  const v = obj[field];
  return typeof v === 'string' ? v : undefined;
}

function required(obj: JsonObject, field: string, who: string): string {
  const v = str(obj, field);
  if (!v) throw new InvalidInputError(`${who}: attestation missing ${field}`);
  return v;
}

function bytesEqual(a: Uint8Array | undefined, b: Uint8Array): boolean {
  if (!a || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
