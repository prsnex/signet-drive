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

import type {
  AttestationVerificationResponse,
  DriveApi,
  LogReceipt,
  ServerInfoResponse,
} from './api';
import { b64uDecode, type Bytes } from './crypto/bytes';
import { IntegrityError, InvalidInputError } from './crypto/errors';
import { hybridRfp } from './crypto/hybrid_wrap';
import { toCanonicalBytes, type JsonObject, type JsonValue } from './crypto/jcs';
import { fingerprint, fingerprintRaw } from './crypto/pubkey';

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
 *  the web verifies only the ES256 half (module docs). */
export class ServerTrust {
  private info: ServerInfoResponse | undefined;

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
    }
    return this.info;
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

  if (isPrsn) {
    await verifyAgainstAttestation(trust, api, bundle, recipient, accountId, handle, who);
  } else {
    await verifyAgainstReceipts(trust, api, bundle, accountId, who);
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
  // ES256-verified + shape-checked (ties the attested keys into the log).
  await verifyInlineReceipts(trust, response, attestation, who);
}

/** Human recipients: no attestation exists — the verified source is the §10a
 *  log receipt for EACH half of the hybrid KEM pair, bound to the recipient's
 *  account (D2 affirmation §1). Key-currency note: a receipt proves the key
 *  was LOGGED for the account, not that it is current — moot for humans in v1
 *  (the KEM identity is set-once); PRSN currency is the attestation path's
 *  status check, which is why classification comes from the handle. */
async function verifyAgainstReceipts(
  trust: ServerTrust,
  api: IdentityApi,
  bundle: RecipientKeyBundle,
  accountId: string,
  who: string,
): Promise<void> {
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
      receipt = await api.getLogReceipt(fp, purpose);
    } catch (e) {
      throw new IntegrityError(
        `${who}: no verifiable ${purpose} log receipt for the offered key — ` +
          `an unlogged key is not a wrap target (${e instanceof Error ? e.message : e})`,
      );
    }
    await verifyOneReceipt(trust, receipt, fp, accountId, purpose, who);
  }
}

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
  who: string,
): Promise<void> {
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
    // The attestation (server-signed) binds the keys to the subject account;
    // no separate account binding needed here.
    await verifyOneReceipt(trust, receipt, assertedFp, null, purpose, who);
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
  expectedAccountId: string | null,
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
  if (expectedAccountId !== null) {
    const receiptAccount = receipt['account_id'];
    if (
      typeof receiptAccount !== 'string' ||
      receiptAccount.toLowerCase() !== expectedAccountId.toLowerCase()
    ) {
      throw new IntegrityError(
        `${who}: ${purpose} receipt binds the key to a DIFFERENT account — a ` +
          `logged key that is not this recipient's is a substitution`,
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
