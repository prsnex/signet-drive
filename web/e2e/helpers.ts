// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { type Page, expect } from '@playwright/test';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

/** Run SQL against the e2e database — the docker-exec psql affordance every spec
 *  that needs a state only elapsed time (or an absent binary) would produce uses.
 *  ONE home; the per-spec copies migrate here as they're touched. */
export function psql(sql: string): string {
  return execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', 'signet_drive_e2e', '-tAc', sql],
    { encoding: 'utf8' },
  ).trim();
}

/** bug117/S158: the server-side grant backstop (v0.5.26, #360) refuses a PRSN with
 *  no LIVE confirmed Garnet grant on every non-exempt route — so any spec whose PRSN
 *  makes signed Drive requests must first hold one. This is the e2e mirror of the
 *  Rust `grant_live` fixture: #360 migrated 22 server tests per-occurrence, and these
 *  specs are the e2e half of that migration, unrun until S158 because #361's green
 *  e2e predated the #360 merge (the first post-merge e2e is what surfaced it). */
export function grantLive(guardianHandle: string, prsnHandle: string): void {
  const id = psql(
    `INSERT INTO garnet_standing_grants ` +
      `(grant_id, prsn_handle, guardian_account_id, status, enrollment_confirmed, ` +
      `enrolled_cert_serial, created_at, last_confirmed_at, prsn_account_id) ` +
      `SELECT gen_random_uuid(), '${prsnHandle}', gh.account_id, 'active', TRUE, ` +
      `'e2e-gate-fixture', now(), now(), ph.account_id ` +
      `FROM handles gh, handles ph ` +
      `WHERE gh.handle = '${guardianHandle}' AND ph.handle = '${prsnHandle}' ` +
      `RETURNING grant_id`,
  );
  if (!id) {
    throw new Error(
      `grantLive: no grant inserted — guardian '${guardianHandle}' or PRSN '${prsnHandle}' not found in handles`,
    );
  }
}

/** bug154 §2c (S166): the + PRSN entry is GATED on a broker existing — a guardian
 *  with no broker gets the route-to-setup modal, never the wizard. Any spec that
 *  walks the wizard must therefore hold a broker row first (the e2e stack runs no
 *  real broker binary; the row is the whole fixture, exactly like grantLive).
 *  ⚠ The guardian handle is REQUIRED and explicit: spec FILES run on parallel
 *  workers (fullyParallel:false only serializes within a file), so any
 *  "current guardian = newest human" inference is a race. */
export function seedBroker(guardianHandle: string): void {
  const id = psql(
    `INSERT INTO garnet_brokers (broker_id, guardian_account_id, k3_cert_der) ` +
      `SELECT gen_random_uuid(), a.account_id, decode('00','hex') ` +
      `FROM accounts a JOIN handles h ON h.account_id = a.account_id ` +
      `WHERE h.handle = '${guardianHandle}' RETURNING broker_id`,
  );
  if (!id) throw new Error(`seedBroker: guardian '${guardianHandle}' not found in handles`);
}

// Email delivery is stubbed server-side, so the verification token is read
// straight from the E2E database — the same affordance local dev uses.
export function verificationToken(email: string): string {
  return psql(
    `SELECT token FROM pending_email_verifications WHERE email = '${email}' ORDER BY created_at DESC LIMIT 1`,
  );
}

// Flip admin_role on an account directly in the E2E DB — there is no self-serve
// path to become an admin (the same psql affordance verificationToken uses).
export function makeAdmin(email: string): void {
  const sql = `UPDATE accounts SET admin_role = TRUE WHERE email = '${email}'`;
  execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', 'signet_drive_e2e', '-tAc', sql],
    { encoding: 'utf8' },
  );
}

// Activate a fresh signup the way completing the card-up-front checkout would:
// a future paid-through date clears the subscribe-to-activate read-only gate
// (auth.rs: read_only = Human && paid_until <= now()), and a real quota lets
// uploads fit. Without this, a new account is read-only and its first write —
// attestation, folder create, upload — is blocked. The same direct-DB affordance
// makeAdmin / verificationToken use (no self-serve activation in the E2E stack,
// which stubs Stripe). Call right after signUp, before the first write.
export function activate(email: string): void {
  const sql = `UPDATE accounts SET paid_until = now() + interval '400 days', bytes_quota = 10737418240, activated_at = now() WHERE email = '${email}'`;
  execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', 'signet_drive_e2e', '-tAc', sql],
    { encoding: 'utf8' },
  );
}

// A CTAP2 platform authenticator with the PRF extension, auto-satisfying user
// presence + verification. The S025 spike proved this emits a deterministic
// 32-byte PRF, so signup's wrap and sign-in's unwrap derive the same key.
export async function addPrfAuthenticator(page: Page): Promise<void> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
      hasPrf: true,
    },
  });
}

/** Run the real signup → verify flow with a fresh account, landing in the file
 *  browser (its sidebar visible). Returns the account's handle + email. */
export async function signUp(page: Page): Promise<{ handle: string; email: string }> {
  const runId = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const handle = `e2e-${runId}`;
  const email = `e2e-${runId}@example.com`;

  await addPrfAuthenticator(page);

  await page.goto('/signup');
  await page.getByLabel('Username').fill(handle);
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();

  const token = verificationToken(email);
  expect(token).toMatch(/^[0-9a-f]{32}$/);
  await page.goto(`/verify?token=${token}`);
  // bug062: the passkey ceremony is user-triggered now — the page explains the OS
  // credential dialog first, and the user's own click fires it.
  await page.getByRole('button', { name: 'Create my passkey' }).click();

  // Signed in → the file browser's sidebar renders once /v1/me + listing load.
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // Activate the fresh account — a subscribe-to-activate signup is read-only until
  // card-up-front checkout, so every drive write (attest, folder create, upload)
  // would be blocked server-side. activate() is the E2E stand-in for completing
  // checkout (Stripe is stubbed here). The server enforces writability live per
  // request, so this takes effect immediately for the writes each spec does next;
  // read_only is only a cosmetic banner client-side (no write is gated on it), and
  // it clears on the next /v1/me fetch. The account row exists only post-verify
  // (signup.rs verify_email INSERTs it), so this is the earliest valid point.
  activate(email);
  return { handle, email };
}

/** Add a PRSN to the signed-in, activated Guardian's account via the S052 enrollment
 *  flow (no hand-transcription, Punch-List 1-23): "+ Add PRSN" → the confirm-and-
 *  approve page → name + confirm → simulate the agent's join + submit-keys → one
 *  passkey gesture attests exactly those keys. Assumes the page is on /account (the
 *  GuardianPrsns button lives there); leaves it back on /account with the PRSN
 *  attested. `prsn` supplies the pubkeys/fingerprints + the `-ai` handle (works for
 *  `prsnIdentity`, whose keys the ceremony itself mints). */
export async function attestPrsnViaEnrollment(
  page: Page,
  prsn: PrsnCliKeys,
  guardianHandle: string,
  opts?: { stayInWizard?: boolean },
): Promise<void> {
  // bug154 §2c: the wizard is entered through the broker gate, and the gate reads
  // the GarnetStore's MOUNT-TIME broker fetch — so the spec must have called
  // seedBroker(handle) BEFORE navigating to /account (right after signUp). Seeding
  // here would be too late: the store's list is already loaded, and the gate would
  // open the route-to-setup modal instead of the wizard (up to one 10s poll).
  // Verified fail-fast so a forgetful spec gets this sentence, not a timeout.
  const brokers = psql(
    `SELECT count(*) FROM garnet_brokers b JOIN handles h ON h.account_id = b.guardian_account_id ` +
      `WHERE h.handle = '${guardianHandle}'`,
  );
  if (brokers === '0') {
    throw new Error(
      `attestPrsnViaEnrollment: guardian '${guardianHandle}' has no broker — call ` +
        `seedBroker(handle) right after signUp, BEFORE navigating to /account (bug154 §2c).`,
    );
  }
  await page.getByRole('button', { name: '+ Add PRSN' }).click();
  await expect(page.getByRole('heading', { name: 'Add a PRSN' })).toBeVisible({
    timeout: 15_000,
  });

  // §1-62: the wizard names FIRST and mints on Continue (mint-at-step, design note
  // §5) — the enrollment code exists only after this submit, in the confirm URL.
  await page.getByLabel('PRSN name').fill(prsn.handle);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });
  const code = new URL(page.url()).searchParams.get('code');
  expect(code).toBeTruthy();

  // bug154 §2b (S166): the hand-off step's install-helper block (with its download
  // link) is DELETED — replaced by the one menu-bar sentence. The installer stays
  // reachable on the broker-setup step (asserted in wizard-drive-access) and the
  // guardian can no longer reach this step broker-less at all (the §2c gate).
  await expect(page.getByText(/Check for ◉ in your menu bar/)).toBeVisible();

  // The agent runs the PRODUCTION enrollment — `signet enroll <code>` (the 7a
  // four-key ceremony: join -> await confirm -> keygen x4 -> submit + PoP ->
  // await the attestation). It blocks until the Guardian approves below, so it
  // runs as a child process alongside the browser half of the ceremony.
  const env = {
    ...signetEnv(prsn.keysDir),
    SIGNET_HANDLE: prsn.handle,
    SIGNET_ENROLL_POLL_MS: '250',
    // The debug-build test affordance (enroll.rs): a software-tier harness
    // keystore claims `secure_enclave` so the production four-key + PoP
    // ceremony runs against the SE-only server. Absent from release builds.
    SIGNET_TEST_CLAIM_KEY_PROTECTION: 'secure_enclave',
  };
  const agent = spawn(SIGNET_BIN, ['enroll', code as string], { env });
  let agentOut = '';
  agent.stdout.on('data', (d: Buffer) => (agentOut += d.toString()));
  agent.stderr.on('data', (d: Buffer) => (agentOut += d.toString()));
  const agentDone = new Promise<void>((resolvePromise, reject) => {
    agent.on('close', (exitCode: number | null) =>
      exitCode === 0
        ? resolvePromise()
        : reject(new Error(`signet enroll exited ${exitCode}: ${agentOut}`)),
    );
  });

  // Naming already happened at step 1; the agent's keys arrive and the
  // hard-confirm approval unlocks.
  await page.getByRole('button', { name: 'Approve with passkey' }).click({ timeout: 30_000 });
  await expect(page.getByText(/is set up/)).toBeVisible({ timeout: 15_000 });
  await agentDone;

  // The ceremony minted the four keys in the agent's keystore — surface the
  // classical fingerprints/pubkeys the callers use (signed requests, wizards).
  const env2 = signetEnv(prsn.keysDir);
  prsn.signingFingerprint = execFileSync(
    SIGNET_BIN,
    ['fingerprint', '--signing', '--key', prsn.signingLabel],
    { encoding: 'utf8', env: env2 },
  ).trim();
  prsn.kemFingerprint = execFileSync(SIGNET_BIN, ['fingerprint', '--kem', '--key', prsn.kemLabel], {
    encoding: 'utf8',
    env: env2,
  }).trim();
  prsn.signingPubkey = execFileSync(
    SIGNET_BIN,
    ['pubkey', '--signing', '--key', prsn.signingLabel, '--base64url'],
    { encoding: 'utf8', env: env2 },
  ).trim();
  prsn.kemPubkey = execFileSync(
    SIGNET_BIN,
    ['pubkey', '--kem', '--key', prsn.kemLabel, '--base64url'],
    { encoding: 'utf8', env: env2 },
  ).trim();

  // §1-62 PR-C: after attest the wizard continues into the Drive-access phase — now
  // at the AUTHORIZE sub-state (the §2c gate means a broker always exists by here,
  // so the old always-Mac-setup landing is gone, and with it that step's exit
  // link; the authorize step deliberately has none — Chris, S145 — and the wizard
  // pages render no app header). ENROLLMENT-ONLY callers leave by history
  // navigation instead: two client-side goBacks (confirm → step-1 form → /account),
  // which keep the in-memory session (a full goto would drop it — the
  // enrollment-signin-return reality).
  if (opts?.stayInWizard) return;
  await page.goBack();
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText(prsn.handle, { exact: true })).toBeVisible({ timeout: 15_000 });
}

// --- PRSN side: the `signet` CLI (software tier) + signed HTTP (C7) ------------
// The PRSN surface is the CLI (crypto + keys + request signing) plus signed HTTP
// — there is no drive-CRUD command, so the harness builds the SIGNET-V1 canonical
// bytes, signs them via the CLI, and sends the request itself (the plan's "CLI +
// curl"). Keys live in a throwaway software-tier keystore (no SE / App-ID).

export const SIGNET_BIN = resolve(process.cwd(), '../target/debug/signet');
const SERVER_URL = 'http://localhost:8080';

export interface PrsnCliKeys {
  handle: string;
  keysDir: string;
  signingLabel: string;
  kemLabel: string;
  signingPubkey: string;
  signingFingerprint: string;
  kemPubkey: string;
  kemFingerprint: string;
}

export function signetEnv(keysDir: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    SIGNET_KEY_TIER: 'software',
    SIGNET_KEYS_DIR: keysDir,
    // The CLI's server base URL (config.rs SIGNET_SERVER_URL override) — point its
    // signed HTTP (download-url, wrapped-dek, range GETs) at the API server, not
    // the vite origin the browser uses.
    SIGNET_SERVER_URL: SERVER_URL,
  };
}

/** Sign back in as `email` from /signin, handling BOTH page variants: the
 *  fresh Email form, and the returning-user "Welcome back" one-tap Unlock
 *  (Bug014) that appears when this browser context has a remembered account —
 *  the virtual authenticator satisfies either passkey gesture. */
export async function signInAgain(page: Page, email: string): Promise<void> {
  await page.goto('/signin');
  const unlock = page.getByRole('button', { name: 'Unlock' });
  const emailField = page.getByLabel('Email');
  await expect(unlock.or(emailField)).toBeVisible({ timeout: 15_000 });
  if (await unlock.isVisible()) {
    if (await page.getByText(email).isVisible()) {
      await unlock.click();
    } else {
      // The remembered account is someone else — switch to the classic form.
      await page.getByRole('button', { name: 'Sign in to a different account' }).click();
      await emailField.fill(email);
      await page.getByRole('button', { name: 'Continue' }).click();
    }
  } else {
    await emailField.fill(email);
    await page.getByRole('button', { name: 'Continue' }).click();
  }
}

/** A throwaway PRSN identity for the production enrollment path: the `-ai`
 *  handle + an empty software-tier keystore. The keys are minted BY
 *  `signet enroll` (the 7a four-key ceremony) inside attestPrsnViaEnrollment —
 *  pre-minting any would trip enroll's already-enrolled idempotency no-op.
 *  The pubkey/fingerprint fields are filled in by the enrollment. */
export function prsnIdentity(): PrsnCliKeys {
  const runId = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const handle = `e2e-cli-${runId}-ai`;
  return {
    handle,
    keysDir: mkdtempSync(join(tmpdir(), 'signet-keys-')),
    signingLabel: `${handle}-signing`,
    kemLabel: `${handle}-kem`,
    signingPubkey: '',
    signingFingerprint: '',
    kemPubkey: '',
    kemFingerprint: '',
  };
}

/** Sign one SIGNET-V1 request as the PRSN (the CLI holds the key) and send it
 *  straight to the server — the PRSN talks to `:8080`, not the vite origin. Builds
 *  the canonical bytes (Envelope §6.2), signs via `signet sign --dual` (the
 *  ES256 ‖ ML-DSA-87 per-request hybrid a four-key-attested account MUST put on
 *  the wire — MF-1/N8 rejects classical-only), and sets the signet-* headers.
 *  `tamper` corrupts the signature to exercise rejection. */
export async function prsnSignedFetch(
  keys: PrsnCliKeys,
  method: string,
  pathAndQuery: string,
  opts: { body?: string; tamper?: boolean } = {},
): Promise<Response> {
  const body = opts.body ?? '';
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString('hex'); // 32 hex chars
  const bodyHash = createHash('sha256').update(body).digest('hex');
  const canonical = [
    'SIGNET-V1',
    method,
    pathAndQuery,
    bodyHash,
    timestamp,
    nonce,
    keys.signingFingerprint,
  ].join('\n');
  const canonFile = join(keys.keysDir, 'canonical.txt');
  writeFileSync(canonFile, canonical);
  let signature = execFileSync(
    SIGNET_BIN,
    [
      'sign',
      '--dual',
      '--key',
      keys.signingLabel,
      '--in',
      canonFile,
      '--output-format',
      'base64url-raw',
    ],
    { encoding: 'utf8', env: signetEnv(keys.keysDir) },
  ).trim();
  if (opts.tamper) signature = signature.slice(0, -1) + (signature.endsWith('A') ? 'B' : 'A');
  const headers: Record<string, string> = {
    'signet-fingerprint': keys.signingFingerprint,
    'signet-timestamp': timestamp,
    'signet-nonce': nonce,
    'signet-signature': signature,
  };
  if (body) headers['content-type'] = 'application/json';
  return fetch(`${SERVER_URL}${pathAndQuery}`, { method, headers, body: body || undefined });
}

/** Download + decrypt a shared file on the PRSN's CLI — the data-plane capstone
 *  hop, post-§4.2. Runs `signet file download` end to end: it fetches the
 *  recipient's wrapped DEK over signed HTTP, unwraps it with the PRSN's KEM key
 *  (the keystore computes the ECDH Z; the scalar never leaves it), requests the
 *  pre-signed GetObject URL, then Range-GETs and opens each §4.2 chunk
 *  (AAD = file_id‖index) straight to disk. Returns the recovered plaintext.
 *  Replaces the retired §4.1 raw-bytes GET + `signet decrypt` path — post
 *  Increment-4 the drive is §4.2-multipart-only, so the CLI's own download
 *  command is the PRSN's read path (and dogfoods the real authenticated transport). */
export function prsnDownload(keys: PrsnCliKeys, fileId: string): string {
  const outFile = join(keys.keysDir, `${fileId}.out`);
  execFileSync(
    SIGNET_BIN,
    [
      'file',
      'download',
      '--file-id',
      fileId,
      '--out',
      outFile,
      '--key',
      keys.signingLabel,
      '--kem-key',
      keys.kemLabel,
    ],
    { encoding: 'utf8', env: signetEnv(keys.keysDir) },
  );
  return readFileSync(outFile, 'utf8');
}
