<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PRSN EX Inc. -->
<script lang="ts">
  import Wordmark from '$lib/components/Wordmark.svelte';
</script>

<svelte:head>
  <title>Signet Drive API &amp; CLI Reference</title>
  <meta
    name="description"
    content="The PRSN-facing API and signet CLI reference for Signet Drive: authentication, data-plane workflows, the crypto envelope, errors, and installation."
  />
</svelte:head>

<main class="docs">
  <header class="head">
    <a href="/" class="home"><Wordmark /></a>
    <h1>API &amp; CLI Reference</h1>
    <p class="lede">
      Signet Drive has two equal surfaces. Humans use the web app, with no install and no terminal.
      PRSNs (and anyone scripting against the API) use the <code>signet</code> CLI plus signed HTTP. This
      page documents that second surface: every request is signed with your attested signing key, and
      all encryption happens locally, so the server stores only ciphertext it cannot read.
    </p>
  </header>

  <nav class="toc" aria-label="Contents">
    <a href="#quick-start">Quick start</a>
    <a href="#auth">Authentication</a>
    <a href="#workflows">Workflows</a>
    <a href="#cli">CLI reference</a>
    <a href="#errors">Errors</a>
    <a href="#install">Installation</a>
    <a href="#transparency">Transparency log</a>
  </nav>

  <section id="quick-start">
    <h2>Quick start</h2>
    <p>
      Five minutes from a fresh Mac to your first authenticated request. Onboarding is one command:
      your keys are generated for you during the flow, and nothing is ever hand-copied.
    </p>
    <pre><code
        ># 0. One-time per Mac. Your human installs Signet: download, double-click,
#    done (no terminal; see Installation below). The Add-PRSN page links it.

# 1. Enroll. Your human starts the enrollment from their Signet account
#    ("+ Add PRSN") and hands you the one-time CODE. This generates your
#    FOUR keys in the Secure Enclave (ES256 + ECDH classical, plus
#    ML-DSA-87 + ML-KEM-1024 post-quantum: the hybrid identity), proves
#    possession of both signing keys, and lands your human's passkey
#    attestation over all four:
signet enroll &lt;code&gt;
# (Already enrolled? `signet enroll` no-ops: identity comes from
#  SIGNET_HANDLE, below. There is no config folder to carry around.)

# 2. Tell signet who you are (identity is discovered, not carried;
#    your harness sets this once):
export SIGNET_HANDLE=&lt;your-handle&gt;

# 3. Confirm it all works:
signet whoami
# -> account_type "prsn", handle "&lt;your-handle&gt;", guardian "&lt;their-handle&gt;",
#    prsn_sharing_capability "read_only"

# 4. Once your human has authorized you (their account page), connect:
signet connect
# -> enrollment_confirmed true; your Drive access is live</code
      ></pre>
    <p class="note">
      PRSN keys are always <strong>Secure-Enclave-bound</strong> (<code>key_protection</code> is
      <code>secure_enclave</code>; there is no software tier): all four keys are created in the
      Mac's Secure Enclave and are non-extractable, so private key material never leaves the
      hardware and never appears on a command line. Crypto operations reach the Enclave through the
      <strong>local Secure-Enclave broker</strong>: with <code>SIGNET_BROKER_ADDR</code>
      set, every key operation is delegated over mutual-TLS to the broker your human authorized, at
      <code>127.0.0.1:&lt;port&gt;</code> natively, <code>host.docker.internal:&lt;port&gt;</code>
      from a Docker container (the container never holds keys). Your broker credential comes from
      <code>signet connect</code>, and it is signature-authenticated: your attested key is the
      proof, so there is no code to enter and nothing for your human to confirm. Full wiring:
      <em>Harness Contract for PRSNs</em> (ships with the public source repository at launch).
    </p>
  </section>

  <section id="auth">
    <h2>Authentication</h2>
    <p>
      Every request carries a per-request signature over a fixed set of canonical bytes, listed
      below. The server resolves your signing-key fingerprint to your active attestation and
      verifies the signature; there are no bearer tokens or sessions on this surface. For a
      hybrid-attested account (every account enrolled through the four-key ceremony), the signature
      is the <strong>hybrid dual</strong>: the raw ES256 half (64 B, <code>r&#8214;s</code>)
      followed by the ML-DSA-87 half (4,627 B), <em>both over the identical canonical bytes</em>,
      the ML-DSA half under the <code>signet:req:v1</code> FIPS&nbsp;204 context. Verification is
      AND-semantics (both halves verify or the request is rejected), and the server
      <em>requires</em> the dual from a hybrid account: a classical-only signature gets
      <code>401 dual_signature_required</code>, never a silent downgrade.
    </p>

    <h3>Canonical bytes</h3>
    <p>Seven lines, joined by a single newline, in this exact order:</p>
    <pre><code
        >SIGNET-V1
&lt;METHOD&gt;                 # GET, PUT, POST, DELETE (uppercase)
&lt;path-and-query&gt;         # exactly as requested, e.g. /v1/folders/&lt;id&gt;/files
&lt;sha256(body) hex&gt;       # lowercase hex; SHA-256 of the empty string when no body
&lt;timestamp&gt;              # Unix seconds
&lt;nonce&gt;                  # random hex, fresh per request
&lt;signing fingerprint&gt;    # lowercase hex SHA-256 of your signing key's DER SPKI</code
      ></pre>
    <p>
      The signature header is base64url (no-pad) of the signature bytes: the 4,691-byte dual for a
      hybrid account. Send these headers: <code>signet-fingerprint</code>,
      <code>signet-timestamp</code>, <code>signet-nonce</code>, <code>signet-signature</code> (and
      <code>content-type: application/json</code> when there is a body). The fingerprint is your
      <em>classical</em> signing key's: it's the attestation-lookup key, and the attestation then supplies
      your ML-DSA-87 verification key for the dual's second half.
    </p>

    <h3>A reusable <code>sign_request</code> helper (Bash)</h3>
    <pre><code
        >SERVER="$&lbrace;SIGNET_SERVER_URL:-https://drive.mysignet.ca&rbrace;"
SIGNING_LABEL="yourhandle-ai-signing"
FP=$(signet fingerprint --signing --key "$SIGNING_LABEL")

sign_request() &lbrace;
  method="$1"; path="$2"; body="$&lbrace;3:-&rbrace;"
  body_hash=$(printf '%s' "$body" | shasum -a 256 | cut -d' ' -f1)
  ts=$(date +%s)
  nonce=$(signet rand --hex 16)
  printf 'SIGNET-V1\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$method" "$path" "$body_hash" "$ts" "$nonce" "$FP" &gt; /tmp/canonical.txt
  # --dual = the hybrid ES256‖ML-DSA-87 signature a hybrid account MUST send
  # (both halves over the same bytes; drop --dual only for a pre-hybrid
  # two-key identity; the server rejects classical sigs from hybrid accounts):
  sig=$(signet sign --dual --key "$SIGNING_LABEL" --in /tmp/canonical.txt --output-format base64url-raw)
  curl -sS -X "$method" "$SERVER$path" \
    -H "signet-fingerprint: $FP" \
    -H "signet-timestamp: $ts" \
    -H "signet-nonce: $nonce" \
    -H "signet-signature: $sig" \
    $&lbrace;body:+-H "content-type: application/json" -d "$body"&rbrace;
&rbrace;</code
      ></pre>

    <h3>Check your setup</h3>
    <p>
      <code>POST /v1/test/sign-check</code> verifies a signed request end-to-end without changing any
      state. It is the fastest way to confirm your signing is correct.
    </p>
    <pre><code
        >sign_request POST /v1/test/sign-check '&lbrace;&rbrace;'
# -> 200 with your resolved identity, or a 401 explaining what failed</code
      ></pre>

    <h3>Common signing failures</h3>
    <ul>
      <li>
        <code>signature_invalid</code>: the bytes you signed don't match what the server rebuilt.
        Re-check the canonical-byte order, the uppercase method, and the exact path (including any
        query string).
      </li>
      <li>
        <code>dual_signature_required</code>: your account is hybrid-attested but the request
        carried a classical-only signature. Sign with <code>signet sign --dual</code> (the server never
        accepts a downgrade from a hybrid account).
      </li>
      <li>
        <code>timestamp_skew</code>: your clock is off. Use a fresh <code>date +%s</code> per request.
      </li>
      <li>
        <code>replay_detected</code>: the (fingerprint, nonce, timestamp) triple was already seen.
        Generate a fresh nonce every request.
      </li>
      <li>
        <code>attestation_invalid</code> / <code>attestation_not_found</code>: your attestation is
        missing, revoked, or expired (or your account isn't active). Ask your Guardian to re-attest.
      </li>
    </ul>
  </section>

  <section id="workflows">
    <h2>Workflows</h2>
    <p>
      Your drive is full-parity with the human web app: the grouped
      <code>signet folder | file | share</code> commands manage it by <em>path</em> (names are the
      shared human↔PRSN vocabulary; every command also takes an id as the precision fallback). Each
      command signs its own requests and does all encryption locally, and large files go
      <em>directly</em> to object storage in encrypted chunks (multipart); the API never sees a content
      byte.
    </p>

    <h3>Folders and files</h3>
    <pre><code
        ># See your drive:
signet share list                  # share folders (yours + shared with you)
signet folder list                 # top-level; `signet folder list /Finance` for children
signet file list /Finance          # the files in a folder, names decrypted

# Create structure (a share folder is top-level; subfolders nest under it):
signet share create Finance
signet folder create /Finance/Q3

# Upload: encrypted in chunks locally, wrapped to every folder recipient,
# then sent straight to object storage (up to 100 GB). The path's last
# segment is the file's name (or use --to /Finance/Q3 --name report.pdf):
signet file upload /Finance/Q3/report.pdf --in report.pdf

# Download + decrypt:
signet file download /Finance/Q3/report.pdf --out report.pdf</code
      ></pre>
    <p class="note">
      Every command addresses targets path-first (<code>--folder-id</code>/<code>--file-id</code>
      are the precision fallbacks), and base64url values (keys, codes, signatures) are accepted as-is
      even when they begin with <code>-</code> (about 1 in 64 do).
    </p>
    <p class="note">
      Uploads are <strong>stall-resilient</strong>: a part transfer that stops moving is cut within
      seconds and retried on a fresh connection (each retry is announced on stderr). If repeated
      transfer failures exhaust the retry budget, the upload
      <strong>pauses instead of failing</strong>
      (exit <code>32 transfer_stalled</code>) and
      <strong>re-running the same command resumes</strong> from the parts already stored (nothing is re-sent;
      the server is authoritative for what landed). A source file that changed since the interrupted attempt
      starts fresh by design.
    </p>
    <p class="note">
      For a PRSN-owned share folder your Guardian is always among the recipients (server-enforced),
      so you can't lock them out: uploads wrap the file key to them automatically.
    </p>

    <h3>Sharing</h3>
    <pre><code
        ># Who can see a folder:
signet share recipients /Finance

# Invite someone (re-wraps every file's key to them; PRSN-initiated sharing is
# capability-gated; your Guardian sets your level):
signet share invite /Finance --to maren --permission read_only

# Receive a share: preview, then accept (the pre-staged wraps activate atomically):
signet share preview --token "$TOKEN"
signet share accept  --token "$TOKEN"

# Pending invitations (a pending invitation write-locks its folder; the
# one-time link is shown only once, at `invite`; a lost link is cancel + re-invite):
signet share invitations /Finance                            # list pending (recipient, permission, expiry, id)
signet share cancel-invite /Finance --invitation-id "$ID"    # cancel: the link dies, writes resume

# Housekeeping:
signet share remove /Finance --recipient-id "$ACCOUNT_ID"   # owner removes a recipient
signet share leave --folder-id "$FOLDER_ID"                 # leave a folder shared with you
# (recipient/folder ids come from `share recipients` / `share list`)</code
      ></pre>

    <h3>Verify an attestation</h3>
    <pre><code
        ># Online, the server keys resolve from /v1/server-info automatically,
# and the response is verified against BOTH server signatures (ES256 +
# ML-DSA-87; once the PQ key is known, a classical-only response is refused):
signet attestation-verify --attestation-id "$ATTESTATION_ID"

# Offline, pin both keys yourself (select by purpose, never by index):
INFO=$(curl -s https://drive.mysignet.ca/v1/server-info)
SERVER_KEY=$(echo "$INFO"    | jq -r '.current_signing_keys[] | select(.purpose=="attestation_verification") | .public_key')
SERVER_PQ_KEY=$(echo "$INFO" | jq -r '.current_signing_keys[] | select(.purpose=="attestation_verification_pq") | .public_key')
signet attestation-verify --attestation-id "$ATTESTATION_ID" \
  --server-pubkey "$SERVER_KEY" --server-pq-pubkey "$SERVER_PQ_KEY"</code
      ></pre>

    <h3>Audit log &amp; transparency cross-check</h3>
    <pre><code
        ># Your account's audit history (signed request):
signet audit --key yourhandle-ai-signing --since 0 --limit 100

# Independently verify a key is in the public transparency log:
signet transparency-verify --fingerprint "$KEM_FINGERPRINT" --purpose kem</code
      ></pre>
  </section>

  <section id="cli">
    <h2>CLI reference</h2>
    <p>
      Run <code>signet &lt;command&gt; --help</code> for full options. Global flags:
      <code>--server-url</code>
      (or <code>SIGNET_SERVER_URL</code>), <code>--quiet</code>, <code>--pretty</code>,
      <code>--json-errors</code>. Identity: <code>SIGNET_HANDLE</code> (discovered, not carried;
      there is no config folder to move around). PRSN keys are always Secure-Enclave-backed, and
      with
      <code>SIGNET_BROKER_ADDR</code> set, operations go to the local Secure-Enclave broker over mutual-TLS
      (native and Docker); the keystore otherwise auto-detects (the device Secure Enclave natively).
    </p>
    <table>
      <thead><tr><th>Command</th><th>Purpose</th></tr></thead>
      <tbody>
        <tr
          ><td><code>enroll [CODE]</code></td><td
            >One-command onboarding: your human's confirm-and-approve + the four-key Secure-Enclave
            ceremony (ES256 · ECDH · ML-DSA-87 · ML-KEM-1024) with proof-of-possession. Idempotent:
            omit CODE to no-op when already enrolled.</td
          ></tr
        >
        <tr
          ><td><code>whoami</code> · <code>quota</code></td><td
            >Your identity (handle, guardian, capability) · your pooled storage usage.</td
          ></tr
        >
        <tr
          ><td><code>folder list|create [PATH]</code></td><td
            >List or create folders by path (ids as the precision fallback).</td
          ></tr
        >
        <tr
          ><td><code>file list|upload|download</code></td><td
            >The data plane: chunked client-side encryption, direct to object storage (up to 100
            GB).</td
          ></tr
        >
        <tr
          ><td><code>share create|list|recipients|invite|preview|accept|remove|leave</code></td><td
            >Share-folder management; <code>invite</code> re-wraps file keys to the recipient (capability-gated).</td
          ></tr
        >
        <tr
          ><td><code>status</code></td><td
            >Helper health: LaunchAgent liveness, version, provisioned channels (the menu-bar item's
            data source).</td
          ></tr
        >
        <tr
          ><td><code>connect</code></td><td
            >Connect to Signet Drive once your guardian has authorized you. Claims your credential
            by signed pickup (your attested key is the proof; no code, nothing for your human to
            confirm).</td
          ></tr
        >
        <tr
          ><td><code>device pickup|keygen|sign|renew|renew-cert</code></td><td
            >This device's key operations via the broker, for scripts and explicit provisioning:
            <code>pickup</code> is what <code>connect</code> runs; the rest operate via the broker.</td
          ></tr
        >
        <tr
          ><td><code>host-channel provision|list|remove</code></td><td
            >Host-side delegation channels: the present-but-inactive fallback path (Apple
            <code>container</code> runtimes); Docker + native use the local broker.</td
          ></tr
        >
        <tr
          ><td><code>keygen --signing|--kem --label L</code></td><td
            >Generate a keypair in the keystore (low-level; <code>enroll</code> does this for you).</td
          ></tr
        >
        <tr
          ><td><code>pubkey --signing|--kem --key L [--base64url]</code></td><td
            >Print the public key (x963/der/pem/jwk).</td
          ></tr
        >
        <tr
          ><td><code>fingerprint --signing|--kem --key L</code></td><td
            >SHA-256 of the DER SPKI (lowercase hex).</td
          ></tr
        >
        <tr
          ><td><code>keys list</code> · <code>keys delete --label HANDLE</code></td><td
            >List or delete keys by handle; <code>--purpose</code> selects one of
            <code>signing|kem|signing-pq|kem-pq</code>, else every key the handle holds (all four
            for a hybrid identity).</td
          ></tr
        >
        <tr
          ><td><code>sign [--dual] --key L --in F --output-format base64url-raw</code></td><td
            >ES256 over canonical bytes, or with <code>--dual</code> the hybrid ES256&#8214;ML-DSA-87
            per-request signature a hybrid account must send.</td
          ></tr
        >
        <tr
          ><td><code>encrypt --in --out --aad-file-id --to-pubkey… --wraps-out</code></td><td
            >AES-256-GCM a file + wrap the DEK to recipients.</td
          ></tr
        >
        <tr
          ><td><code>decrypt --in --out --aad-file-id --wrap-envelope --key</code></td><td
            >Unwrap the DEK + open the file envelope.</td
          ></tr
        >
        <tr
          ><td><code>rewrap --wrap-envelope-in --to-pubkey --wrap-out --key</code></td><td
            >Re-wrap a DEK to a new recipient (DEK never exposed).</td
          ></tr
        >
        <tr
          ><td><code>encrypt-name</code> · <code>decrypt-name</code></td><td
            >Encrypt/decrypt a folder or file name.</td
          ></tr
        >
        <tr
          ><td><code>attestation-verify --attestation-id|--in --server-pubkey</code></td><td
            >Verify a server-signed attestation response.</td
          ></tr
        >
        <tr
          ><td><code>transparency-verify --fingerprint --purpose [--published-root]</code></td><td
            >Verify a transparency-log inclusion proof.</td
          ></tr
        >
        <tr
          ><td><code>audit --key --since --limit</code></td><td
            >Fetch your audit-log entries (signed).</td
          ></tr
        >
        <tr
          ><td
            ><code>rand</code> · <code>base64url-no-pad</code> · <code>version</code> ·
            <code>update</code></td
          ><td>Utilities.</td></tr
        >
      </tbody>
    </table>
  </section>

  <section id="errors">
    <h2>Errors</h2>
    <p>
      Every error is a JSON envelope (an <code>error</code> object carrying <code>code</code>,
      <code>message</code>, and an optional <code>details</code>) with an HTTP status matching the
      code. The codes you'll meet on this surface:
    </p>
    <table>
      <thead><tr><th>Status</th><th>Code</th><th>Meaning</th></tr></thead>
      <tbody>
        <tr
          ><td>401</td><td><code>authentication_required</code></td><td
            >No valid signed request was presented.</td
          ></tr
        >
        <tr
          ><td>401</td><td><code>attestation_not_found</code> / <code>attestation_invalid</code></td
          ><td
            >No active attestation for your fingerprint (missing, revoked, expired, or account not
            active).</td
          ></tr
        >
        <tr
          ><td>401</td><td
            ><code>signature_invalid</code> / <code>signature_format_unknown</code></td
          ><td>The signature failed to verify, or wasn't the expected encoding.</td></tr
        >
        <tr
          ><td>401</td><td><code>dual_signature_required</code></td><td
            >Your account is hybrid-attested; sign with the ES256&#8214;ML-DSA-87 dual (<code
              >signet sign --dual</code
            >). Classical-only signatures are refused.</td
          ></tr
        >
        <tr
          ><td>401</td><td><code>timestamp_skew</code></td><td
            >Your timestamp is outside the allowed window.</td
          ></tr
        >
        <tr
          ><td>409</td><td><code>replay_detected</code></td><td
            >This (fingerprint, nonce, timestamp) was already used.</td
          ></tr
        >
        <tr
          ><td>409</td><td><code>version_conflict</code> / <code>idempotency_key_conflict</code></td
          ><td>Concurrent or duplicate mutation.</td></tr
        >
        <tr
          ><td>409</td><td
            ><code>invitation_already_consumed</code> /
            <code>folder_write_locked_pending_invitations</code></td
          ><td>Invitation already accepted; folder locked while invitations are outstanding.</td
          ></tr
        >
        <tr
          ><td>403</td><td
            ><code>permission_denied</code> / <code>sharing_capability_insufficient</code></td
          ><td>Not allowed; a PRSN's sharing capability is too low for this action.</td></tr
        >
        <tr
          ><td>403</td><td
            ><code>invitation_for_different_recipient</code> /
            <code>cannot_remove_mandatory_guardian</code></td
          ><td>Invitation isn't addressed to you; the Guardian can't be removed.</td></tr
        >
        <tr
          ><td>404</td><td><code>not_found</code></td><td>No such resource, or you can't see it.</td
          ></tr
        >
        <tr
          ><td>403</td><td><code>account_read_only</code></td><td
            >The account (or its Guardian's) is read-only: an inactive or lapsed subscription, or
            over quota. Reads still work; writes resume when it's restored.</td
          ></tr
        >
        <tr
          ><td>413</td><td><code>quota_exceeded</code> / <code>file_too_large</code></td><td
            >The upload would exceed your storage quota, or the file exceeds the size limit.</td
          ></tr
        >
        <tr><td>429</td><td><code>rate_limited</code></td><td>Slow down and retry.</td></tr>
        <tr
          ><td>400</td><td
            ><code>cross_root_move_not_supported</code> / <code>cli_outdated</code> /
            <code>invalid_request</code></td
          ><td>Unsupported move; update the CLI; malformed request.</td></tr
        >
        <tr
          ><td>500</td><td><code>internal_error</code></td><td
            >Server fault. Safe to retry an idempotent request.</td
          ></tr
        >
      </tbody>
    </table>

    <h3>Client-version signals</h3>
    <p class="note">
      The server drives the CLI update contract on every <code>/v1</code> request that carries a
      <code>Signet-Cli-Version</code> header (the <code>signet</code> CLI always sends it; plain
      HTTP scripts may too). A client below the operator's <em>recommended</em> version gets
      <code>Signet-Cli-Update-Recommended: true</code> on the response, and the CLI surfaces it as a
      one-line stderr nudge; the operation proceeds. A client below the <em>minimum</em> version
      (raised conservatively, e.g. for a security-critical fix) is refused with
      <code>400 cli_outdated</code>, and the CLI exits 16 with "run 'signet update'". The
      <code>/cli/*</code> download namespace is never version-gated, so an outdated client can always
      fetch its own update.
    </p>
  </section>

  <section id="install">
    <h2>Installation</h2>
    <p>
      Signet is installed <strong>by a human, once per Mac</strong>: a notarized,
      Developer-ID-signed Signet app with a graphical install (no terminal, no
      <code>curl | sh</code>). The agent never installs itself.
    </p>
    <pre><code
        ># 1. Download (the Add-PRSN page links this; it redirects to the latest
#    versioned release, with a .sha256 companion alongside):
https://drive.mysignet.ca/cli/signet-macos.zip

# 2. Double-click the unzipped Signet app (signet-&lt;version&gt;.app). macOS
#    confirms Apple checked it → Open. "Signet is set up": the signet CLI is on
#    the PATH, and the helper runs as an always-on menu-bar item (◉ shows
#    liveness + version at a glance).

# Check for a newer release any time (exit 8 = update available):
signet update
# Updating: when a newer release is published, the menu-bar item shows ◉ ↑ and
# an "Update Signet…" action: the app downloads, verifies, installs, and
# restarts itself. (Re-running the installer by hand still works and replaces
# the previous version in place.)</code
      ></pre>
    <p class="note">
      The app is open source and the build is reproducible: each release's sha256 is committed
      publicly, so anyone can verify the served artifact matches the published source. The download
      is convenience, not the trust anchor. Apple's notarization means Gatekeeper runs it without
      warnings. Source: the public Signet Drive repository (published at launch).
    </p>
  </section>

  <section id="transparency">
    <h2>Transparency log</h2>
    <p>
      Every public-key binding (each attestation's signing and KEM keys) is appended to an
      append-only, Merkle-tree transparency log. You can independently verify that a key the server
      hands you is the same one committed to the log, so a misbehaving server can't quietly swap a
      recipient's key.
    </p>
    <pre><code
        ># Verify a fingerprint's inclusion in the current log:
signet transparency-verify --fingerprint "$FINGERPRINT" --purpose kem

# The raw endpoints, if you want to check proofs yourself:
#   GET /v1/transparency/log/root
#   GET /v1/transparency/log/inclusion-proof?fingerprint=...&amp;purpose=...
#   GET /v1/transparency/log/consistency-proof?...</code
      ></pre>
  </section>

  <footer class="foot">
    <Wordmark />
    <span>Post-quantum-ready, zero-knowledge storage, used by humans and PRSNs as equals.</span>
  </footer>
</main>

<style>
  .docs {
    max-width: 52rem;
    margin: 0 auto;
    padding: 2.5rem 1.5rem 4rem;
    color: var(--ink);
    line-height: 1.6;
  }
  .head {
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .home {
    text-decoration: none;
  }
  h1 {
    font-family: var(--font-serif);
    font-size: 2rem;
    margin: 1rem 0 0.5rem;
  }
  h2 {
    font-family: var(--font-serif);
    font-size: 1.5rem;
    margin: 2.5rem 0 0.75rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--border);
  }
  h3 {
    font-size: 1.1rem;
    margin: 1.5rem 0 0.5rem;
    color: var(--ink-soft);
  }
  .lede {
    color: var(--ink-soft);
    font-size: 1.05rem;
  }
  .toc {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 1.25rem;
    font-size: 0.95rem;
    margin-bottom: 1rem;
  }
  .toc a {
    color: var(--accent);
    text-decoration: none;
  }
  .toc a:hover {
    text-decoration: underline;
  }
  pre {
    background: var(--ink);
    color: #e9e9f0;
    border-radius: var(--radius-sm);
    padding: 1rem 1.1rem;
    overflow-x: auto;
    font-size: 0.86rem;
    line-height: 1.5;
  }
  pre code {
    background: none;
    color: inherit;
    padding: 0;
  }
  code {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.88em;
    background: #ece9e1;
    border-radius: 4px;
    padding: 0.08em 0.32em;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
    margin: 0.5rem 0;
  }
  th,
  td {
    text-align: left;
    padding: 0.5rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  th {
    color: var(--muted);
    font-weight: 600;
  }
  .note {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.75rem 1rem;
    font-size: 0.92rem;
    color: var(--ink-soft);
  }
  ul {
    padding-left: 1.2rem;
  }
  li {
    margin: 0.35rem 0;
  }
  .foot {
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    color: var(--muted);
    font-size: 0.9rem;
  }
</style>
