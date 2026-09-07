// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The Garnet SE-broker — the **concurrent, multi-PRSN mutual-TLS listener** (Auth-Core Spec v03
//! §6/§7, Design Spec v05 §4.4/§5.2). One broker per Mac serves a guardian's ≤8 PRSNs, performing
//! a Secure-Enclave op only for a connection that proves, per op:
//!
//! 1. **mTLS** — a client cert chaining (depth-1) to the pinned K2 deployment CA, EKU=clientAuth
//!    ([`crate::broker_tls`]); the cert SAN is the authenticated PRSN handle.
//! 2. **A cert-bound token** — a `signet-broker`-audience JWS whose `cnf` is *this* connection's
//!    leaf thumbprint and whose `sub` equals the cert SAN handle (the §7 consistency triple); the
//!    structure + binding are verified here, the time/freshness by the lease (below).
//! 3. **A live grant** — the leased check-at-use confirm (§6): the broker confirms the grant is live
//!    at op-time (via [`GrantStatusClient`]), leasing it briefly so a burst shares one check. Cold
//!    start / a definitive revoke / a sustained outage all **fail closed**.
//!
//! Then the SE op runs via [`crate::host_signer::handle_op`] with the **authenticated** handle —
//! which fail-closes any cross-handle label (the same per-PRSN authorization the mount model used).
//!
//! ## The #1 build risk: concurrent multi-PRSN isolation (§7)
//!
//! Today's mount-channel host-signer gets per-PRSN isolation "for free" from channel topology; this
//! broker derives the handle from the presented cert + token and serves many PRSNs concurrently, so
//! isolation is **enforced explicitly**: the `(cert, token, handle, label)` for an op is a single
//! **stack-local tuple** ([`handle_request`]'s locals) — there is **no** process- or connection-scoped
//! "current identity". `cnf` is re-derived against *this* connection's leaf; SE access is serialized
//! behind a mutex (the SE is a serial coprocessor); per-grant leases are independently locked. The
//! NORMATIVE build-gate (`tests::no_cross_prsn_se_access_under_concurrency`) hammers N distinct-handle
//! agents across many threads and asserts no op ever touches a non-`sub` key.
//!
//! ## Transport / runtime
//!
//! Synchronous `rustls` on a bounded worker pool (no tokio — the CLI is sync and SE ops block). The
//! pool size is the structural accept-rate-limit. The listener binds **loopback** ([`assert_loopback`]
//! — the broker must never be routable; the S1 zero-access-under-server-compromise invariant rests on
//! its inbound unreachability). The broker→server grant-status query is injected as a
//! [`GrantStatusClient`]; Phase-2 #4 lands the real K2-pinned mutual-TLS client, and until then the
//! default ([`UnreachableGrantStatus`]) fails closed.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection};
use signet_channel::wire::{OpErr, Response};
use uuid::Uuid;

use crate::broker_wire::BrokerRequest;
use crate::error::{CliError, Result};
use crate::garnet_revocation::{Decision, FailReason, GrantLease, GrantStatusOutcome, LeaseConfig};
use crate::keystore::Keystore;

/// The broker's default loopback bind address — the single source shared by the `signet broker
/// serve --bind` clap default and the broker LaunchAgent plist ([`crate::install`]), so the daemon
/// and the agents that reach it (`SIGNET_BROKER_ADDR`) can't silently disagree. Loopback-only (the
/// broker must never be routable — the S1 zero-access-under-server-compromise invariant).
pub const DEFAULT_BROKER_BIND: &str = "127.0.0.1:8765";

/// Bounded worker pool — the structural accept-rate-limit (caps concurrent TLS handshakes; the SE op
/// is serialized regardless, §7.3). Sized for a guardian's ≤8 PRSNs with headroom for concurrent ops.
const BROKER_WORKER_THREADS: usize = 16;
/// Per-connection read/write timeout (slowloris defense — an op is one small frame + one SE call).
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Accept-poll interval for the non-blocking listener (bounds shutdown latency to ~this).
const ACCEPT_POLL: Duration = Duration::from_millis(100);

/// The broker→server grant-status query (Auth-Core §6) — the check-at-use confirm. The broker queries
/// the server (over the K2-pinned mutual-TLS channel, presenting its K_bc client cert) for the
/// (`grant_id`, `handle`) it is serving, plus `cnf` — the **presented** agent cert's thumbprint, so
/// the server reports whether *this* cert is revoked (presented-cert-precise, S085), not merely the
/// grant's enrolled cert. The broker maps the server's answer to a [`GrantStatusOutcome`]: a
/// definitive live answer (`status=active` & `enrollment_confirmed` & not `cert_revoked`) →
/// [`GrantStatusOutcome::Live`] carrying the authoritative `server_time`; `enrollment_confirmed=false`
/// / `cert_revoked` / `status=revoked` → [`GrantStatusOutcome::Revoked`] (definitive, no grace);
/// unreachable/ambiguous → [`GrantStatusOutcome::Unreachable`]. The real client is
/// [`crate::garnet_grant_status_client::HttpGrantStatusClient`]; until Phase 6 wires it, the default
/// ([`UnreachableGrantStatus`]) fails closed.
pub trait GrantStatusClient: Send + Sync {
    fn query(&self, grant_id: Uuid, handle: &str, cnf: &str) -> GrantStatusOutcome;
}

/// The default grant-status client until #4 lands the real K2-pinned mutual-TLS query: it can never
/// reach the server, so every required re-confirm yields [`GrantStatusOutcome::Unreachable`] and the
/// broker fail-closes (cold-start refuses, with no trusted time). The safe default — the broker must
/// not serve real SE ops without a live grant confirm.
pub struct UnreachableGrantStatus;

impl GrantStatusClient for UnreachableGrantStatus {
    fn query(&self, _grant_id: Uuid, _handle: &str, _cnf: &str) -> GrantStatusOutcome {
        GrantStatusOutcome::Unreachable
    }
}

/// The shared, immutable-except-the-locked-maps broker state borrowed by every worker thread. It is
/// `Sync` (so `&BrokerContext` crosses thread boundaries): the keystore is shared `&(dyn Keystore +
/// Sync)` with SE access serialized by `se_lock`; the per-grant leases are individually locked.
struct BrokerContext<'a> {
    /// The mutual-TLS server config (the K2 client-cert verifier + the broker's K3 server cert).
    server_config: Arc<ServerConfig>,
    /// K1's public verifying key (X9.63) — the token signature root.
    k1_verify_key: &'a [u8],
    /// The broker→server grant-status query (the check-at-use confirm).
    grant_status: &'a dyn GrantStatusClient,
    /// The check-at-use control values (`system_config`).
    lease_cfg: LeaseConfig,
    /// The host keystore (SE / software). Shared across workers; access serialized by `se_lock`.
    keystore: &'a (dyn Keystore + Sync),
    /// Per-grant leases, keyed by the *verified* token's `grant_id`. The outer mutex guards only the
    /// map lookup/insert; the inner mutex serializes one grant's lease decisions.
    leases: Mutex<HashMap<Uuid, Arc<Mutex<GrantLease>>>>,
    /// Serializes Secure-Enclave access (the SE is a serial coprocessor; §7.3 — cheap at ≤8 PRSNs).
    se_lock: Mutex<()>,
}

/// Serve the broker on `bind_addr` (loopback-only — see [`assert_loopback`]) until `shutdown` is set.
/// Binds the listener then delegates to [`serve_on`]. The production entry (wired live in Phase 6;
/// the mount model is the working fallback until then).
pub fn serve(
    bind_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    k1_verify_key: Vec<u8>,
    grant_status: Arc<dyn GrantStatusClient>,
    lease_cfg: LeaseConfig,
    keystore: &(dyn Keystore + Sync),
    shutdown: &AtomicBool,
) -> Result<()> {
    assert_loopback(bind_addr)?;
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| CliError::new(70, "internal", format!("broker bind {bind_addr}: {e}")))?;
    serve_on(
        listener,
        server_config,
        k1_verify_key,
        grant_status,
        lease_cfg,
        keystore,
        shutdown,
    )
}

/// Serve on an already-bound `listener` (the testable core — the caller learns the ephemeral addr via
/// `listener.local_addr()`). Spawns the bounded worker pool; each worker accept-polls the shared
/// non-blocking listener and handles one connection to completion. Returns when `shutdown` is set and
/// all workers have drained (the scope joins them).
pub fn serve_on(
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
    k1_verify_key: Vec<u8>,
    grant_status: Arc<dyn GrantStatusClient>,
    lease_cfg: LeaseConfig,
    keystore: &(dyn Keystore + Sync),
    shutdown: &AtomicBool,
) -> Result<()> {
    listener.set_nonblocking(true).ok();
    let ctx = BrokerContext {
        server_config,
        k1_verify_key: &k1_verify_key,
        grant_status: grant_status.as_ref(),
        lease_cfg,
        keystore,
        leases: Mutex::new(HashMap::new()),
        se_lock: Mutex::new(()),
    };
    std::thread::scope(|s| {
        for _ in 0..BROKER_WORKER_THREADS {
            s.spawn(|| accept_worker(&listener, &ctx, shutdown));
        }
    });
    Ok(())
}

/// Serve the broker from a persisted [`crate::broker_credential::BrokerCredential`] — the core of the
/// `signet broker serve` entry. Builds the K3 mutual-TLS **server** config + the K_bc grant-status
/// **client** from the credential, applies the check-at-use lease defaults, and serves on `bind_addr`
/// (loopback-only — [`assert_loopback`]) until `shutdown` is set. `keystore` performs the PRSN SE ops
/// (the device SE in production; a software keystore for dev/CI).
///
/// The lease values passed here are the **defaults**; since bug125 (F-006) the live
/// `system_config` SLA arrives on each grant-status affirmative and is adopted per grant.
pub fn serve_from_credential(
    cred: &crate::broker_credential::BrokerCredential,
    bind_addr: SocketAddr,
    keystore: &(dyn Keystore + Sync),
    shutdown: &AtomicBool,
) -> Result<()> {
    // bug087 fix 3, enforced at the one entry every caller shares: prove the credential's key
    // IS its certificate's key before binding a listener. A broker that fails this would
    // complete TCP accepts and then fail every TLS CertificateVerify with `bad signature` —
    // "running" while serving nothing. Refusing to serve (no listener; port closed) is the
    // honest state, and the error names the recovery (re-provision).
    cred.verify_k3_binding()?;
    let server_config = cred.broker_server_config()?;
    let grant_status: Arc<dyn GrantStatusClient> = Arc::new(cred.grant_status_client()?);
    serve(
        bind_addr,
        server_config,
        cred.k1_verify().to_vec(),
        grant_status,
        default_lease_config(),
        keystore,
        shutdown,
    )
}

/// The check-at-use control **defaults** (Auth-Core §6/§8 `system_config`):
/// `revocation_lease_seconds=30`, `revocation_outage_grace_seconds=90`, `token_skew_seconds=30`.
///
/// bug125 (audit F-006) — these are now the *starting* values, not the only ones. Each grant-status
/// affirmative carries the live `system_config` SLA, which the per-grant [`GrantLease`] adopts after
/// re-clamping to the broker's own bounds; these defaults govern only until the first such answer
/// (and remain in force against a server that does not supply them). Before bug125 they were the
/// permanent values and the operator's setting reached nothing.
///
/// `token_skew` stays compiled-in deliberately: F-006 concerns the two revocation-SLA knobs (0022),
/// not token-expiry tolerance (`token_skew_seconds`, 0018).
///
/// ⚠ **Public solely so the drift control can read it** (bug136 residual, Gus S161). `lease +
/// outage_grace` here is twin-derived with `REVOCATION_TOTAL_BUDGET_SECONDS` in
/// `server/src/admin.rs`, and no crate is shared between server and CLI to home one constant. Both
/// sites documented the coupling and documentation is not a control — our own governing lesson.
/// `budget_is_twin_derived_with_the_brokers_compiled_defaults` (in that module's tests) reads this
/// function and asserts the sum, so tuning either side alone goes red instead of silently letting
/// the admin API accept pairs the enforcer refuses — bug136's own shape, reintroduced by drift.
pub fn default_lease_config() -> LeaseConfig {
    LeaseConfig {
        lease: Duration::from_secs(30),
        outage_grace: Duration::from_secs(90),
        token_skew: Duration::from_secs(30),
    }
}

/// One worker: accept-poll the shared non-blocking listener until shutdown, handling each accepted
/// connection inline. A transient accept error is tolerated (keep serving); the pool size caps
/// concurrent handshakes.
fn accept_worker(listener: &TcpListener, ctx: &BrokerContext, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => handle_connection(stream, ctx),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => sleep(ACCEPT_POLL),
            Err(_) => sleep(ACCEPT_POLL),
        }
    }
}

/// Rate-limited handshake-failure logging (bug087 fix 4). The serve loop still drops failed
/// connections without content detail (tokens/handles are never logged), but a FULLY silent
/// drop cost the bug087 diagnosis: a broker failing 100% of its handshakes was
/// indistinguishable from a broker nobody was calling. One line per window with a
/// suppressed-count — enough to see "handshakes are failing" in `broker.log`, cheap enough
/// that a misbehaving loopback client cannot spam the log. The `detail` is the TLS/IO error
/// display only (alert names, IO kinds) — never certificate contents or request bytes.
fn log_handshake_failure(what: &str, detail: &str) {
    use std::time::Instant;
    const WINDOW: Duration = Duration::from_secs(60);
    static LAST: Mutex<Option<(Instant, u64)>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    match &mut *last {
        Some((at, suppressed)) if at.elapsed() < WINDOW => *suppressed += 1,
        slot => {
            let suppressed = slot.as_ref().map(|(_, n)| *n).unwrap_or(0);
            if suppressed > 0 {
                eprintln!(
                    "signet broker serve: {what} ({detail}): plus {suppressed} suppressed in \
                     the last minute"
                );
            } else {
                eprintln!("signet broker serve: {what} ({detail})");
            }
            *slot = Some((Instant::now(), 0));
        }
    }
}

/// Drive one connection: complete the mutual-TLS handshake (the client-cert verifier runs here),
/// extract the authenticated leaf, read one request frame, dispatch it, write the response. Any
/// failure (bad/absent client cert, handshake/IO error, malformed frame) drops the connection —
/// fail-closed, with the handshake-failure CLASS logged rate-limited (bug087 fix 4; content
/// stays unlogged — tokens/handles/certs never appear).
fn handle_connection(stream: TcpStream, ctx: &BrokerContext) {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_nonblocking(false).ok(); // blocking IO for the rustls handshake/app data
    let mut sock = stream;

    let mut conn = match ServerConnection::new(Arc::clone(&ctx.server_config)) {
        Ok(c) => c,
        Err(_) => return,
    };
    // Complete the handshake (the K2 client-cert verifier gates it). On a blocking socket one
    // complete_io drives it to completion; a still-handshaking state after is defensive-only.
    if let Err(e) = conn.complete_io(&mut sock) {
        log_handshake_failure("a mutual-TLS handshake failed", &e.to_string());
        return;
    }
    if conn.is_handshaking() {
        log_handshake_failure(
            "a mutual-TLS handshake stalled",
            "still handshaking after IO",
        );
        return;
    }

    // The authenticated identity comes ONLY from the verified leaf — never from the request body.
    let leaf = match conn.peer_certificates().and_then(|c| c.first()) {
        Some(c) => c.as_ref().to_vec(),
        None => return, // mutual-TLS is mandatory; defensive
    };
    let handle = match signet_crypto::x509::cert_san_handle(&leaf) {
        Ok(Some(h)) => h,
        _ => return, // the verifier accepted it, so it carries a URN SAN; defensive
    };
    let cnf = signet_crypto::x509::cert_thumbprint_b64url(&leaf);

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let req: BrokerRequest = match crate::broker_wire::read_frame(&mut tls) {
        Ok(r) => r,
        Err(_) => return,
    };
    let resp = handle_request(&handle, &cnf, req, ctx);
    let _ = crate::broker_wire::write_frame(&mut tls, &resp);
}

/// The per-op core — the **stack-local tuple** `(handle, cnf, token, op)`. `handle`/`cnf` are this
/// connection's authenticated leaf; nothing is read from a process/connection-scoped "current
/// identity". Steps: (1) verify the token's structure + binding against THIS leaf (`sub` == `handle`,
/// `cnf` == this leaf, `aud` == broker) — NOT time, which the lease owns (§6); (2) the leased
/// live-grant check; (3) on a live decision, the SE op (serialized), with the authenticated `handle`
/// — `handle_op` fail-closes any cross-handle label.
fn handle_request(handle: &str, cnf: &str, req: BrokerRequest, ctx: &BrokerContext) -> Response {
    // (1) Structure + binding. The lease is the trusted-time authority (§6: the broker cannot check
    // exp at verify-time — trusted time arrives only with the grant-status confirm, which needs the
    // verified grant_id to query), so we skip the time window here and feed exp to the lease.
    let verified = match signet_crypto::garnet_token::verify_skipping_time(
        &req.token,
        ctx.k1_verify_key,
        signet_crypto::garnet_token::Audience::Broker,
        handle,
        cnf,
    ) {
        Ok(v) => v,
        Err(_) => return op_err("unauthorized", "token verification failed"),
    };

    // (2) The leased check-at-use confirm. The outer map lock guards only the lookup/insert; the
    // grant-status query + decision run under this grant's own lease lock (a burst for one PRSN
    // shares one confirm and does not block other grants).
    let lease_arc = {
        let mut map = ctx.leases.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(map.entry(verified.grant_id).or_default())
    };
    let decision = {
        let mut lease = lease_arc.lock().unwrap_or_else(|e| e.into_inner());
        match lease.decide(Instant::now(), verified.exp, &ctx.lease_cfg) {
            Decision::ReconfirmRequired => {
                let outcome = ctx.grant_status.query(verified.grant_id, handle, cnf);
                lease.on_grant_status(outcome, Instant::now(), verified.exp, &ctx.lease_cfg)
            }
            other => other,
        }
    };

    // (3) Serve only on a live decision. SE access is serialized; the label's handle is the
    // AUTHENTICATED handle (the §7 triple — handle_op refuses any cross-handle label).
    match decision {
        Decision::Serve => {
            let _se = ctx.se_lock.lock().unwrap_or_else(|e| e.into_inner());
            crate::host_signer::handle_op(ctx.keystore, handle, req.op)
        }
        // A token that expired against the broker's *trusted server time* (§6) is a renewable
        // re-authenticate condition, NOT a definitive "no": the agent fixes it by minting a fresh
        // token (same cert, same live grant). It is reported distinctly so the agent's BrokerKeystore
        // force-renews once and retries — this is the host-clock-skew case where the agent's own
        // proactive near-expiry check judged the token still fresh (its host clock runs behind the
        // server). A *revoked* / unconfirmed / unreachable grant is `access_paused` (below) — a
        // definitive negative the agent must NEVER retry.
        Decision::FailClosed(FailReason::TokenExpired) => op_err(
            "token_expired",
            "access token expired against trusted server time",
        ),
        Decision::FailClosed(reason) => {
            op_err("access_paused", &format!("grant not live ({reason:?})"))
        }
        // on_grant_status never returns ReconfirmRequired; defensive.
        Decision::ReconfirmRequired => op_err("internal", "grant check did not resolve"),
    }
}

/// Build an [`OpErr`] response. Codes mirror the broker's agent-facing surface (`access_paused` is
/// the "ask your guardian to re-enable" state; §4.5).
fn op_err(code: &str, message: &str) -> Response {
    Response::Err(OpErr {
        code: code.to_string(),
        message: message.to_string(),
    })
}

/// Refuse any non-loopback bind address. The broker MUST never be routable — the S1
/// zero-access-under-server-compromise invariant (§8) rests on its inbound unreachability (a
/// compromised server holding K1+K2 could forge a cert+token but still cannot reach the local
/// broker). (#3 binds loopback only; the Apple-`container` host-private vmnet binding is a fast-follow
/// that relaxes this to "loopback or the configured host-only vmnet addr" — still never routable.)
fn assert_loopback(addr: SocketAddr) -> Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(CliError::new(
            70,
            "internal",
            format!(
                "broker bind address {addr} is not loopback: refusing (the broker only ever serves this Mac)"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    //! The §8 NORMATIVE build-gates for the listener: the concurrent multi-PRSN isolation gate (the
    //! #1 build risk — invariant #4), the leased revocation gates (cold-start / live / revoked), and
    //! a real mutual-TLS round-trip plus a rejected-cert handshake (the transport proof). The
    //! isolation and lease gates hammer [`handle_request`] directly (platform-independent — the
    //! `software` keystore, no real SE, no S3); the mTLS test stands up a real loopback listener.

    use super::*;
    use crate::keystore::{KeyLabel, KeyMeta, Keystore, SoftwareKeystore, Tier};
    use signet_channel::wire::{Op, OpOk};
    use std::sync::atomic::AtomicUsize;

    // ── Test PKI + token harness ───────────────────────────────────────────────

    /// A test deployment CA (K2).
    fn test_ca() -> ([u8; 32], Vec<u8>) {
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let der = signet_crypto::x509::build_ca_cert(&scalar, "Test Garnet CA", &[1], 315_360_000)
            .unwrap()
            .der;
        (scalar, der)
    }

    /// An enrolled agent: its client leaf (DER) + cnf thumbprint + PKCS#8 key, for `handle`.
    struct Agent {
        leaf_der: Vec<u8>,
        cnf: String,
        pkcs8: Vec<u8>,
    }

    fn issue_agent(ca_scalar: &[u8; 32], handle: &str, serial: u8) -> Agent {
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&scalar, "agent").unwrap();
        let leaf = signet_crypto::x509::issue_agent_cert(
            &csr,
            handle,
            ca_scalar,
            "Test Garnet CA",
            &[serial],
            604_800,
        )
        .unwrap();
        Agent {
            cnf: leaf.thumbprint_b64url.clone(),
            leaf_der: leaf.der,
            pkcs8: signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&scalar).unwrap(),
        }
    }

    /// Mint a `signet-broker`-audience token for `handle`, bound to `cnf`, signed by `k1_scalar`.
    fn broker_token(
        k1_scalar: &[u8; 32],
        k1_kid: Uuid,
        handle: &str,
        cnf: &str,
        grant: Uuid,
    ) -> String {
        let si = signet_crypto::garnet_token::encode_signing_input(
            k1_kid,
            signet_crypto::garnet_token::Audience::Broker,
            handle,
            cnf,
            grant,
            900,
            unix_now(),
        )
        .unwrap();
        let sig = signet_crypto::ecdsa::sign_es256(k1_scalar, si.as_bytes()).unwrap();
        use base64::Engine;
        format!(
            "{si}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
        )
    }

    /// Mint a `signet-broker`-audience token whose `exp` is already in the past (iat 2000s ago, ttl
    /// 900 ⇒ exp ≈ now-1100, beyond the 30s skew). Structurally valid (`verify_skipping_time` passes),
    /// so the ONLY gate it trips is the trusted-time expiry check — exercising the `token_expired` path.
    fn expired_broker_token(
        k1_scalar: &[u8; 32],
        k1_kid: Uuid,
        handle: &str,
        cnf: &str,
        grant: Uuid,
    ) -> String {
        let si = signet_crypto::garnet_token::encode_signing_input(
            k1_kid,
            signet_crypto::garnet_token::Audience::Broker,
            handle,
            cnf,
            grant,
            900,
            unix_now() - 2000,
        )
        .unwrap();
        let sig = signet_crypto::ecdsa::sign_es256(k1_scalar, si.as_bytes()).unwrap();
        use base64::Engine;
        format!(
            "{si}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
        )
    }

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn lease_cfg() -> LeaseConfig {
        LeaseConfig {
            lease: Duration::from_secs(30),
            outage_grace: Duration::from_secs(90),
            token_skew: Duration::from_secs(30),
        }
    }

    // ── A recording keystore: wraps `software`, counts/records SE accesses ──────

    struct RecordingKeystore {
        inner: SoftwareKeystore,
        /// The PRSN handle of every key a SE op (`generate`/`sign`/`ecdh`/`meta`/`delete`) reached —
        /// the cross-PRSN-access oracle (a foreign handle here would be an isolation breach).
        accessed: Mutex<Vec<String>>,
        /// Count of `sign` ops that actually reached the keystore.
        signs: AtomicUsize,
    }

    impl RecordingKeystore {
        fn new(dir: std::path::PathBuf) -> Self {
            Self {
                inner: SoftwareKeystore::open(dir).unwrap(),
                accessed: Mutex::new(Vec::new()),
                signs: AtomicUsize::new(0),
            }
        }
        fn record(&self, label: &KeyLabel) {
            self.accessed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(label.handle().to_string());
        }
    }

    impl Keystore for RecordingKeystore {
        fn tier(&self) -> Tier {
            self.inner.tier()
        }
        fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
            self.record(label);
            self.inner.generate(label, algorithm)
        }
        fn meta(&self, label: &KeyLabel) -> Result<KeyMeta> {
            self.record(label);
            self.inner.meta(label)
        }
        fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]> {
            self.record(label);
            self.signs.fetch_add(1, Ordering::Relaxed);
            self.inner.sign(label, msg)
        }
        fn ecdh(&self, label: &KeyLabel, peer: &[u8]) -> Result<[u8; 32]> {
            self.record(label);
            self.inner.ecdh(label, peer)
        }
        fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]> {
            self.record(label);
            self.inner.ml_kem_decapsulate(label, ek)
        }
        fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
            self.record(label);
            self.inner.ml_dsa_sign(label, msg, ctx)
        }
        fn list(&self) -> Result<Vec<KeyMeta>> {
            self.inner.list()
        }
        fn delete(&self, label: &KeyLabel) -> Result<()> {
            self.record(label);
            self.inner.delete(label)
        }
        fn exists(&self, label: &KeyLabel) -> Result<bool> {
            self.inner.exists(label)
        }
    }

    /// A programmable grant-status stub returning a fixed outcome (the isolation/lease gates drive
    /// the §6 wiring deterministically without network I/O).
    struct StubGrantStatus(GrantStatusOutcome);
    impl GrantStatusClient for StubGrantStatus {
        fn query(&self, _grant: Uuid, _handle: &str, _cnf: &str) -> GrantStatusOutcome {
            self.0
        }
    }

    /// Build a minimal `BrokerContext` for the direct-handler gates. `server_config` is required by
    /// the struct but unused by `handle_request`; we build a throwaway one.
    fn ctx<'a>(
        ca_der: &[u8],
        k1_pub: &'a [u8],
        grant_status: &'a dyn GrantStatusClient,
        keystore: &'a (dyn Keystore + Sync),
    ) -> BrokerContext<'a> {
        BrokerContext {
            server_config: throwaway_server_config(ca_der),
            k1_verify_key: k1_pub,
            grant_status,
            lease_cfg: lease_cfg(),
            keystore,
            leases: Mutex::new(HashMap::new()),
            se_lock: Mutex::new(()),
        }
    }

    /// A broker `ServerConfig` with a throwaway self-signed K3 identity (the handler tests don't use
    /// it; the mTLS test pins it on the client side).
    fn throwaway_server_config(ca_der: &[u8]) -> Arc<ServerConfig> {
        let (k3_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let k3 =
            signet_crypto::x509::build_ca_cert(&k3_scalar, "Test Broker", &[7], 86_400).unwrap();
        let key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();
        crate::broker_tls::broker_server_config(
            ca_der.to_vec(),
            vec![rustls::pki_types::CertificateDer::from(k3.der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
        )
        .unwrap()
    }

    // ── The NORMATIVE isolation gate (invariant #4) ────────────────────────────

    #[test]
    fn no_cross_prsn_se_access_under_concurrency() {
        // N distinct-handle agents, each with a seeded signing key + a broker token. M threads hammer
        // interleaved HONEST (own-handle label) and MALICIOUS (sibling-handle label) Sign ops. The
        // gate: no op ever touches a non-`sub` key, every honest signature verifies under its OWN
        // handle's key (the cross-key detector), every malicious op is refused, and the count of SE
        // signs equals exactly the honest requests (no malicious op reached the SE).
        const N: usize = 6;
        const THREADS: usize = 24;
        const ITERS: usize = 40;

        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();
        let dir = tempfile::tempdir().unwrap();
        let ks = RecordingKeystore::new(dir.path().to_path_buf());

        // Per handle: seed its signing key (so honest ops succeed) + record its pubkey; mint an agent
        // + a broker token bound to that agent's cnf.
        struct Subject {
            handle: String,
            pubkey: Vec<u8>,
            cnf: String,
            token: String,
        }
        let mut subjects = Vec::new();
        for i in 0..N {
            let handle = format!("agent{i}-ai");
            let label = KeyLabel::parse(&format!("{handle}-signing"), None).unwrap();
            let meta = ks.inner.generate(&label, "ES256").unwrap();
            let agent = issue_agent(&ca_scalar, &handle, i as u8 + 10);
            let token = broker_token(&k1_scalar, k1_kid, &handle, &agent.cnf, Uuid::new_v4());
            subjects.push(Subject {
                handle,
                pubkey: meta.public_key,
                cnf: agent.cnf,
                token,
            });
        }

        let grant_status = StubGrantStatus(GrantStatusOutcome::live(unix_now()));
        let context = ctx(&ca_der, &k1_pub, &grant_status, &ks);

        let msg = b"isolation probe";
        let honest_count = AtomicUsize::new(0);

        std::thread::scope(|s| {
            for t in 0..THREADS {
                let subjects = &subjects;
                let context = &context;
                let honest_count = &honest_count;
                s.spawn(move || {
                    for k in 0..ITERS {
                        let i = (t + k) % N;
                        let conn = &subjects[i];
                        let honest = k % 2 == 0;
                        let label_handle = if honest {
                            conn.handle.clone()
                        } else {
                            subjects[(i + 1) % N].handle.clone() // a sibling's handle
                        };
                        let req = BrokerRequest {
                            token: conn.token.clone(),
                            op: Op::Sign {
                                label: format!("{label_handle}-signing"),
                                msg: msg.to_vec(),
                            },
                        };
                        let resp = handle_request(&conn.handle, &conn.cnf, req, context);
                        if honest {
                            honest_count.fetch_add(1, Ordering::Relaxed);
                            match resp {
                                Response::Ok(OpOk::Sign { signature }) => {
                                    let sig: [u8; 64] = signature.try_into().unwrap();
                                    // The cross-key detector: an honest op MUST use the conn's OWN key.
                                    signet_crypto::ecdsa::verify_es256(&conn.pubkey, msg, &sig)
                                        .expect(
                                            "honest signature verifies under the conn's own key",
                                        );
                                }
                                other => panic!("honest op should serve, got {other:?}"),
                            }
                        } else {
                            // A sibling-handle label on this connection MUST be refused before the SE.
                            match resp {
                                Response::Err(OpErr { code, .. }) => {
                                    assert_eq!(code, "authorization_denied")
                                }
                                other => {
                                    panic!("malicious cross-label must be refused, got {other:?}")
                                }
                            }
                        }
                    }
                });
            }
        });

        // No malicious op reached the SE: the count of SE signs equals exactly the honest requests.
        assert_eq!(
            ks.signs.load(Ordering::Relaxed),
            honest_count.load(Ordering::Relaxed),
            "exactly the honest ops reached the SE — no cross-PRSN access"
        );
        // Every handle the SE ever served is a legitimate subject handle (no foreign handle slipped
        // through as an SE access).
        let valid: std::collections::HashSet<String> =
            subjects.iter().map(|s| s.handle.clone()).collect();
        for h in ks.accessed.lock().unwrap().iter() {
            assert!(valid.contains(h), "SE served an unexpected handle: {h}");
        }
    }

    // ── The leased revocation gates (the §6 wiring) ────────────────────────────

    fn one_subject_request() -> (
        [u8; 32], // ca_scalar
        Vec<u8>,  // ca_der
        Vec<u8>,  // k1_pub
        String,   // cnf
        BrokerRequest,
        tempfile::TempDir,
    ) {
        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();
        let agent = issue_agent(&ca_scalar, "solo-ai", 42);
        let token = broker_token(&k1_scalar, k1_kid, "solo-ai", &agent.cnf, Uuid::new_v4());
        let dir = tempfile::tempdir().unwrap();
        // pass k1_scalar back is not needed; capture k1_pub.
        let req = BrokerRequest {
            token,
            op: Op::Keygen {
                label: "solo-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        };
        (ca_scalar, ca_der, k1_pub, agent.cnf, req, dir)
    }

    #[test]
    fn cold_start_and_unreachable_fail_closed() {
        let (_ca_scalar, ca_der, k1_pub, cnf, req, dir) = one_subject_request();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        let gs = StubGrantStatus(GrantStatusOutcome::Unreachable);
        let context = ctx(&ca_der, &k1_pub, &gs, &ks);
        match handle_request("solo-ai", &cnf, req, &context) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "access_paused"),
            other => panic!("cold-start + unreachable must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn revoked_fails_closed_immediately() {
        let (_ca_scalar, ca_der, k1_pub, cnf, req, dir) = one_subject_request();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        let gs = StubGrantStatus(GrantStatusOutcome::Revoked);
        let context = ctx(&ca_der, &k1_pub, &gs, &ks);
        match handle_request("solo-ai", &cnf, req, &context) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "access_paused"),
            other => panic!("a revoked grant must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_on_a_live_grant_is_token_expired_not_access_paused() {
        // The host-clock-skew case: the grant is LIVE, but the presented token expired against the
        // broker's trusted server time. The broker reports `token_expired` (a renewable
        // re-authenticate condition the agent's BrokerKeystore retries once with a fresh token) —
        // NOT `access_paused`, which is reserved for definitive negatives (revoked / unconfirmed /
        // unreachable) that must never be retried. This is the distinction that makes the reactive
        // renew-and-retry both effective (it fires here) and safe (it never re-hammers a revoke).
        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();
        let agent = issue_agent(&ca_scalar, "solo-ai", 42);
        let token = expired_broker_token(&k1_scalar, k1_kid, "solo-ai", &agent.cnf, Uuid::new_v4());
        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        // A *live* grant (server reachable, active) — so the only gate that can trip is token expiry.
        let gs = StubGrantStatus(GrantStatusOutcome::live(unix_now()));
        let context = ctx(&ca_der, &k1_pub, &gs, &ks);
        let req = BrokerRequest {
            token,
            op: Op::Keygen {
                label: "solo-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        };
        match handle_request("solo-ai", &agent.cnf, req, &context) {
            Response::Err(OpErr { code, .. }) => assert_eq!(
                code, "token_expired",
                "an expired token on a live grant is a renewable re-authenticate condition"
            ),
            other => panic!("an expired token must be reported as token_expired, got {other:?}"),
        }
    }

    #[test]
    fn live_grant_serves_the_op() {
        let (_ca_scalar, ca_der, k1_pub, cnf, req, dir) = one_subject_request();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        let gs = StubGrantStatus(GrantStatusOutcome::live(unix_now()));
        let context = ctx(&ca_der, &k1_pub, &gs, &ks);
        match handle_request("solo-ai", &cnf, req, &context) {
            Response::Ok(OpOk::Keygen { public_key, .. }) => assert_eq!(public_key.len(), 65),
            other => panic!("a live grant should serve the keygen, got {other:?}"),
        }
    }

    #[test]
    fn wrong_cert_token_is_rejected() {
        // A valid token presented over a DIFFERENT agent's cert (the PoP boundary): the cnf the broker
        // computes from the connection leaf differs from the token's bound cnf → reject.
        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();
        let a = issue_agent(&ca_scalar, "solo-ai", 1);
        let b = issue_agent(&ca_scalar, "solo-ai", 2); // same handle, different key → different cnf
        let token = broker_token(&k1_scalar, k1_kid, "solo-ai", &a.cnf, Uuid::new_v4());
        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        let gs = StubGrantStatus(GrantStatusOutcome::live(unix_now()));
        let context = ctx(&ca_der, &k1_pub, &gs, &ks);
        let req = BrokerRequest {
            token,
            op: Op::Keygen {
                label: "solo-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        };
        // Present it over agent B's cnf (the leaf the "connection" authenticated).
        match handle_request("solo-ai", &b.cnf, req, &context) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "unauthorized"),
            other => panic!("a token bound to another cert must be rejected, got {other:?}"),
        }
    }

    // ── The real mutual-TLS transport proof ────────────────────────────────────

    #[test]
    fn mtls_round_trip_and_rejected_cert() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();

        // The broker's K3 server identity (a throwaway self-signed cert the client pins).
        let (k3_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let k3 =
            signet_crypto::x509::build_ca_cert(&k3_scalar, "Test Broker", &[7], 86_400).unwrap();
        let k3_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();
        let server_config = crate::broker_tls::broker_server_config(
            ca_der.clone(),
            vec![CertificateDer::from(k3.der.clone())],
            PrivateKeyDer::Pkcs8(k3_key.into()),
        )
        .unwrap();

        // An enrolled agent + its broker token (a live grant via the stub → the op serves).
        let agent = issue_agent(&ca_scalar, "wire-ai", 5);
        let token = broker_token(&k1_scalar, k1_kid, "wire-ai", &agent.cnf, Uuid::new_v4());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let grant_status: Arc<dyn GrantStatusClient> =
            Arc::new(StubGrantStatus(GrantStatusOutcome::live(unix_now())));
        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();

        std::thread::scope(|s| {
            s.spawn(|| {
                serve_on(
                    listener,
                    server_config,
                    k1_pub.clone(),
                    grant_status,
                    lease_cfg(),
                    &ks,
                    &shutdown,
                )
                .unwrap();
            });

            // (a) An honest mTLS client (valid K4 cert + token) → the keygen serves.
            let client = mtls_client(&k3.der, &agent.leaf_der, &agent.pkcs8);
            let resp = mtls_request(
                addr,
                client,
                &BrokerRequest {
                    token: token.clone(),
                    op: Op::Keygen {
                        label: "wire-ai-signing".into(),
                        algorithm: "ES256".into(),
                    },
                },
            );
            match resp {
                Some(Response::Ok(OpOk::Keygen { public_key, .. })) => {
                    assert_eq!(public_key.len(), 65)
                }
                other => panic!("honest mTLS keygen should serve, got {other:?}"),
            }

            // (b) A client cert from a DIFFERENT CA → the handshake is rejected (no response).
            let (other_ca_scalar, _) = test_ca();
            let imposter = issue_agent(&other_ca_scalar, "wire-ai", 9);
            let client2 = mtls_client(&k3.der, &imposter.leaf_der, &imposter.pkcs8);
            let resp2 = mtls_request(
                addr,
                client2,
                &BrokerRequest {
                    token,
                    op: Op::Keygen {
                        label: "wire-ai-signing".into(),
                        algorithm: "ES256".into(),
                    },
                },
            );
            assert!(
                resp2.is_none(),
                "a client cert not chaining to K2 must fail the handshake"
            );

            shutdown.store(true, Ordering::Relaxed);
            // Nudge a final accept so a worker observes the shutdown promptly.
            let _ = TcpStream::connect(addr);
        });
    }

    /// The **custom K3 signer** path (the Secure-Enclave home) proven through a real mutual-TLS
    /// handshake — the CI proof for the SE key home, decorrelated from the hardware. The server
    /// config is built via [`broker_tls::broker_server_config_with_signing_key`] with a
    /// `BrokerK3SigningKey` whose backend is a **raw scalar** (the SE-`sign` leg itself is proven on
    /// device, #208-style); the client verifies the server's `CertificateVerify` against K3's public
    /// key, so a successful handshake means the custom signer produced a valid ECDSA-P256 signature.
    #[test]
    fn mtls_round_trip_se_signer() {
        use rustls::pki_types::CertificateDer;

        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();

        // The broker's K3 identity: a cert whose key is k3_scalar, served by the CUSTOM signer
        // (the SE path) with a raw-scalar backend standing in for the enclave.
        let (k3_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let k3 =
            signet_crypto::x509::build_ca_cert(&k3_scalar, "Test Broker", &[8], 86_400).unwrap();
        let signing_key: Arc<dyn rustls::sign::SigningKey> =
            Arc::new(crate::broker_transport_key::BrokerK3SigningKey::new(
                Arc::new(crate::broker_transport_key::RawEs256Signer::new(k3_scalar)),
            ));
        let server_config = crate::broker_tls::broker_server_config_with_signing_key(
            ca_der.clone(),
            vec![CertificateDer::from(k3.der.clone())],
            signing_key,
        )
        .unwrap();

        let agent = issue_agent(&ca_scalar, "wire-ai", 8);
        let token = broker_token(&k1_scalar, k1_kid, "wire-ai", &agent.cnf, Uuid::new_v4());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let grant_status: Arc<dyn GrantStatusClient> =
            Arc::new(StubGrantStatus(GrantStatusOutcome::live(unix_now())));
        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();

        std::thread::scope(|s| {
            s.spawn(|| {
                serve_on(
                    listener,
                    server_config,
                    k1_pub.clone(),
                    grant_status,
                    lease_cfg(),
                    &ks,
                    &shutdown,
                )
                .unwrap();
            });

            // The handshake's server CertificateVerify is produced by the custom signer; the client
            // verifies it against K3's public key. A served keygen ⇒ the signer works end-to-end.
            let client = mtls_client(&k3.der, &agent.leaf_der, &agent.pkcs8);
            let resp = mtls_request(
                addr,
                client,
                &BrokerRequest {
                    token,
                    op: Op::Keygen {
                        label: "wire-ai-signing".into(),
                        algorithm: "ES256".into(),
                    },
                },
            );
            match resp {
                Some(Response::Ok(OpOk::Keygen { public_key, .. })) => {
                    assert_eq!(public_key.len(), 65)
                }
                other => {
                    panic!("the custom-signer handshake should serve the keygen, got {other:?}")
                }
            }

            shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(addr);
        });
    }

    /// The **`BrokerKeystore` cutover** proven end-to-end: the full `Keystore` trait forwarded over a
    /// real mutual-TLS broker to a (software, for CI) SE-backend — the live PRSN-access path (S094).
    /// The credential carries a fresh broker token, so no renewal fires here (the lazy-renewal path is
    /// proven against the real token endpoint in `garnet_command_e2e`); this proves the op mapping +
    /// faithful exit-code re-raising, the same contract `full_delegation_round_trip` proves for the mount.
    #[test]
    fn broker_keystore_round_trips_the_full_trait() {
        use crate::garnet_credential::PoPCredential;
        use crate::keystore::{BrokerKeystore, Purpose};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let handle = "wire-ai";
        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();
        let (ca_scalar, ca_der) = test_ca();

        // The broker's K3 server identity: a K2-signed serverAuth leaf; the agent pins its SPKI.
        let (k3_scalar, k3_pub) = signet_crypto::ecdsa::generate_keypair();
        let k3 = signet_crypto::x509::build_server_leaf(
            &k3_pub,
            "test-broker",
            &ca_scalar,
            "Test Garnet CA",
            &[7],
            86_400,
        )
        .unwrap();
        let k3_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();
        let broker_spki_pin = signet_crypto::x509::cert_spki_sha256_b64url(&k3.der).unwrap();
        let server_config = crate::broker_tls::broker_server_config(
            ca_der.clone(),
            vec![CertificateDer::from(k3.der.clone())],
            PrivateKeyDer::Pkcs8(k3_key.into()),
        )
        .unwrap();

        // The agent's K4 identity + a fresh broker token, assembled into a persisted PoP credential.
        let agent = issue_agent(&ca_scalar, handle, 5);
        let token = broker_token(&k1_scalar, k1_kid, handle, &agent.cnf, Uuid::new_v4());
        let mut cred = PoPCredential::new(
            handle,
            agent.pkcs8.clone(),
            agent.leaf_der.clone(),
            ca_der.clone(),
            broker_spki_pin,
            "https://127.0.0.1:8443", // unused: the token is fresh, so no renewal fires
            "unused-server-token",
        );
        cred.set_broker_token(token);
        let cred_dir = tempfile::tempdir().unwrap();
        let cred_path = cred_dir
            .path()
            .join("garnet")
            .join(format!("{handle}.json"));
        cred.save(&cred_path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let grant_status: Arc<dyn GrantStatusClient> =
            Arc::new(StubGrantStatus(GrantStatusOutcome::live(unix_now())));
        let ks_dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(ks_dir.path().to_path_buf()).unwrap();

        std::thread::scope(|s| {
            s.spawn(|| {
                serve_on(
                    listener,
                    server_config,
                    k1_pub.clone(),
                    grant_status,
                    lease_cfg(),
                    &ks,
                    &shutdown,
                )
                .unwrap();
            });

            let bks = BrokerKeystore::open(addr, cred_path.clone()).unwrap();
            let signing = KeyLabel::from_handle(handle, Purpose::Signing).unwrap();
            let kem = KeyLabel::from_handle(handle, Purpose::Kem).unwrap();

            // generate → the op runs in the (software) SE-backend and reports the SE tier.
            let sm = bks.generate(&signing, "ES256").unwrap();
            assert_eq!(sm.storage, "secure-enclave");
            assert_eq!(sm.public_key.len(), 65);
            let km = bks.generate(&kem, "ECDH-ES+A256KW").unwrap();

            // sign verifies under the returned pubkey.
            let msg = b"broker keystore round-trip";
            let sig = bks.sign(&signing, msg).unwrap();
            signet_crypto::ecdsa::verify_es256(&sm.public_key, msg, &sig).unwrap();

            // ecdh agrees with the peer-side computation (the file-decrypt path).
            let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
            let z = bks.ecdh(&kem, &eph_pub).unwrap();
            let z_peer = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &km.public_key).unwrap();
            assert_eq!(z, z_peer);

            // exists / list / delete — all reporting the SE tier.
            assert!(bks.exists(&signing).unwrap());
            let listed = bks.list().unwrap();
            assert!(listed.iter().any(|m| m.label == "wire-ai-signing"));
            assert!(listed.iter().all(|m| m.storage == "secure-enclave"));
            bks.delete(&signing).unwrap();
            assert!(!bks.exists(&signing).unwrap());

            // A failure re-raises with the faithful exit code (a deleted key → key_not_found / exit 12,
            // the same as the native + mount paths).
            let err = bks.sign(&signing, msg).unwrap_err();
            assert_eq!(err.code, "key_not_found");
            assert_eq!(err.exit_code, 12);

            shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(addr);
        });
    }

    /// A test-only rustls client: pins the broker's K3 server cert by exact DER, presents the agent's
    /// K4 client cert + key. TLS 1.3, aws-lc-rs provider, P-256 schemes.
    fn mtls_client(
        pinned_server_der: &[u8],
        client_leaf: &[u8],
        client_pkcs8: &[u8],
    ) -> rustls::ClientConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let algs = provider.signature_verification_algorithms;
        let verifier = Arc::new(PinnedServerVerifier {
            pinned: pinned_server_der.to_vec(),
            algs,
        });
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                vec![CertificateDer::from(client_leaf.to_vec())],
                PrivateKeyDer::Pkcs8(client_pkcs8.to_vec().into()),
            )
            .unwrap()
    }

    /// Connect, present the client cert, send `req`, read the response. `None` if the handshake or IO
    /// failed (e.g. a rejected client cert).
    fn mtls_request(
        addr: SocketAddr,
        config: rustls::ClientConfig,
        req: &BrokerRequest,
    ) -> Option<Response> {
        use rustls::pki_types::ServerName;
        let mut sock = TcpStream::connect(addr).ok()?;
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let name = ServerName::try_from("broker.local").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).ok()?;
        if conn.complete_io(&mut sock).is_err() || conn.is_handshaking() {
            return None;
        }
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        crate::broker_wire::write_frame(&mut tls, req).ok()?;
        crate::broker_wire::read_frame(&mut tls).ok()
    }

    #[derive(Debug)]
    struct PinnedServerVerifier {
        pinned: Vec<u8>,
        algs: rustls::crypto::WebPkiSupportedAlgorithms,
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            if end_entity.as_ref() == self.pinned.as_slice() {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &rustls::pki_types::CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Err(rustls::Error::General("tls1.2 unsupported".into()))
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }
}
