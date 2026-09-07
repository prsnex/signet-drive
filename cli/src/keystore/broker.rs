// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The `secure_enclave` keystore via the **Garnet SE-broker** — the live PRSN-access path (S094).
//!
//! This is the cutover: with a broker configured (`SIGNET_BROKER_ADDR`), every `signet` crypto op
//! (`sign`, `keygen`, `ecdh`, …) is forwarded to the local SE-broker ([`crate::broker`]) over
//! mutual-TLS, which performs it in the host Mac's Secure Enclave for the authenticated handle and
//! returns the result — exactly as the mount ([`DelegatedKeystore`](super::delegated::DelegatedKeystore))
//! forwards to the host-signer over its channel. The agent holds no keys; it reports
//! `key_protection = secure_enclave` (the keys live in *an* SE, the host's). [`keystore::open`](super)
//! selects this backend **before** the mount, which stays present-but-inactive as the fallback until
//! Garnet is proven on Staging.
//!
//! **Two things this backend owns that the mount does not:**
//!
//! * **Proof-of-possession, not a shared secret.** Each op rides the agent's cert-bound broker token
//!   inside the K2-pinned mutual-TLS connection (the broker verifies `alg`/`typ`/`kid`/`cnf`/`sub`/
//!   `aud`/`exp` and the live grant per §3/§6). The identity is the K4 cert's SAN handle, which the
//!   broker enforces against the token `sub` and the server-built SE-key label (the §7 triple) — so
//!   this backend does no per-op label trust; it names its own labels from the credential handle.
//! * **Lazy token renewal.** The broker-audience token is short-lived (§3). This backend renews it
//!   at op-time when it is absent or near expiry (the spec's *lazy / activity-gated* renewal — an
//!   idle PRSN renews nothing), over the Garnet ingress the server advertised at pickup, and persists
//!   the fresh token so the next invocation reuses it. A renewal re-checks the live grant server-side
//!   (a revoked/unconfirmed grant cannot renew), and the first broker token is mintable only after
//!   the guardian hard-confirms (§7) — so a pre-confirm PRSN gets a clear "awaiting confirmation"
//!   error, never an SE op.
//!
//! Belt-and-suspenders: two broker rejections are transient-and-renewable, and each triggers a single
//! force-renew-and-retry — `token_expired` (the token expired against the broker's *trusted server
//! time* even though the agent's own near-expiry check judged it still fresh: the host-clock-skew case,
//! where the agent's clock runs behind the server's) and `unauthorized` (a structural token failure a
//! fresh token can fix — e.g. a K1 rotation the agent's cached token predates).
//!
//! A *revoked* / unconfirmed / unreachable grant surfaces as `access_paused` (from the broker's
//! check-at-use) or `token_denied` (the server refusing this credential's token mint). **bug114
//! Part F (S156, Chris — Option A):** that state MAY mean the guardian revoked and RE-AUTHORIZED
//! (a fresh grant sits in `pickup_wait` — live-verified S156: the old credential fails definitively
//! while `signet garnet pickup` recovers cleanly), so it triggers **ONE** signed re-pickup + one
//! retry, the exact bug090 recovery shape with a second trigger. If no fresh grant awaits, the
//! re-pickup is refused and the ORIGINAL definitive error stands — whose "ask your guardian to
//! re-enable" guidance is then correct by construction (reaching it proves no fresh grant exists).
//! Guarded once-per-keystore (no retry storm; the server's per-PRSN pickup rate cap bounds the
//! cross-invocation case). A genuinely-paused grant is still never re-hammered: one check, then
//! definitive.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use signet_channel::wire::{Op, OpOk, Response};

use super::{
    KeyLabel, KeyMeta, Keystore, Tier, check_identity_match, cli_error_from_wire, unexpected,
};
use crate::broker_client::BrokerClient;
use crate::error::{CliError, Result};
use crate::garnet_credential::PoPCredential;

/// Renew the broker token this many seconds *before* its `exp` (the lazy-renewal lead). Generous
/// against host-clock skew vs the broker's trusted-time check (the broker's own `token_skew` is 30s);
/// a larger skew (the agent's clock running >~150s behind the server) is caught reactively — the
/// broker answers `token_expired` and [`BrokerKeystore::perform_op`] force-renews and retries.
const RENEW_MARGIN_SECS: i64 = 120;

/// The Garnet-broker keystore. Holds no key material — the [`BrokerClient`] (the agent's mutual-TLS
/// identity; behind a mutex so the bug090 pin-refresh can rebuild it in place) + the
/// [`PoPCredential`] behind a mutex (its broker token is renewed + persisted in place).
pub struct BrokerKeystore {
    client: Mutex<BrokerClient>,
    addr: SocketAddr,
    credential_path: PathBuf,
    cred: Mutex<PoPCredential>,
    /// bug114 Part F: whether the ONE-per-keystore re-auth recovery (paused/refused grant →
    /// signed re-pickup) has been spent. Never reset — a second pause in the same process is
    /// definitive (see [`recovery_for`]).
    reauth_attempted: AtomicBool,
}

impl BrokerKeystore {
    /// Open the broker keystore: load the agent's PoP credential, **cross-check** its cryptographic
    /// handle against the harness-asserted `SIGNET_HANDLE` (defense-in-depth — the broker enforces the
    /// same via the §7 triple, but a mis-wired `SIGNET_BROKER_CREDENTIAL` is caught here, fail-closed),
    /// and build the K2-pinned mutual-TLS client to the loopback broker.
    pub fn open(broker_addr: SocketAddr, credential_path: PathBuf) -> Result<Self> {
        let cred = PoPCredential::load(&credential_path)?;
        // Bug037 (i): self-extend the K4 cert when past half its life (best-effort;
        // BEFORE the mutual-TLS client below is built, so it rides the fresh leaf).
        let cred = crate::garnet::auto_renew_cert_if_due(&credential_path, cred);
        // The credential's handle is its own, cryptographically-bound identity (the K4 leaf SAN). If
        // the harness asserts a handle, it MUST match — else this is a mis-mapped credential.
        let asserted = std::env::var("SIGNET_HANDLE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        check_identity_match(Some(&cred.handle), asserted.as_deref())?;

        let client = BrokerClient::new(broker_addr, &cred)?;
        Ok(Self {
            client: Mutex::new(client),
            addr: broker_addr,
            credential_path,
            cred: Mutex::new(cred),
            reauth_attempted: AtomicBool::new(false),
        })
    }

    /// **The bug090 pin refresh: recover from a re-provisioned broker with ONE signed
    /// re-pickup.** Fires only on the distinct `broker_pin_mismatch` failure (a K2-chained
    /// broker presenting a non-pinned SPKI — the rotated-K3 signature; a down broker or a
    /// rejected agent cert never reaches here). The re-pickup is the v09 re-issue path:
    /// signature-authenticated against the server (the same guardian→server→agent authority
    /// the original pin came from — a local rogue broker cannot influence it), it re-fetches
    /// the broker's CURRENT pin, rotates K4, and is LOUD by construction (the server audits
    /// it to both parties and the pickup prints the takeover-signal line). The refreshed
    /// credential + rebuilt mTLS client replace this keystore's in place; the caller retries
    /// the op once.
    fn refresh_pin_by_repickup(&self) -> Result<()> {
        let handle = self.credential_handle();
        eprintln!(
            "signet: the broker's identity changed (it no longer matches this credential's \
             pin: a re-provisioned broker); refreshing the credential for '{handle}' by \
             signed pickup…"
        );
        self.repickup_and_reload(&handle)
    }

    /// **The bug114 Part-F re-auth recovery: recover from a paused/refused grant with ONE
    /// signed re-pickup.** Fires on `access_paused` / `token_denied` — the credential's grant
    /// is not serving, which after a guardian **re-authorize** (revoke → fresh grant in
    /// `pickup_wait`) is exactly the state the old credential is stuck in (live-verified
    /// S156). The re-pickup is the same signature-authenticated engine as the bug090 pin
    /// refresh: if a fresh grant awaits, it binds + auto-confirms it (a first CSR bind, so no
    /// false takeover warning) and the caller retries once; if the grant is genuinely paused
    /// (no fresh grant), the server refuses the pickup and the caller re-raises the ORIGINAL
    /// definitive error, whose guidance is then correct by construction.
    fn refresh_authorization_by_repickup(&self) -> Result<()> {
        let handle = self.credential_handle();
        eprintln!(
            "signet: access is paused for '{handle}'. Checking whether your guardian \
             re-authorized (one signed pickup)…"
        );
        self.repickup_and_reload(&handle)?;
        eprintln!("signet: re-authorized. Reconnected as '{handle}' with a fresh credential.");
        Ok(())
    }

    /// The credential's own cryptographically-bound handle (the K4 leaf SAN) — never the
    /// environment's.
    fn credential_handle(&self) -> String {
        let cred = self.cred.lock().unwrap_or_else(|e| e.into_inner());
        cred.handle.clone()
    }

    /// The ONE shared re-pickup engine both recoveries drive (bug090 pin-refresh + bug114
    /// re-auth — the S127 one-home rule): a signed re-pickup for this credential's own
    /// handle (the v09 path — server-audited to both parties; loud on an actual re-issue),
    /// then reload the refreshed credential and rebuild the mTLS client in place.
    fn repickup_and_reload(&self, handle: &str) -> Result<()> {
        let config = crate::config::Config::load()?;
        crate::garnet::refresh_pickup(&config, handle, &self.credential_path)?;
        let fresh = PoPCredential::load(&self.credential_path)?;
        let client = BrokerClient::new(self.addr, &fresh)?;
        *self.client.lock().unwrap_or_else(|e| e.into_inner()) = client;
        *self.cred.lock().unwrap_or_else(|e| e.into_inner()) = fresh;
        Ok(())
    }

    /// Ensure a usable broker-audience token, renewing it when `force` (a reactive retry), or when it
    /// is absent or within [`RENEW_MARGIN_SECS`] of expiry (proactive lazy renewal). A fresh token is
    /// persisted to the credential file so the next process reuses it. Returns the token to present.
    fn ensure_broker_token(&self, force: bool) -> Result<String> {
        let mut cred = self.cred.lock().unwrap_or_else(|e| e.into_inner());
        let stale = match cred.broker_token() {
            None => true,
            Some(tok) => token_near_expiry(tok),
        };
        if force || stale {
            let token_url = cred.grant_status_url().to_string();
            // "signet-broker" is the broker-audience wire value (Auth-Core §3). A renewal re-checks the
            // live grant + `enrollment_confirmed` server-side; a pre-confirm grant is refused here.
            let token = crate::garnet::request_token(&token_url, &cred, "signet-broker")?;
            cred.set_broker_token(token);
            cred.save(&self.credential_path)?;
        }
        // Present: just ensured non-None on the renewal branch; on the not-stale branch it was Some.
        cred.broker_token()
            .map(str::to_string)
            .ok_or_else(|| CliError::generic("broker token unavailable after renewal"))
    }

    /// Perform one op over the broker: present a fresh (lazily-renewed) token; on a `token_expired` or
    /// `unauthorized` rejection (both renewable — see the module doc), force-renew once and retry; on
    /// a `broker_pin_mismatch` transport failure (bug090 — a re-provisioned broker), refresh the pin
    /// by ONE signed re-pickup and retry once; on an `access_paused` / `token_denied` grant refusal
    /// (bug114 Part F — possibly a guardian re-authorize), attempt ONE signed re-pickup (per keystore,
    /// [`recovery_for`]) and retry once, re-raising the ORIGINAL error if no fresh grant awaits. Any
    /// other failure is re-raised immediately with its faithful exit code.
    fn perform_op(&self, op: Op) -> Result<OpOk> {
        match self.perform_op_inner(op.clone()) {
            Err(e) => match recovery_for(e.code, &self.reauth_attempted) {
                Recovery::PinRefresh => {
                    self.refresh_pin_by_repickup()?;
                    self.perform_op_inner(op)
                }
                Recovery::ReauthOnce => match self.refresh_authorization_by_repickup() {
                    Ok(()) => self.perform_op_inner(op),
                    Err(_) => {
                        // No fresh grant: the pickup was refused. The ORIGINAL definitive
                        // error (faithful code + exit) stands — its "ask your guardian to
                        // re-enable" guidance is now correct by construction.
                        eprintln!("signet: no new authorization found. Access remains paused.");
                        Err(e)
                    }
                },
                Recovery::None => Err(e),
            },
            ok => ok,
        }
    }

    /// One token-managed attempt (the pre-bug090 `perform_op` body).
    fn perform_op_inner(&self, op: Op) -> Result<OpOk> {
        let token = self.ensure_broker_token(false)?;
        match self.perform_wire(&token, op.clone())? {
            Response::Ok(ok) => Ok(ok),
            Response::Err(e) if e.code == "token_expired" || e.code == "unauthorized" => {
                let token = self.ensure_broker_token(true)?;
                match self.perform_wire(&token, op)? {
                    Response::Ok(ok) => Ok(ok),
                    Response::Err(e) => Err(cli_error_from_wire(&e.code, e.message)),
                }
            }
            Response::Err(e) => Err(cli_error_from_wire(&e.code, e.message)),
        }
    }

    /// One wire round-trip under the (refreshable) client lock — the lock scope is the single
    /// op, so a concurrent pin refresh swaps the client between ops, never under one.
    fn perform_wire(&self, token: &str, op: Op) -> Result<Response> {
        self.client
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .perform(token, op)
    }

    /// Rebuild a [`KeyMeta`] from wire fields, stamping `storage` with the SE tier (the keys are in
    /// the host SE, reached via the broker) — mirrors the delegated backend.
    fn meta_from(
        &self,
        label: String,
        purpose: String,
        algorithm: String,
        fingerprint: String,
        public_key: Vec<u8>,
    ) -> KeyMeta {
        KeyMeta {
            label,
            purpose,
            algorithm,
            storage: Tier::SecureEnclave.as_str().to_string(),
            fingerprint,
            public_key,
        }
    }
}

impl Keystore for BrokerKeystore {
    fn tier(&self) -> Tier {
        Tier::SecureEnclave
    }

    fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
        match self.perform_op(Op::Keygen {
            label: label.full(),
            algorithm: algorithm.to_string(),
        })? {
            OpOk::Keygen {
                public_key,
                fingerprint,
                algorithm,
            } => Ok(self.meta_from(
                label.full(),
                label.purpose().as_str().to_string(),
                algorithm,
                fingerprint,
                public_key,
            )),
            other => Err(unexpected(&other)),
        }
    }

    fn meta(&self, label: &KeyLabel) -> Result<KeyMeta> {
        match self.perform_op(Op::Meta {
            label: label.full(),
        })? {
            OpOk::Meta {
                public_key,
                fingerprint,
                algorithm,
                purpose,
            } => Ok(self.meta_from(label.full(), purpose, algorithm, fingerprint, public_key)),
            other => Err(unexpected(&other)),
        }
    }

    fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]> {
        match self.perform_op(Op::Sign {
            label: label.full(),
            msg: msg.to_vec(),
        })? {
            OpOk::Sign { signature } => signature
                .try_into()
                .map_err(|_| CliError::generic("broker returned a non-64-byte signature")),
            other => Err(unexpected(&other)),
        }
    }

    fn ecdh(&self, label: &KeyLabel, peer_pub_x963: &[u8]) -> Result<[u8; 32]> {
        match self.perform_op(Op::Ecdh {
            label: label.full(),
            peer_pub_x963: peer_pub_x963.to_vec(),
        })? {
            OpOk::Ecdh { shared_secret } => shared_secret
                .try_into()
                .map_err(|_| CliError::generic("broker returned a non-32-byte shared secret")),
            other => Err(unexpected(&other)),
        }
    }

    fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]> {
        match self.perform_op(Op::MlKemDecapsulate {
            label: label.full(),
            ek: ek.to_vec(),
        })? {
            OpOk::MlKemDecapsulate { shared_secret } => shared_secret.try_into().map_err(|_| {
                CliError::generic("broker returned a non-32-byte ml-kem shared secret")
            }),
            other => Err(unexpected(&other)),
        }
    }

    fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        crate::keystore::validate_mldsa_ctx(ctx)?;
        match self.perform_op(Op::MlDsaSign {
            label: label.full(),
            msg: msg.to_vec(),
            ctx: ctx.to_vec(),
        })? {
            OpOk::MlDsaSign { signature } => {
                if signature.len() != crate::keystore::ML_DSA_87_SIG_LEN {
                    return Err(CliError::generic(format!(
                        "broker returned a {}-byte ml-dsa signature (expected {})",
                        signature.len(),
                        crate::keystore::ML_DSA_87_SIG_LEN
                    )));
                }
                Ok(signature)
            }
            other => Err(unexpected(&other)),
        }
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        match self.perform_op(Op::List)? {
            OpOk::List { keys } => Ok(keys
                .into_iter()
                .map(|k| {
                    self.meta_from(k.label, k.purpose, k.algorithm, k.fingerprint, k.public_key)
                })
                .collect()),
            other => Err(unexpected(&other)),
        }
    }

    fn delete(&self, label: &KeyLabel) -> Result<()> {
        match self.perform_op(Op::Delete {
            label: label.full(),
        })? {
            OpOk::Delete => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    fn exists(&self, label: &KeyLabel) -> Result<bool> {
        match self.perform_op(Op::Exists {
            label: label.full(),
        })? {
            OpOk::Exists { exists } => Ok(exists),
            other => Err(unexpected(&other)),
        }
    }
}

/// Whether a JWS access token is within [`RENEW_MARGIN_SECS`] of its `exp` (or unreadable). This reads
/// the `exp` claim **unverified** — it is only a renewal heuristic for the agent's *own* token; the
/// broker verifies the token for real. An unreadable token is treated as stale (fail-safe: renew).
fn token_near_expiry(jws: &str) -> bool {
    match token_exp(jws) {
        Some(exp) => exp - now() < RENEW_MARGIN_SECS,
        None => true,
    }
}

/// Read the `exp` (seconds since the epoch) from a compact JWS `header.payload.signature`, decoding
/// the payload only (no signature check — see [`token_near_expiry`]). `None` if the shape/base64/JSON
/// is unreadable.
fn token_exp(jws: &str) -> Option<i64> {
    let payload_b64 = jws.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value.get("exp")?.as_i64()
}

/// Current unix time (seconds). A pre-epoch clock (impossible in practice) reads as 0 → renew.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What [`BrokerKeystore::perform_op`] does about a failed attempt.
#[derive(Debug, PartialEq, Eq)]
enum Recovery {
    /// bug090: a re-provisioned broker (`broker_pin_mismatch`) — refresh the pin by signed
    /// re-pickup and retry. Not once-guarded: each occurrence is a distinct transport fact.
    PinRefresh,
    /// bug114 Part F: a paused/refused grant (`access_paused` / `token_denied`) — ONE signed
    /// re-pickup (per keystore) in case the guardian re-authorized, then one retry.
    ReauthOnce,
    /// Everything else — re-raise faithfully; and a SECOND paused/refused failure after the
    /// one re-auth attempt is definitive (never re-hammer a genuinely-paused grant).
    None,
}

/// The recovery decision, pure and pinned by tests: which failure codes are recoverable, and
/// that the re-auth recovery is spent by the `attempted` flag (swapped HERE, exactly once, so
/// the decision and the guard cannot drift apart). `token_denied` deliberately covers any
/// token-mint refusal, not only "paused" — the recovery is one signed pickup, refused
/// harmlessly if no fresh grant awaits, and the original error always stands on refusal.
fn recovery_for(code: &str, attempted: &AtomicBool) -> Recovery {
    match code {
        "broker_pin_mismatch" => Recovery::PinRefresh,
        "access_paused" | "token_denied" => {
            if attempted.swap(true, Ordering::SeqCst) {
                Recovery::None
            } else {
                Recovery::ReauthOnce
            }
        }
        _ => Recovery::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JWS with an `exp` `delta` seconds from now (header/signature are throwaway — only the payload
    /// `exp` is read).
    fn token_with_exp(delta: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now() + delta).as_bytes());
        format!("{header}.{payload}.c2ln")
    }

    #[test]
    fn token_exp_reads_the_claim() {
        let target = now() + 500;
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"hlin-ai","exp":{target}}}"#));
        let jws = format!("aGRy.{payload}.c2ln");
        assert_eq!(token_exp(&jws), Some(target));
    }

    #[test]
    fn near_expiry_is_true_within_the_margin_and_for_junk() {
        // Well within the token's life → not near expiry.
        assert!(!token_near_expiry(&token_with_exp(RENEW_MARGIN_SECS + 300)));
        // Inside the renewal margin → near expiry.
        assert!(token_near_expiry(&token_with_exp(RENEW_MARGIN_SECS - 10)));
        // Already expired → near expiry.
        assert!(token_near_expiry(&token_with_exp(-10)));
        // Unreadable tokens are treated as stale (fail-safe: renew).
        assert!(token_near_expiry("not-a-jws"));
        assert!(token_near_expiry("only.two"));
        assert!(token_near_expiry("aaa.!!!not-base64!!!.bbb"));
    }

    /// bug114 Part F — pin the recovery decision: which codes recover, that the re-auth
    /// recovery is once-per-keystore, and that a spent guard (or any other code) is
    /// definitive. A refactor that "tidies" the code set or drops the guard goes red here.
    #[test]
    fn recovery_decision_pins_the_codes_and_the_once_guard() {
        // bug090 pin refresh: not once-guarded (each mismatch is a distinct transport fact),
        // and it does NOT spend the re-auth guard.
        let attempted = AtomicBool::new(false);
        assert_eq!(
            recovery_for("broker_pin_mismatch", &attempted),
            Recovery::PinRefresh
        );
        assert_eq!(
            recovery_for("broker_pin_mismatch", &attempted),
            Recovery::PinRefresh
        );
        assert!(!attempted.load(Ordering::SeqCst));

        // The re-auth recovery fires ONCE per keystore for each trigger code…
        assert_eq!(
            recovery_for("access_paused", &attempted),
            Recovery::ReauthOnce
        );
        // …and a second paused/refused failure is definitive (the guard is spent).
        assert_eq!(recovery_for("access_paused", &attempted), Recovery::None);
        assert_eq!(recovery_for("token_denied", &attempted), Recovery::None);

        // token_denied is a trigger too (the server refusing the token mint — the S156
        // live-observed surface of the re-authorized state).
        let fresh = AtomicBool::new(false);
        assert_eq!(recovery_for("token_denied", &fresh), Recovery::ReauthOnce);

        // Anything else is re-raised faithfully, and does not spend the guard.
        let untouched = AtomicBool::new(false);
        assert_eq!(recovery_for("key_not_found", &untouched), Recovery::None);
        assert_eq!(recovery_for("token_expired", &untouched), Recovery::None);
        assert_eq!(recovery_for("unauthorized", &untouched), Recovery::None);
        assert!(!untouched.load(Ordering::SeqCst));
    }

    /// bug118 coverage closer (Willa, S156): `token_request_failed` — the code
    /// `request_token` mints for every non-authorization refusal (5xx, 429, a
    /// proxy 403 without our JSON shape) — must NEVER trigger a recovery, and
    /// must not spend the once-per-keystore re-auth guard. Until this test the
    /// property held only via the catch-all `_` arm, which a future edit could
    /// narrow without anything going red; this names the load-bearing non-trigger.
    /// (The chain this closes: `reject_kind` pins 5xx→Other; `request_token`
    /// maps Other→`token_request_failed`; HERE pins that code→None — so a server
    /// blip on a healthy grant can never reach a pickup, and the server-side
    /// zero-`garnet_credential_reissued` assert on refused pickups covers the
    /// remainder. The mTLS wire leg is proven server-side by design — the
    /// grant-status-client precedent.)
    #[test]
    fn token_request_failed_never_triggers_recovery_and_never_spends_the_guard() {
        let guard = AtomicBool::new(false);
        assert_eq!(recovery_for("token_request_failed", &guard), Recovery::None);
        // Repeat: still None (not once-guard semantics — a plain non-trigger)…
        assert_eq!(recovery_for("token_request_failed", &guard), Recovery::None);
        // …and the re-auth guard is UNSPENT: a genuine trigger arriving later
        // still gets its one recovery.
        assert!(!guard.load(Ordering::SeqCst));
        assert_eq!(recovery_for("token_denied", &guard), Recovery::ReauthOnce);
    }
}
