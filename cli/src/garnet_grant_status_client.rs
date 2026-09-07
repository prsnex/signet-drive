// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The broker's real grant-status client — the check-at-use confirm over mutual-TLS (Auth-Core Spec
//! v03 §6, Phase-2 #4). Implements [`crate::broker::GrantStatusClient`] against the server's
//! `GET /v1/garnet/grant-status` ([`signet_server::garnet::grant_status`]), replacing the
//! fail-closed [`crate::broker::UnreachableGrantStatus`] default once Phase 6 wires it in.
//!
//! ## The channel (§6)
//!
//! The query runs over a **K2-pinned mutual-TLS** connection: the broker presents its K_bc **client**
//! cert (clientAuth, T3 option (a)), and verifies the server's cert **chains to the pinned K2** with
//! serverAuth — *not* the public web PKI, so a same-host attacker who redirects the connection cannot
//! impersonate the server (the broker trusts exactly the one CA the deployment holds). The server-cert
//! hostname is irrelevant (the cert SAN is `urn:signet:server:` — not a DNS name), so the verifier
//! authenticates by the K2 chain, not the name. The config (the server-cert verifier + the client-cert
//! presentation) is built by the shared [`crate::broker_tls::k2_pinned_client_config`], whose chain
//! decision is the project's hand-rolled, ring-free [`signet_crypto::x509::verify_leaf_chains_to_ca_uri`].
//!
//! ## Fail-safe mapping (§6)
//!
//! Only a definitive **200 negative** is [`GrantStatusOutcome::Revoked`] (cut immediately, no grace).
//! Everything ambiguous — a non-200, a transport/TLS failure, an unparseable body or `server_time` —
//! is [`GrantStatusOutcome::Unreachable`], which the lease serves on last-known-good only within
//! `lease + outage_grace`, then fails closed. A "no" is never graced; only *unreachability* is.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use uuid::Uuid;

use crate::broker::GrantStatusClient;
use crate::error::{CliError, Result};
use crate::garnet_revocation::{GrantStatusOutcome, ServerSla};

/// A per-request connect/read timeout — the grant-status check is on the SE-op hot path (§6), so a
/// stalled server must surface as `Unreachable` quickly rather than block an op indefinitely.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// The grant-status response body (the §6 NORMATIVE shape). Parsed leniently; the mapping in
/// [`map_response`] applies the fail-closed rules.
#[derive(Debug, Deserialize)]
struct GrantStatusBody {
    status: String,
    enrollment_confirmed: bool,
    cert_revoked: bool,
    server_time: String,
    /// bug125 (F-006): the live revocation-SLA values. **`Option` + `serde(default)` on purpose** —
    /// a server older than this field is not an error, it just leaves the broker on its compiled
    /// defaults. Making these required would turn a version skew into a total broker outage
    /// (every answer unparseable ⇒ `Unreachable` ⇒ fail-closed once grace expires), which is a far
    /// worse failure than running the default SLA.
    #[serde(default)]
    lease_seconds: Option<i64>,
    #[serde(default)]
    outage_grace_seconds: Option<i64>,
}

/// The real grant-status client: a `ureq` agent pre-built with the K2-pinned mutual-TLS config, plus
/// the server base URL. One agent (connection-pooled) is reused across queries.
pub struct HttpGrantStatusClient {
    base_url: String,
    agent: ureq::Agent,
}

impl HttpGrantStatusClient {
    /// Build the client from the broker's grant-status credentials: `base_url` (the server's
    /// grant-status mTLS endpoint, e.g. `https://drive.mysignet.ca:<port>`), the pinned **K2** anchor
    /// (DER), and the broker's K_bc **client** cert chain + key. The mutual-TLS config presents K_bc
    /// and pins the server to the K2 chain (serverAuth).
    pub fn new(
        base_url: impl Into<String>,
        ca_anchor_der: Vec<u8>,
        client_cert_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let tls = crate::broker_tls::k2_pinned_client_config(
            ca_anchor_der,
            client_cert_chain,
            client_key,
        )
        .map_err(|e| CliError::new(70, "internal", format!("broker mTLS config: {e}")))?;
        let agent = ureq::builder()
            .timeout(QUERY_TIMEOUT)
            .tls_config(Arc::new(tls))
            .build();
        Ok(Self {
            base_url: base_url.into(),
            agent,
        })
    }

    /// Best-effort **broker self-deregister** (#37 part a) — `POST /v1/garnet/broker/deregister` over
    /// the same K_bc mutual-TLS channel. The broker's presented leaf IS its identity (the server reads
    /// the `broker_id` from the SAN — nothing is sent in the body), so this simply asks the server to
    /// forget this Mac's broker. Returns `Ok(())` on a 2xx; `Err` on any non-2xx or transport/TLS
    /// failure — `signet uninstall` treats the error as **non-fatal** (it removes the local install
    /// regardless; a stale server row is still clearable via the dashboard "remove this Mac" or a
    /// re-provision, which replaces it).
    pub fn deregister(&self) -> Result<()> {
        let url = format!("{}/v1/garnet/broker/deregister", self.base_url);
        self.agent
            .post(&url)
            .send_bytes(&[])
            .map(|_| ())
            .map_err(|e| CliError::new(70, "deregister_failed", format!("broker deregister: {e}")))
    }
}

impl GrantStatusClient for HttpGrantStatusClient {
    fn query(&self, grant_id: Uuid, handle: &str, cnf: &str) -> GrantStatusOutcome {
        // Bug035: the first op after a long idle can pick up a dead pooled connection
        // (server keepalive closed it) and get a TRANSPORT error → fail-closed on the
        // agent's first op, clean on retry. One transparent retry on a transport error
        // ONLY (never on a `Response` the server actually answered — a 4xx/5xx negative
        // must not be re-queried): the retry re-establishes the connection, and a second
        // transport miss still falls through to `Unreachable` (fail-closed, lease-bounded).
        // An HTTP status arrives via `Ok(resp)` and is mapped verbatim — never retried.
        query_with_one_retry(|| self.attempt(grant_id, handle, cnf))
    }
}

/// The Bug035 retry policy, pure + unit-testable: run `attempt`; on a transport failure
/// (`Err`) run it ONCE more; on a second transport failure return `Unreachable`. A server
/// answer (`Ok`, any HTTP status already mapped) is returned immediately — never retried,
/// so a definitive negative can't be re-queried.
fn query_with_one_retry(
    mut attempt: impl FnMut() -> std::result::Result<GrantStatusOutcome, ()>,
) -> GrantStatusOutcome {
    match attempt() {
        Ok(outcome) => outcome,
        Err(()) => attempt().unwrap_or(GrantStatusOutcome::Unreachable),
    }
}

impl HttpGrantStatusClient {
    /// One grant-status attempt. `Ok(outcome)` when the server ANSWERED (any HTTP status,
    /// mapped by [`map_response`] — a definitive result, never retried); `Err(())` on a
    /// transport/TLS failure (a dead pooled connection, DNS, timeout — retryable per Bug035).
    fn attempt(
        &self,
        grant_id: Uuid,
        handle: &str,
        cnf: &str,
    ) -> std::result::Result<GrantStatusOutcome, ()> {
        let url = format!("{}/v1/garnet/grant-status", self.base_url);
        match self
            .agent
            .get(&url)
            .query("grant_id", &grant_id.to_string())
            .query("handle", handle)
            .query("cnf", cnf)
            .call()
        {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().unwrap_or_default();
                Ok(map_response(status, &body))
            }
            Err(_) => Err(()),
        }
    }
}

/// Map an HTTP response to a [`GrantStatusOutcome`] (the §6 fail-closed rules; pure + unit-testable).
/// A definitive **200 negative** (parsed, but `status != active` / unconfirmed / cert-revoked) is
/// `Revoked`; a 200 affirmative with a parseable `server_time` is `Live`; everything else (non-200,
/// unparseable body, unparseable `server_time`) is `Unreachable`.
fn map_response(status: u16, body: &str) -> GrantStatusOutcome {
    if status != 200 {
        return GrantStatusOutcome::Unreachable;
    }
    let Ok(b) = serde_json::from_str::<GrantStatusBody>(body) else {
        return GrantStatusOutcome::Unreachable;
    };
    if b.status == "active" && b.enrollment_confirmed && !b.cert_revoked {
        match parse_rfc3339_unix(&b.server_time) {
            // A live answer needs an authoritative anchor; an unparseable time can't anchor trusted
            // time, so treat it as ambiguous rather than serve without a clock.
            Some(server_time) => {
                // bug125 (F-006): both values or neither. A half-populated body is a server we do
                // not understand, so we decline to derive an SLA from it rather than pair one
                // operator-set value with a compiled default and call the result "the live SLA".
                let sla = match (b.lease_seconds, b.outage_grace_seconds) {
                    (Some(lease_seconds), Some(outage_grace_seconds)) => Some(ServerSla {
                        lease_seconds,
                        outage_grace_seconds,
                    }),
                    _ => None,
                };
                GrantStatusOutcome::Live { server_time, sla }
            }
            None => GrantStatusOutcome::Unreachable,
        }
    } else {
        GrantStatusOutcome::Revoked
    }
}

/// Parse an RFC3339 UTC timestamp to unix seconds, or `None` if malformed.
fn parse_rfc3339_unix(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .ok()
}

#[cfg(test)]
mod tests {
    //! The pure §6 response→outcome mapping (every fail-closed branch). The K2-pinned mutual-TLS
    //! client config is now shared from [`crate::broker_tls`] (where the server-cert verifier's
    //! K2-chain decision is tested); the full HTTP-over-mutual-TLS round-trip is proven on the server
    //! side (`server/tests/garnet_grant_status.rs`), which exercises this same ureq + rustls client
    //! mechanism against the real listener.

    use super::*;

    /// A fixed RFC3339 anchor + its unix value (derived via the parse path under test) — avoids the
    /// `time` `formatting` feature in the cli (only `parsing` is the runtime dep).
    const ANCHOR_RFC3339: &str = "2025-06-15T13:46:40Z";
    fn anchor_unix() -> i64 {
        parse_rfc3339_unix(ANCHOR_RFC3339).expect("the anchor parses")
    }

    #[test]
    fn maps_a_live_affirmative_to_live_with_server_time() {
        let body = format!(
            r#"{{"grant_id":"{}","status":"active","enrollment_confirmed":true,"cert_revoked":false,"server_time":"{ANCHOR_RFC3339}"}}"#,
            Uuid::new_v4(),
        );
        assert_eq!(
            map_response(200, &body),
            GrantStatusOutcome::live(anchor_unix())
        );
    }

    #[test]
    fn maps_every_definitive_negative_to_revoked() {
        let st = ANCHOR_RFC3339;
        // revoked grant
        let revoked = format!(
            r#"{{"grant_id":"{}","status":"revoked","enrollment_confirmed":true,"cert_revoked":false,"server_time":"{st}"}}"#,
            Uuid::new_v4()
        );
        assert_eq!(map_response(200, &revoked), GrantStatusOutcome::Revoked);
        // unconfirmed
        let unconfirmed = format!(
            r#"{{"grant_id":"{}","status":"active","enrollment_confirmed":false,"cert_revoked":false,"server_time":"{st}"}}"#,
            Uuid::new_v4()
        );
        assert_eq!(map_response(200, &unconfirmed), GrantStatusOutcome::Revoked);
        // cert revoked (the presented-cert-precise negative, S085)
        let cert_revoked = format!(
            r#"{{"grant_id":"{}","status":"active","enrollment_confirmed":true,"cert_revoked":true,"server_time":"{st}"}}"#,
            Uuid::new_v4()
        );
        assert_eq!(
            map_response(200, &cert_revoked),
            GrantStatusOutcome::Revoked
        );
    }

    #[test]
    fn maps_ambiguous_answers_to_unreachable() {
        let st = ANCHOR_RFC3339;
        // non-200
        let body = format!(
            r#"{{"grant_id":"{}","status":"active","enrollment_confirmed":true,"cert_revoked":false,"server_time":"{st}"}}"#,
            Uuid::new_v4()
        );
        assert_eq!(map_response(503, &body), GrantStatusOutcome::Unreachable);
        assert_eq!(map_response(404, &body), GrantStatusOutcome::Unreachable);
        // unparseable body
        assert_eq!(
            map_response(200, "not json"),
            GrantStatusOutcome::Unreachable
        );
        // a live affirmative with an unparseable server_time can't anchor trusted time → ambiguous
        let bad_time = format!(
            r#"{{"grant_id":"{}","status":"active","enrollment_confirmed":true,"cert_revoked":false,"server_time":"not-a-time"}}"#,
            Uuid::new_v4()
        );
        assert_eq!(
            map_response(200, &bad_time),
            GrantStatusOutcome::Unreachable
        );
    }

    // Bug035: the one-retry policy over transport failures.
    fn live() -> GrantStatusOutcome {
        GrantStatusOutcome::live(0)
    }

    #[test]
    fn a_server_answer_on_the_first_try_is_never_retried() {
        let mut calls = 0;
        let out = query_with_one_retry(|| {
            calls += 1;
            Ok(live())
        });
        assert_eq!(out, live());
        assert_eq!(calls, 1, "a definitive answer is used as-is, no retry");
    }

    #[test]
    fn a_definitive_negative_is_not_re_queried() {
        // A `Revoked` answer is `Ok(Revoked)` — the retry must not run (re-querying a
        // definitive negative would be the dangerous bug this policy avoids).
        let mut calls = 0;
        let out = query_with_one_retry(|| {
            calls += 1;
            Ok(GrantStatusOutcome::Revoked)
        });
        assert_eq!(out, GrantStatusOutcome::Revoked);
        assert_eq!(calls, 1);
    }

    #[test]
    fn one_transport_failure_then_success_heals() {
        let mut calls = 0;
        let out = query_with_one_retry(|| {
            calls += 1;
            if calls == 1 { Err(()) } else { Ok(live()) }
        });
        assert_eq!(out, live(), "the retry re-establishes and succeeds");
        assert_eq!(calls, 2);
    }

    #[test]
    fn two_transport_failures_fail_closed_unreachable() {
        let mut calls = 0;
        let out = query_with_one_retry(|| {
            calls += 1;
            Err::<GrantStatusOutcome, ()>(())
        });
        assert_eq!(out, GrantStatusOutcome::Unreachable, "still fail-closed");
        assert_eq!(calls, 2, "exactly one retry — never an unbounded loop");
    }
}
