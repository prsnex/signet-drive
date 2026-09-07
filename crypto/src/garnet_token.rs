// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Garnet access tokens — the cert-bound, scoped, short-lived authorization credential
//! (Auth-Core Spec v03 §3). A token is a JWS Compact Serialization (ES256, `typ="at+jwt"`,
//! RFC 9068) signed by the server's K1 token-signing key; it is **useless without the
//! matching client-cert private key** (the `cnf` proof-of-possession binding,
//! RFC 7800 / RFC 8705).
//!
//! # Why this lives in `signet-crypto` (and not the server)
//!
//! The **verifier contract is identical at the server and the broker** (Auth-Core §3): both
//! pin `alg`/`typ` from policy, verify the ES256 signature, and enforce `cnf`/`sub`/`aud`/`exp`
//! fail-closed. Duplicating that verifier across the two crates would invite drift on a
//! security-critical path, so the **pure** logic (no DB, no HTTP) lives here, adjacent to the
//! vetted [`crate::ecdsa`] ES256 it calls. The server wraps [`verify`] with its DB `kid`
//! resolution (`verify_token`) and owns minting (the K1 signer); the broker (the local SE
//! listener) calls [`verify`] directly with the K1 public key it was provisioned.
//!
//! # The verifier is the security heart
//!
//! [`verify`] is written as the explicit, fail-closed MUSTs of §3 because the threat-model's
//! meta-finding was that intent described in prose is not enforcement — a literal build falls
//! into the unsafe default at every gap. In particular it **pins `alg`/`typ` from local policy
//! and NEVER selects the verification algorithm from the token header** (defeating `alg=none`
//! and the ES256→HMAC key-confusion), and it **fail-closes on an absent/mismatched `cnf`**
//! (preserving the proof-of-possession independent root).
//!
//! The JWS is hand-built over the vetted RustCrypto ES256 ([`crate::ecdsa`]) rather than a JOSE
//! library: the project is deliberately ring-free (to keep the differential-oracle lineage
//! clean), and hand-parsing is what lets the verifier pin the algorithm with zero chance of a
//! library's permissive default accepting a forged `alg`. The §8 NORMATIVE negative tests (in
//! `tests`) are the gate that proves the contract holds.
//!
//! **Trusted time:** [`verify`] takes `now` as a parameter — the caller supplies the clock. The
//! server passes the wall clock; the broker passes the **trusted server time** carried in its
//! latest grant-check response (Auth-Core §6, the re-anchored REV-4 defense), never the bare
//! host clock. The verifier itself is clock-source-agnostic by design.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CryptoError, Result};

const ALG_ES256: &str = "ES256";
const TYP_AT_JWT: &str = "at+jwt";
/// The token issuer — the canonical deployment origin (1-Pager §Resolved #10).
const ISS: &str = "https://drive.mysignet.ca";

/// The two token audiences (decision A, S081). Exactly one value per token, never both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// `"signet-server"` — account / ciphertext access at the SigDrive server.
    Server,
    /// `"signet-broker"` — Secure-Enclave ops at the local SE-broker.
    Broker,
}

impl Audience {
    pub fn as_str(self) -> &'static str {
        match self {
            Audience::Server => "signet-server",
            Audience::Broker => "signet-broker",
        }
    }
}

/// The JWS protected header. We emit exactly this shape and accept exactly this shape; the
/// verifier checks `alg`/`typ` against policy and never uses `alg` to select an algorithm.
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// The access-token claims (Auth-Core §3). `jti` is a log-correlation id only — there is no
/// per-token (`jti`) revocation; revocation is the leased live grant check (§6).
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    grant_id: String,
    /// Proof-of-possession confirmation. `Option` so an absent `cnf` parses and is then
    /// rejected with a precise [`TokenError::CnfMissing`] (fail-closed), not a generic parse error.
    cnf: Option<Cnf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cnf {
    #[serde(rename = "x5t#S256")]
    x5t_s256: String,
}

/// What a verified token yields to the caller (the trustworthy, post-verification claims).
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub sub: String,
    pub grant_id: Uuid,
    pub jti: String,
    pub exp: i64,
}

/// Every way a token is rejected. Each variant is a fail-closed rejection; the HTTP boundary
/// (server) maps these to 401/403, the broker fails the SE op closed. Tests assert the exact
/// reason (the §8 negative-test gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not three `.`-separated parts, or a part is not valid base64url / JSON.
    Malformed,
    /// `alg` is not exactly `ES256` (covers `none`, any HMAC family, anything else).
    AlgNotAllowed,
    /// `typ` is not exactly `at+jwt`.
    TypNotAllowed,
    /// `kid` is not a well-formed key id.
    KidMalformed,
    /// `kid` is well-formed but does not resolve to an active K1 key (the {current,previous} allowlist).
    UnknownKid,
    /// The ES256 signature did not verify under the resolved K1 key.
    SignatureInvalid,
    /// `cnf` is absent or empty.
    CnfMissing,
    /// `cnf.x5t#S256` does not equal the presented client-cert thumbprint.
    CnfMismatch,
    /// `sub` does not equal the expected handle (the presenting cert's SAN handle).
    SubMismatch,
    /// `aud` does not name this surface.
    AudMismatch,
    /// `iss` is not the deployment origin.
    IssMismatch,
    /// `exp` is in the past (beyond the skew tolerance).
    Expired,
    /// `nbf`/`iat` is in the future (beyond the skew tolerance).
    NotYetValid,
}

/// Build the JWS **signing input** (`base64url(header).base64url(claims)`) for an access token —
/// the bytes the caller's K1 signer signs. The caller (the server, the only minter) appends
/// `.base64url(signature)` to form the compact JWS; the broker never mints.
///
/// This is the single source of the token's wire shape, so `mint` (server) and [`verify`]
/// (server + broker) cannot drift on field names. `kid` is K1's current id; `audience`/`sub`/
/// `cnf_thumbprint`/`grant_id` populate the claims; `ttl_seconds` is the per-audience TTL from
/// `system_config`; `now` is unix seconds (the caller passes the wall clock — a parameter so
/// tests are deterministic). A fresh v4 `jti` (log-correlation only) is generated here.
pub fn encode_signing_input(
    kid: Uuid,
    audience: Audience,
    sub: &str,
    cnf_thumbprint: &str,
    grant_id: Uuid,
    ttl_seconds: i64,
    now: i64,
) -> Result<String> {
    let header = Header {
        alg: ALG_ES256.to_string(),
        typ: TYP_AT_JWT.to_string(),
        kid: kid.to_string(),
    };
    let claims = Claims {
        iss: ISS.to_string(),
        sub: sub.to_string(),
        aud: audience.as_str().to_string(),
        iat: now,
        nbf: now,
        exp: now + ttl_seconds,
        jti: Uuid::new_v4().to_string(),
        grant_id: grant_id.to_string(),
        cnf: Some(Cnf {
            x5t_s256: cnf_thumbprint.to_string(),
        }),
    };
    // Serializing plain owned-String/i64 structs cannot realistically fail; surfaced as a coarse
    // InvalidInput rather than a panic to keep the crate's no-panic-on-encode posture.
    let header_json = serde_json::to_vec(&header)
        .map_err(|_| CryptoError::InvalidInput("garnet token header"))?;
    let claims_json = serde_json::to_vec(&claims)
        .map_err(|_| CryptoError::InvalidInput("garnet token claims"))?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json),
        URL_SAFE_NO_PAD.encode(claims_json)
    ))
}

/// Parse the header and **pin `alg`/`typ` from policy**, returning the `kid` so the caller can
/// resolve the K1 verify key BEFORE any signature work. Pinning here means a forged `alg=none`
/// or `alg=HS256` is rejected before we ever touch a key or the DB. Does NOT verify the
/// signature (the caller resolves the key by `kid`, then calls [`verify`]).
pub fn extract_kid(jws: &str) -> core::result::Result<Uuid, TokenError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenError::Malformed);
    }
    let header = decode_header(parts[0])?;
    pin_header(&header)?;
    Uuid::parse_str(&header.kid).map_err(|_| TokenError::KidMalformed)
}

/// Verify a token against the §3 contract — all MUSTs, fail-closed. `verify_key` is the K1
/// public key (X9.63) the caller resolved from the token's `kid` (an unresolvable `kid` is
/// rejected by the caller before reaching here). `expected_audience` is this surface;
/// `expected_sub` is the presenting cert's SAN handle (the consistency check `sub==cert-SAN`);
/// `presented_cert_thumbprint` is the base64url SHA-256 of the leaf cert authenticated on THIS
/// connection; `now`/`skew_seconds` are unix seconds (`now` is the caller's trusted clock — see
/// the module doc; the broker passes trusted server time, not the host wall clock).
///
/// Order is load-bearing: pin `alg`/`typ` (format only) → verify the signature → only THEN
/// trust and check the claims. The algorithm is ALWAYS ES256 against `verify_key`; the header
/// `alg` field is checked equal to `ES256` but is never used to *select* the algorithm.
pub fn verify(
    jws: &str,
    verify_key: &[u8],
    expected_audience: Audience,
    expected_sub: &str,
    presented_cert_thumbprint: &str,
    now: i64,
    skew_seconds: i64,
) -> core::result::Result<VerifiedToken, TokenError> {
    let claims = verify_structural(
        jws,
        verify_key,
        expected_audience,
        expected_sub,
        presented_cert_thumbprint,
    )?;
    // Validity window with skew. exp in the past → Expired; nbf/iat in the future → NotYetValid.
    if now > claims.exp.saturating_add(skew_seconds) {
        return Err(TokenError::Expired);
    }
    if claims.nbf.saturating_sub(skew_seconds) > now
        || claims.iat.saturating_sub(skew_seconds) > now
    {
        return Err(TokenError::NotYetValid);
    }
    into_verified(claims)
}

/// Verify the token's structure + binding (alg/typ pin → signature → iss/aud/sub → `cnf` PoP)
/// **without** the `iat`/`nbf`/`exp` time checks — for the **broker only**. The broker cannot
/// check `exp` at token-verify time because its trusted time arrives only with the leased
/// grant-status confirm (Auth-Core §6), and that confirm needs the verified `grant_id` to query —
/// so the **lease** is the broker's single, authoritative time gate (it checks `exp` against
/// `server_time + monotonic`, never the host clock; cold-start refuses until the first confirm).
/// The returned [`VerifiedToken`] carries `exp` (the claim) for the lease to check. **The SERVER
/// MUST use [`verify`]** — it holds the authoritative wall clock and is the time authority on its
/// own path.
pub fn verify_skipping_time(
    jws: &str,
    verify_key: &[u8],
    expected_audience: Audience,
    expected_sub: &str,
    presented_cert_thumbprint: &str,
) -> core::result::Result<VerifiedToken, TokenError> {
    let claims = verify_structural(
        jws,
        verify_key,
        expected_audience,
        expected_sub,
        presented_cert_thumbprint,
    )?;
    into_verified(claims)
}

/// The shared structural + binding core of [`verify`] / [`verify_skipping_time`]: pin `alg`/`typ`,
/// verify the ES256 signature, then (claims now trustworthy) check `iss`/`aud`/`sub` and the `cnf`
/// proof-of-possession — everything EXCEPT the time window. Order is load-bearing: format pin →
/// signature → trust-and-check. Returns the verified [`Claims`].
fn verify_structural(
    jws: &str,
    verify_key: &[u8],
    expected_audience: Audience,
    expected_sub: &str,
    presented_cert_thumbprint: &str,
) -> core::result::Result<Claims, TokenError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenError::Malformed);
    }

    // 1. Header: pin alg=ES256 + typ=at+jwt from policy (before any crypto).
    let header = decode_header(parts[0])?;
    pin_header(&header)?;

    // 2. Signature: ALWAYS ES256 over `header.claims`, under the resolved key. Never branch on
    //    the header `alg`. A bad signature (incl. a forged token, or HS256-with-the-pubkey) fails.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| TokenError::Malformed)?;
    crate::ecdsa::verify_es256(verify_key, signing_input.as_bytes(), &sig)
        .map_err(|_| TokenError::SignatureInvalid)?;

    // 3. Claims are now trustworthy (signature verified). Check them, all fail-closed.
    let claims = decode_claims(parts[1])?;
    if claims.iss != ISS {
        return Err(TokenError::IssMismatch);
    }
    if claims.aud != expected_audience.as_str() {
        return Err(TokenError::AudMismatch);
    }
    if claims.sub != expected_sub {
        return Err(TokenError::SubMismatch);
    }
    // cnf proof-of-possession: absent/empty → CnfMissing; non-matching → CnfMismatch.
    let cnf = claims.cnf.as_ref().ok_or(TokenError::CnfMissing)?;
    if cnf.x5t_s256.is_empty() {
        return Err(TokenError::CnfMissing);
    }
    if cnf.x5t_s256 != presented_cert_thumbprint {
        return Err(TokenError::CnfMismatch);
    }
    Ok(claims)
}

/// Build the trustworthy [`VerifiedToken`] from verified [`Claims`] (parsing `grant_id`).
fn into_verified(claims: Claims) -> core::result::Result<VerifiedToken, TokenError> {
    let grant_id = Uuid::parse_str(&claims.grant_id).map_err(|_| TokenError::Malformed)?;
    Ok(VerifiedToken {
        sub: claims.sub,
        grant_id,
        jti: claims.jti,
        exp: claims.exp,
    })
}

fn decode_header(part: &str) -> core::result::Result<Header, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| TokenError::Malformed)
}

fn decode_claims(part: &str) -> core::result::Result<Claims, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| TokenError::Malformed)
}

/// Pin the header against local policy: `alg` MUST be exactly `ES256`, `typ` exactly `at+jwt`.
/// This is checked from the token but used only to ACCEPT/REJECT — never to select an algorithm.
fn pin_header(header: &Header) -> core::result::Result<(), TokenError> {
    if header.alg != ALG_ES256 {
        return Err(TokenError::AlgNotAllowed);
    }
    if header.typ != TYP_AT_JWT {
        return Err(TokenError::TypNotAllowed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The NORMATIVE §8 build-gate negative tests for the token verifier contract, plus the
    //! happy path. These are pure (no DB, no signer) — they craft tokens by hand so we can forge
    //! the malicious shapes a real minter would never produce. The verifier "isn't real until
    //! these pass". (The server's mint→verify roundtrip lives in the server crate, where the K1
    //! `Signer` lives.)

    use super::*;
    use serde_json::{Value, json};

    const SUB: &str = "hlin-ai";
    const CNF: &str = "Zm9vYmFyLXRodW1icHJpbnQtMzJieXRlcy1iNjR1cmw";
    const NOW: i64 = 1_750_000_000;
    const SKEW: i64 = 30;

    fn keypair() -> ([u8; 32], Vec<u8>) {
        crate::ecdsa::generate_keypair()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Assemble a JWS from explicit header + claims JSON, ES256-signed by `scalar`.
    fn make(scalar: &[u8; 32], header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(header).unwrap()),
            b64(&serde_json::to_vec(claims).unwrap())
        );
        let sig = crate::ecdsa::sign_es256(scalar, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", b64(&sig))
    }

    fn good_header() -> Value {
        json!({ "alg": "ES256", "typ": "at+jwt", "kid": Uuid::new_v4().to_string() })
    }

    fn good_claims() -> Value {
        json!({
            "iss": ISS, "sub": SUB, "aud": "signet-broker",
            "iat": NOW, "nbf": NOW, "exp": NOW + 120,
            "jti": Uuid::new_v4().to_string(),
            "grant_id": Uuid::new_v4().to_string(),
            "cnf": { "x5t#S256": CNF },
        })
    }

    /// Verify a broker token with the standard expectations; returns the verifier result.
    fn check(jws: &str, key: &[u8]) -> core::result::Result<VerifiedToken, TokenError> {
        verify(jws, key, Audience::Broker, SUB, CNF, NOW, SKEW)
    }

    #[test]
    fn happy_path_broker() {
        let (scalar, pubkey) = keypair();
        let jws = make(&scalar, &good_header(), &good_claims());
        let v = check(&jws, &pubkey).expect("a valid token verifies");
        assert_eq!(v.sub, SUB);
    }

    #[test]
    fn encode_then_verify_roundtrip_and_aud_isolation() {
        // The shared encode path produces a signing input the verifier accepts (signed here by a
        // raw scalar, standing in for the server's K1 signer), and the aud-split holds.
        let (scalar, pubkey) = keypair();
        let kid = Uuid::new_v4();
        let grant = Uuid::new_v4();
        let signing_input =
            encode_signing_input(kid, Audience::Server, SUB, CNF, grant, 900, NOW).unwrap();
        let sig = crate::ecdsa::sign_es256(&scalar, signing_input.as_bytes()).unwrap();
        let jws = format!("{signing_input}.{}", b64(&sig));

        // The kid is recoverable (and alg/typ pin) without a key.
        assert_eq!(extract_kid(&jws).unwrap(), kid);

        // Verifies for its own audience...
        let v = verify(&jws, &pubkey, Audience::Server, SUB, CNF, NOW, SKEW).unwrap();
        assert_eq!(v.grant_id, grant);

        // ...but a SERVER token presented to the BROKER surface is rejected (the aud-split).
        assert_eq!(
            verify(&jws, &pubkey, Audience::Broker, SUB, CNF, NOW, SKEW).unwrap_err(),
            TokenError::AudMismatch
        );
    }

    #[test]
    fn alg_none_is_rejected_before_any_crypto() {
        let (scalar, pubkey) = keypair();
        let header = json!({ "alg": "none", "typ": "at+jwt", "kid": Uuid::new_v4().to_string() });
        let jws = make(&scalar, &header, &good_claims());
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::AlgNotAllowed);
        // ...and extract_kid pins it too (so a forged alg never triggers a DB lookup).
        assert_eq!(extract_kid(&jws).unwrap_err(), TokenError::AlgNotAllowed);
    }

    #[test]
    fn alg_hs256_confusion_is_rejected() {
        // A token that is REALLY ES256-signed but LIES `alg=HS256` in the header. A naive verifier
        // that selected HMAC from the header (using the EC public key as the HMAC secret) would be
        // confused; ours pins `alg=ES256` and rejects before any signature work.
        let (scalar, pubkey) = keypair();
        let header = json!({ "alg": "HS256", "typ": "at+jwt", "kid": Uuid::new_v4().to_string() });
        let jws = make(&scalar, &header, &good_claims());
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::AlgNotAllowed);
    }

    #[test]
    fn wrong_typ_is_rejected() {
        let (scalar, pubkey) = keypair();
        let header = json!({ "alg": "ES256", "typ": "JWT", "kid": Uuid::new_v4().to_string() });
        let jws = make(&scalar, &header, &good_claims());
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::TypNotAllowed);
    }

    #[test]
    fn wrong_signing_key_is_signature_invalid() {
        let (scalar, _) = keypair();
        let (_, other_pubkey) = keypair();
        let jws = make(&scalar, &good_header(), &good_claims());
        assert_eq!(
            check(&jws, &other_pubkey).unwrap_err(),
            TokenError::SignatureInvalid
        );
    }

    #[test]
    fn tampered_claims_break_the_signature() {
        // Sign the original claims, then swap the claims segment — the signature no longer matches.
        let (scalar, pubkey) = keypair();
        let valid = make(&scalar, &good_header(), &good_claims());
        let parts: Vec<&str> = valid.split('.').collect();
        let tampered_claims = b64(&serde_json::to_vec(&json!({
            "iss": ISS, "sub": "attacker-ai", "aud": "signet-broker",
            "iat": NOW, "nbf": NOW, "exp": NOW + 120,
            "jti": Uuid::new_v4().to_string(), "grant_id": Uuid::new_v4().to_string(),
            "cnf": { "x5t#S256": CNF },
        }))
        .unwrap());
        let forged = format!("{}.{}.{}", parts[0], tampered_claims, parts[2]);
        assert_eq!(
            check(&forged, &pubkey).unwrap_err(),
            TokenError::SignatureInvalid
        );
    }

    #[test]
    fn cnf_absent_or_empty_is_rejected() {
        let (scalar, pubkey) = keypair();

        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("cnf");
        let jws = make(&scalar, &good_header(), &claims);
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::CnfMissing);

        let claims = json!({
            "iss": ISS, "sub": SUB, "aud": "signet-broker",
            "iat": NOW, "nbf": NOW, "exp": NOW + 120,
            "jti": Uuid::new_v4().to_string(), "grant_id": Uuid::new_v4().to_string(),
            "cnf": { "x5t#S256": "" },
        });
        let jws = make(&scalar, &good_header(), &claims);
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::CnfMissing);
    }

    #[test]
    fn cnf_mismatch_is_rejected() {
        // A valid token presented over a DIFFERENT client cert (the PoP boundary): the verifier's
        // presented thumbprint differs from the token's bound `cnf` → reject.
        let (scalar, pubkey) = keypair();
        let jws = make(&scalar, &good_header(), &good_claims());
        let other_cert = "ZGlmZmVyZW50LWNlcnQtdGh1bWJwcmludC1ub3QtdGhlLWJvdW5k";
        assert_eq!(
            verify(&jws, &pubkey, Audience::Broker, SUB, other_cert, NOW, SKEW).unwrap_err(),
            TokenError::CnfMismatch
        );
    }

    #[test]
    fn sub_not_matching_cert_san_is_rejected() {
        // The §7 consistency check: token.sub must equal the presenting cert's SAN handle.
        let (scalar, pubkey) = keypair();
        let jws = make(&scalar, &good_header(), &good_claims());
        assert_eq!(
            verify(
                &jws,
                &pubkey,
                Audience::Broker,
                "someone-else-ai",
                CNF,
                NOW,
                SKEW
            )
            .unwrap_err(),
            TokenError::SubMismatch
        );
    }

    #[test]
    fn wrong_iss_is_rejected() {
        let (scalar, pubkey) = keypair();
        let mut claims = good_claims();
        claims["iss"] = json!("https://evil.example");
        let jws = make(&scalar, &good_header(), &claims);
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::IssMismatch);
    }

    #[test]
    fn expired_and_not_yet_valid_are_rejected() {
        let (scalar, pubkey) = keypair();

        let mut expired = good_claims();
        expired["exp"] = json!(NOW - 200); // well past, beyond skew
        let jws = make(&scalar, &good_header(), &expired);
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::Expired);

        let mut future = good_claims();
        future["iat"] = json!(NOW + 200);
        future["nbf"] = json!(NOW + 200);
        future["exp"] = json!(NOW + 320);
        let jws = make(&scalar, &good_header(), &future);
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::NotYetValid);
    }

    #[test]
    fn skew_tolerance_is_honored() {
        // A token that expired 10s ago still verifies within a 30s skew (clock-skew tolerance).
        let (scalar, pubkey) = keypair();
        let mut claims = good_claims();
        claims["exp"] = json!(NOW - 10);
        let jws = make(&scalar, &good_header(), &claims);
        assert!(check(&jws, &pubkey).is_ok());
    }

    #[test]
    fn malformed_shapes_are_rejected() {
        let (_, pubkey) = keypair();
        assert_eq!(
            check("only.two", &pubkey).unwrap_err(),
            TokenError::Malformed
        );
        assert_eq!(
            check("a.b.c.d", &pubkey).unwrap_err(),
            TokenError::Malformed
        );
        assert_eq!(
            check("!!!.???.###", &pubkey).unwrap_err(),
            TokenError::Malformed
        );
    }

    #[test]
    fn verify_skipping_time_accepts_an_expired_token_but_keeps_binding() {
        // The broker path: structure + binding are checked, the time window is NOT — an expired
        // token verifies (the lease then gates exp against trusted time), but the cnf PoP and the
        // sub/aud bindings still hold.
        let (scalar, pubkey) = keypair();
        let mut expired = good_claims();
        expired["exp"] = json!(NOW - 100_000); // long expired
        let jws = make(&scalar, &good_header(), &expired);

        // `verify` rejects it (the server path, time-checked)...
        assert_eq!(check(&jws, &pubkey).unwrap_err(), TokenError::Expired);

        // ...but `verify_skipping_time` accepts it and surfaces the (stale) exp for the lease.
        let v = verify_skipping_time(&jws, &pubkey, Audience::Broker, SUB, CNF).unwrap();
        assert_eq!(v.exp, NOW - 100_000);

        // The binding still fails closed: wrong cnf, wrong sub, wrong audience are all rejected.
        assert_eq!(
            verify_skipping_time(&jws, &pubkey, Audience::Broker, SUB, "other-thumbprint")
                .unwrap_err(),
            TokenError::CnfMismatch
        );
        assert_eq!(
            verify_skipping_time(&jws, &pubkey, Audience::Broker, "someone-else-ai", CNF)
                .unwrap_err(),
            TokenError::SubMismatch
        );
        assert_eq!(
            verify_skipping_time(&jws, &pubkey, Audience::Server, SUB, CNF).unwrap_err(),
            TokenError::AudMismatch
        );
    }
}
