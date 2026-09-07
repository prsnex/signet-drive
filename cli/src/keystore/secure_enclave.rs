// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The `secure_enclave` keystore backend (B6a PR4) — Apple-Silicon Mac host.
//!
//! **Classical keys** are P-256 EC keys generated *in* the Secure Enclave; the
//! private scalar never leaves the enclave. Signing keys do `ES256` via
//! `SecKeyCreateSignature`; KEM keys do ECDH via `SecKeyCopyKeyExchangeResult` —
//! the trait's raw-Z `ecdh` seam: the enclave returns the shared secret Z
//! without exposing the scalar, exactly like the software backend's Z-seam. The
//! CLI does no raw crypto: the DER→raw signature conversion goes through
//! `signet-crypto`.
//!
//! **PQ keys** (PQR item 1; the `signing-pq`/`kem-pq` purposes) are
//! `SecureEnclave.MLDSA87`/`MLKEM1024` keys, likewise generated *in* the Enclave
//! but reached through the Swift/CryptoKit C-ABI shim ([`super::se_shim`]) —
//! CryptoKit-only, no `SecKey` exists for them. Persistence is the SE-sealed
//! `dataRepresentation` blob in a data-protection-keychain generic item (see the
//! custody note at [`PQ_BLOB_SERVICE`]); ops: `ml_kem_decapsulate` (→ `Z_mlkem`
//! for the hybrid content-wrap) and `ml_dsa_sign` (hedged, FIPS 204 context
//! parameter). Requires macOS 26 (the SE-PQC floor); older macOS fails closed
//! with `unsupported_platform`.
//!
//! Access policy (CLI Spec v08 §"Key storage"): `kSecAttrAccessibleWhenUnlocked-
//! ThisDeviceOnly`, no biometry flag — usable by the macOS user's processes while
//! the session is unlocked, with no per-use Touch ID. Keys are permanent in the
//! data-protection keychain, looked up by `kSecAttrLabel` (= the `<handle>-<purpose>`
//! label; the safe `security-framework` crate exposes set/query for `kSecAttrLabel`
//! but not `kSecAttrApplicationTag`, so the label serves as the application handle).
//!
//! **Packaging (PR4 spike finding).** The data-protection keychain requires the
//! binary to be codesigned with a provisioning-profile-authorized
//! `keychain-access-groups` entitlement. An unsigned/dev build hits
//! `errSecMissingEntitlement` (-34018) on the permanent keygen; the Developer ID
//! cert alone is necessary but not sufficient (it signs+notarizes but does not
//! authorize that restricted entitlement). For local/dev work use
//! `SIGNET_KEY_TIER=software`. Full verification of the persistent paths
//! (generate-permanent / lookup / list / delete) is gated on a SigDrive App ID +
//! provisioning profile; the crypto paths (sign / ECDH) are proven by the spike
//! and the transient-key tests below.
//!
//! This whole module is `cfg(target_os = "macos")`; linux CI never compiles it.

use core_foundation::base::{TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, KeyClass, Limit, Location,
    Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::base::errSecItemNotFound;

use super::{KeyLabel, KeyMeta, Keystore, Purpose, Tier, se_shim};
use crate::error::{CliError, Result};

/// Apple `errSecInteractionNotAllowed` (SecBase.h): the keychain/Secure Enclave
/// refused because the macOS session is LOCKED (`kSecAttrAccessibleWhenUnlocked-
/// ThisDeviceOnly`). Not exported by security-framework-sys.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// bug057: translate the lock-gated refusal into the *situation* instead of
/// leaking Apple's "User interaction is not allowed." Fail-closed under lock is
/// by design (1-Pager Resolved #8); the state is temporary and clears when a
/// human unlocks the Mac. Exit 52 `se_locked` so a harness can branch on it.
/// The broker runs this same keystore, so the translation reaches the
/// broker-relayed path at the same chokepoint.
fn se_locked_err(what: impl std::fmt::Display) -> CliError {
    CliError::se_locked(format!(
        "this Mac is locked. Secure Enclave keys are unavailable until a human \
         unlocks it ({what} is lock-gated by design; safe to retry after unlock)"
    ))
}

/// The string-formatted-error variant of the -25308 check, for sites that only
/// have a `{e:?}` detail (CFError paths). Pinned by a unit test below.
fn detail_is_se_locked(detail: &str) -> bool {
    detail.contains("-25308") || detail.contains("User interaction is not allowed")
}

/// Zero-sized: the enclave + keychain hold all state. Each op looks the key up by
/// its label at use time (CLI Spec v08), so there is nothing to cache.
pub struct SecureEnclaveKeystore;

impl SecureEnclaveKeystore {
    /// Open the backend. No state to load (keys live in the keychain/enclave); the
    /// `Result` mirrors the software backend's signature and leaves room for a
    /// future availability probe.
    pub fn open() -> Result<Self> {
        Ok(Self)
    }
}

/// The spec access policy: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no
/// access-control flags (no biometry / user-presence) — so no per-use Touch ID.
fn access_control() -> Result<SecAccessControl> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        0,
    )
    .map_err(|e| CliError::generic(format!("creating Secure Enclave access control: {e}")))
}

// ── SE PQ key custody (PQR item 1) ────────────────────────────────────────────
//
// `SecureEnclave.MLKEM1024`/`MLDSA87` keys are CryptoKit-only — there is no
// `SecKey` for them, so they cannot live in the keychain as key-class items the
// way the P-256 keys do. What CryptoKit gives us is the SE-sealed
// `dataRepresentation` blob (opaque; useless off this device — the private
// key exists only inside this Mac's Enclave). Custody choice (documented per the
// item-1 plan): the sealed blob is stored as a **generic-password item in the
// same data-protection keychain**, under a dedicated service string, labeled
// `<handle>-signing-pq` / `<handle>-kem-pq` — one custody surface and one
// entitlement for all four of a PRSN's keys, and `keys list`/`delete` extend by
// item class rather than by a second storage backend. The *use* policy
// (WhenUnlockedThisDeviceOnly, no biometry) is baked into the SE key itself at
// generation by the shim — the keychain item is storage, not the enforcement
// point. (The crate's add API doesn't expose `kSecAttrAccessible` for the item;
// the DP-keychain default applies. A backup-restored blob on another Mac is a
// dead item, not a live key — SE-sealing, not item accessibility, is what binds
// the key to this device.)

/// `kSecAttrService` for the SE PQ sealed-blob items — scopes search/list to
/// exactly ours.
const PQ_BLOB_SERVICE: &str = "ai.prsnex.signet.se-pq";

/// Store a sealed PQ key blob under `label`. Fails if the add fails (including
/// a duplicate — callers check `exists` first, mirroring classical keygen).
fn pq_blob_store(label: &str, blob: &[u8]) -> Result<()> {
    ItemAddOptions::new(ItemAddValue::Data {
        class: ItemClass::generic_password(),
        data: CFData::from_buffer(blob),
    })
    .set_location(Location::DataProtectionKeychain)
    .set_service(PQ_BLOB_SERVICE)
    .set_account_name(label)
    .set_label(label)
    .add()
    .map_err(|e| {
        let detail = format!("{e:?}");
        if detail.contains("-34018") {
            CliError::unsupported_platform(format!(
                "storing the Secure-Enclave PQ key blob '{label}' failed: \
                 errSecMissingEntitlement (-34018). The signet binary must be codesigned \
                 with a provisioning-profile-authorized keychain-access-groups entitlement; \
                 for local/dev use SIGNET_KEY_TIER=software."
            ))
        } else if detail_is_se_locked(&detail) {
            se_locked_err(format_args!("storing the PQ key blob '{label}'"))
        } else {
            CliError::generic(format!(
                "storing the Secure-Enclave PQ key blob '{label}': {e}"
            ))
        }
    })
}

/// Load the sealed PQ key blob for `label`. `None` if absent.
fn pq_blob_find(label: &str) -> Result<Option<Vec<u8>>> {
    let results = match ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(PQ_BLOB_SERVICE)
        .label(label)
        .ignore_legacy_keychains()
        .load_data(true)
        .search()
    {
        Ok(results) => results,
        Err(e) if e.code() == errSecItemNotFound => return Ok(None),
        Err(e) if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            return Err(se_locked_err(format_args!("the PQ key lookup '{label}'")));
        }
        Err(e) => {
            return Err(CliError::generic(format!(
                "Secure Enclave PQ key lookup '{label}': {e}"
            )));
        }
    };
    Ok(results.into_iter().find_map(|r| match r {
        SearchResult::Data(d) => Some(d),
        _ => None,
    }))
}

/// Delete the sealed PQ key blob for `label` (caller checks existence first,
/// mirroring the classical `delete` semantics).
fn pq_blob_delete(label: &str) -> Result<()> {
    ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(PQ_BLOB_SERVICE)
        .label(label)
        .ignore_legacy_keychains()
        .delete()
        .map_err(|e| {
            if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED {
                se_locked_err(format_args!("deleting the PQ key blob '{label}'"))
            } else {
                CliError::generic(format!(
                    "deleting Secure Enclave PQ key blob '{label}': {e}"
                ))
            }
        })
}

/// All labels stored under the PQ blob service (for `list`). Items whose label
/// is missing or not one of ours are skipped, mirroring the key-item scan.
fn pq_blob_labels() -> Result<Vec<String>> {
    use security_framework_sys::item::kSecAttrLabel;
    let results = match ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(PQ_BLOB_SERVICE)
        .ignore_legacy_keychains()
        .load_attributes(true)
        .limit(Limit::All)
        .search()
    {
        Ok(results) => results,
        Err(e) if e.code() == errSecItemNotFound => return Ok(Vec::new()),
        Err(e) if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            return Err(se_locked_err("the PQ key list"));
        }
        Err(e) => {
            return Err(CliError::generic(format!(
                "Secure Enclave PQ key list: {e}"
            )));
        }
    };
    let mut out = Vec::new();
    for r in results {
        let SearchResult::Dict(attrs) = r else {
            continue;
        };
        if let Some(label) = attrs
            .find(unsafe { kSecAttrLabel }.to_void())
            .map(|v| unsafe { CFString::wrap_under_get_rule(v.cast()) }.to_string())
        {
            out.push(label);
        }
    }
    Ok(out)
}

/// Look up a private SE key by its label (`kSecAttrLabel`). `None` if absent.
fn find(label: &str) -> Result<Option<SecKey>> {
    let results = match ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .ignore_legacy_keychains() // the data-protection keychain (where SE keys live)
        .label(label)
        .load_refs(true)
        .search()
    {
        Ok(results) => results,
        // An empty match surfaces as errSecItemNotFound, not an empty Vec — that's
        // "no such key", which the callers (exists / meta / sign / ecdh) read as None.
        Err(e) if e.code() == errSecItemNotFound => return Ok(None),
        Err(e) if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            return Err(se_locked_err(format_args!("the key lookup '{label}'")));
        }
        Err(e) => {
            return Err(CliError::generic(format!(
                "Secure Enclave key lookup '{label}': {e}"
            )));
        }
    };
    Ok(results.into_iter().find_map(|r| match r {
        SearchResult::Ref(Reference::Key(k)) => Some(k),
        _ => None,
    }))
}

/// The X9.63 uncompressed public key (`0x04 ‖ X ‖ Y`) for an SE key.
fn pub_x963(key: &SecKey) -> Result<Vec<u8>> {
    key.public_key()
        .and_then(|pk| pk.external_representation())
        .map(|d| d.to_vec())
        .ok_or_else(|| CliError::generic("could not extract Secure Enclave public key"))
}

/// `kSecAttrLabel` for a key (the `<handle>-<purpose>` we set at keygen), used by
/// `list`. Mirrors the crate's own `application_label()` access pattern.
/// Build a P-256 *public* `SecKey` from X9.63 bytes (the ECDH peer). The safe
/// crate has no `SecKeyCreateWithData`, so this is the one bit of `-sys` FFI.
fn peer_pub(x963: &[u8]) -> Result<SecKey> {
    use security_framework_sys::item::{
        kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom,
    };
    use security_framework_sys::key::SecKeyCreateWithData;
    unsafe {
        let attrs = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType).as_CFType(),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass).as_CFType(),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPublic).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits).as_CFType(),
                CFNumber::from(256i32).as_CFType(),
            ),
        ]);
        let data = CFData::from_buffer(x963);
        let mut err: CFErrorRef = std::ptr::null_mut();
        let key_ref = SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
            &mut err,
        );
        if key_ref.is_null() {
            let e = CFError::wrap_under_create_rule(err);
            return Err(CliError::invalid_data(format!(
                "peer public key is not a valid X9.63 P-256 point: {e}"
            )));
        }
        Ok(SecKey::wrap_under_create_rule(key_ref))
    }
}

/// `ES256` over `msg` with an SE signing key → raw `r‖s` (the trait contract).
/// The SE emits DER; `signet-crypto` does the DER→raw conversion (no raw crypto
/// in the CLI). The `Message` algorithm hashes with SHA-256 inside the enclave.
fn sign_with(key: &SecKey, msg: &[u8]) -> Result<[u8; 64]> {
    let der = key
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
        .map_err(|e| {
            let detail = format!("{e:?}");
            if detail_is_se_locked(&detail) {
                se_locked_err("signing")
            } else {
                CliError::generic(format!("Secure Enclave signing failed: {e}"))
            }
        })?;
    Ok(signet_crypto::ecdsa::sig_der_to_raw(&der)?)
}

/// ECDH P-256 with an SE KEM key → raw 32-byte Z (`kSecKeyAlgorithmECDHKeyExchange-
/// Standard`, requested size 32, no shared info). The enclave computes Z without
/// exposing the scalar — the same raw-Z seam as the software backend.
fn ecdh_with(key: &SecKey, peer_x963: &[u8]) -> Result<[u8; 32]> {
    let peer = peer_pub(peer_x963)?;
    let z = key
        .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
        .map_err(|e| {
            let detail = format!("{e:?}");
            if detail_is_se_locked(&detail) {
                se_locked_err("the ECDH operation")
            } else {
                CliError::generic(format!("Secure Enclave ECDH failed: {e}"))
            }
        })?;
    z.try_into()
        .map_err(|_| CliError::generic("Secure Enclave ECDH returned a non-32-byte secret"))
}

/// The broker's **K3 transport key** in the Secure Enclave (Garnet Phase-6, S094).
///
/// K3 is the broker's own agent-facing mutual-TLS server identity — a transport key, **not** a
/// PRSN sign/KEM custody key, so it lives outside the `KeyLabel`/`Keystore` abstraction and is
/// reached by these dedicated helpers (reusing this module's SE FFI). The private scalar is
/// generated in and never leaves the enclave; the broker credential holds only the label.
///
/// Generate the K3 signing key in the SE under `label`, returning its X9.63 public key (the
/// half sent to the server for K3 cert issuance). `label` is a fresh **per-generation** label
/// ([`crate::broker_transport_key::broker_k3_generation_label`], bug087 fix 0): each provision
/// attempt mints its own, the credential names it, and stale generations are removed by
/// [`sweep_stale_broker_se_keys`] only after a provision *succeeds* — so this function never
/// deletes anything. A label collision is cryptographically impossible (8 CSPRNG bytes), so
/// an occupied label is refused as evidence of a bug, never "helpfully" replaced. Needs the
/// provisioning-profile `keychain-access-groups` entitlement (a signed build) — dev/CI uses
/// the software tier.
pub(crate) fn generate_broker_se_key(label: &str) -> Result<Vec<u8>> {
    if find(label)?.is_some() {
        return Err(CliError::generic(format!(
            "a Secure-Enclave key already exists under the fresh broker label '{label}'. This cannot happen (labels are per-generation CSPRNG); refusing to touch it"
        )));
    }
    let ac = access_control()?;
    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_location(Location::DataProtectionKeychain) // SE keys MUST use the DP keychain
        .set_label(label)
        .set_access_control(ac);
    let key = SecKey::new(&opts).map_err(|e| broker_keygen_err(label, e))?;
    pub_x963(&key)
}

/// The report from [`sweep_stale_broker_se_keys`]: how many stale broker-K3 generations were
/// removed (verified absent), and any that could not be (label + reason) — surfaced LOUDLY by
/// the caller, never swallowed (the `let _ =` this replaces is how bug087 stayed invisible).
pub(crate) struct BrokerKeySweep {
    pub removed: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Remove every **stale** broker-K3 SE key — the legacy fixed label and any per-generation
/// label other than `keep_label` (bug087 fix 0b; classifier:
/// [`crate::broker_transport_key::is_stale_broker_k3_label`], strict, PRSN-label-proof).
/// Runs only after a provision SUCCEEDS (the new credential names `keep_label`, so everything
/// else is unambiguously stale — including duplicates accumulated under the legacy fixed label
/// by pre-fix versions). Each delete is **verified** (the item must be absent afterwards);
/// failures are reported per-label, never discarded. Stale keys are inert under per-generation
/// labels (no credential references them), so the caller treats failures as a loud warning,
/// not a provision failure.
pub(crate) fn sweep_stale_broker_se_keys(keep_label: &str) -> Result<BrokerKeySweep> {
    use security_framework_sys::item::kSecAttrLabel;
    // Enumerate keychain ITEM attribute dictionaries (never SecKey refs — the S059/S061
    // lesson: a Secure-Enclave key's crypto-attribute dictionary lacks `kSecAttrLabel`).
    let results = match ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .ignore_legacy_keychains()
        .load_attributes(true)
        .limit(Limit::All)
        .search()
    {
        Ok(results) => results,
        // No keys at all — nothing stale.
        Err(e) if e.code() == errSecItemNotFound => {
            return Ok(BrokerKeySweep {
                removed: Vec::new(),
                failed: Vec::new(),
            });
        }
        Err(e) if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            return Err(se_locked_err("the stale broker-key sweep"));
        }
        Err(e) => {
            return Err(CliError::generic(format!(
                "Secure Enclave key enumeration for the broker-key sweep: {e}"
            )));
        }
    };
    let mut sweep = BrokerKeySweep {
        removed: Vec::new(),
        failed: Vec::new(),
    };
    for r in results {
        let SearchResult::Dict(attrs) = r else {
            continue;
        };
        let Some(label) = attrs
            .find(unsafe { kSecAttrLabel }.to_void())
            .map(|v| unsafe { CFString::wrap_under_get_rule(v.cast()) }.to_string())
        else {
            continue;
        };
        if !crate::broker_transport_key::is_stale_broker_k3_label(&label, keep_label) {
            continue;
        }
        // Delete by exact label, then VERIFY absence — a delete that silently fails is how
        // the bug087 duplicate survived. (SecItemDelete removes every match for the query.)
        let delete_result = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .ignore_legacy_keychains()
            .label(&label)
            .delete();
        match delete_result {
            Err(e) if e.code() != errSecItemNotFound => {
                sweep.failed.push((label, format!("delete failed: {e}")));
                continue;
            }
            _ => {}
        }
        match find(&label) {
            Ok(None) => sweep.removed.push(label),
            Ok(Some(_)) => sweep
                .failed
                .push((label, "still present after delete".to_string())),
            Err(e) => sweep
                .failed
                .push((label, format!("post-delete verification failed: {e}"))),
        }
    }
    Ok(sweep)
}

/// `ES256` (raw `r‖s`) over `msg` with the broker's SE-resident K3 key `label` — the seam the
/// broker's rustls K3 signer delegates each TLS handshake signature to. The scalar never leaves
/// the enclave.
pub(crate) fn broker_se_sign(label: &str, msg: &[u8]) -> Result<[u8; 64]> {
    let key = find(label)?
        .ok_or_else(|| CliError::key_not_found(format!("no broker K3 key '{label}'")))?;
    sign_with(&key, msg)
}

/// The broker-key twin of [`keygen_err`] — a raw `&str` label (K3 is not a `KeyLabel`).
fn broker_keygen_err(label: &str, e: CFError) -> CliError {
    let detail = format!("{e:?}");
    if detail.contains("-34018") {
        CliError::unsupported_platform(format!(
            "Secure Enclave keygen for the broker's K3 key '{label}' failed: \
             errSecMissingEntitlement (-34018). The signet binary must be codesigned with a \
             provisioning-profile-authorized keychain-access-groups entitlement; for local/dev \
             use SIGNET_KEY_TIER=software."
        ))
    } else if detail_is_se_locked(&detail) {
        se_locked_err(format_args!("keygen for the broker's K3 key '{label}'"))
    } else {
        CliError::generic(format!(
            "Secure Enclave keygen for the broker's K3 key '{label}' failed: {e}"
        ))
    }
}

/// Map an SE keygen `CFError` to a `CliError`, calling out the common
/// missing-entitlement case with an actionable message.
fn keygen_err(label: &KeyLabel, e: CFError) -> CliError {
    let detail = format!("{e:?}");
    if detail.contains("-34018") {
        CliError::unsupported_platform(format!(
            "Secure Enclave keygen for '{}' failed: errSecMissingEntitlement (-34018). \
             The signet binary must be codesigned with a provisioning-profile-authorized \
             keychain-access-groups entitlement; for local/dev use SIGNET_KEY_TIER=software.",
            label.full()
        ))
    } else if detail_is_se_locked(&detail) {
        se_locked_err(format_args!("keygen for '{}'", label.full()))
    } else {
        CliError::generic(format!(
            "Secure Enclave keygen for '{}' failed: {e}",
            label.full()
        ))
    }
}

impl SecureEnclaveKeystore {
    /// Generate a PQ key (`signing-pq` → `SecureEnclave.MLDSA87`, `kem-pq` →
    /// `SecureEnclave.MLKEM1024`) via the CryptoKit shim and persist its sealed
    /// blob. The PQ algorithms are pinned one-per-purpose (PQR Spec §2), so a
    /// mismatched `algorithm` is refused rather than recorded.
    fn generate_pq(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
        // Pre-flight the SE-PQC availability floor for a crisp error up front
        // (each shim call is also guarded — this is the friendlier message).
        if !se_shim::pq_available() {
            return Err(CliError::unsupported_platform(
                "Secure-Enclave PQ keys require macOS 26 (the SE-PQC floor, PQR Spec §1); \
                 this Mac is running an older version",
            ));
        }
        let expected = label.purpose().default_alg();
        if algorithm != expected {
            return Err(CliError::unsupported_algorithm(format!(
                "a {} key is always {expected}, got algorithm '{algorithm}'",
                label.purpose().as_str()
            )));
        }
        if self.exists(label)? {
            return Err(CliError::key_exists(format!(
                "a key '{}' already exists in the Secure Enclave; delete it first",
                label.full()
            )));
        }
        let out = match label.purpose() {
            Purpose::SigningPq => se_shim::mldsa87_keygen()?,
            Purpose::KemPq => se_shim::mlkem1024_keygen()?,
            _ => unreachable!("generate_pq is only called for PQ purposes"),
        };
        pq_blob_store(&label.full(), &out.blob)?;
        Ok(KeyMeta {
            label: label.full(),
            purpose: label.purpose().as_str().to_string(),
            algorithm: expected.to_string(),
            storage: Tier::SecureEnclave.as_str().to_string(),
            // PQ-component fingerprint: SHA-256 over the raw FIPS 203/204
            // public-key bytes (PQR Spec §8.5) — not the P-256 SPKI convention.
            fingerprint: signet_crypto::pubkey::fingerprint_raw(&out.public_key),
            public_key: out.public_key,
        })
    }

    /// Metadata for a stored PQ key: restore the public key from the sealed
    /// blob (the blob is the single source of truth — nothing else is stored).
    fn meta_pq(&self, label: &KeyLabel) -> Result<KeyMeta> {
        let blob = pq_blob_find(&label.full())?.ok_or_else(|| {
            CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            ))
        })?;
        let public_key = match label.purpose() {
            Purpose::SigningPq => se_shim::mldsa87_vk_from_blob(&blob)?,
            Purpose::KemPq => se_shim::mlkem1024_ek_from_blob(&blob)?,
            _ => unreachable!("meta_pq is only called for PQ purposes"),
        };
        Ok(KeyMeta {
            label: label.full(),
            purpose: label.purpose().as_str().to_string(),
            algorithm: label.purpose().default_alg().to_string(),
            storage: Tier::SecureEnclave.as_str().to_string(),
            fingerprint: signet_crypto::pubkey::fingerprint_raw(&public_key),
            public_key,
        })
    }
}

/// Whether a label's purpose is one of the two PQ purposes (blob custody)
/// rather than a `SecKey` purpose (key-item custody).
fn is_pq(label: &KeyLabel) -> bool {
    matches!(label.purpose(), Purpose::SigningPq | Purpose::KemPq)
}

impl Keystore for SecureEnclaveKeystore {
    fn tier(&self) -> Tier {
        Tier::SecureEnclave
    }

    fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
        // The PQ purposes go through the CryptoKit shim (PQR item 1) — the SecKey
        // path below would otherwise mint a P-256 key under a PQ label.
        if matches!(label.purpose(), Purpose::SigningPq | Purpose::KemPq) {
            return self.generate_pq(label, algorithm);
        }
        if self.exists(label)? {
            return Err(CliError::key_exists(format!(
                "a key '{}' already exists in the Secure Enclave; delete it first",
                label.full()
            )));
        }
        let ac = access_control()?;
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain) // SE keys MUST use the DP keychain
            .set_label(label.full())
            .set_access_control(ac);
        let key = SecKey::new(&opts).map_err(|e| keygen_err(label, e))?;
        let public_key = pub_x963(&key)?;
        let fingerprint = signet_crypto::pubkey::fingerprint(&public_key)?;
        Ok(KeyMeta {
            label: label.full(),
            purpose: label.purpose().as_str().to_string(),
            algorithm: algorithm.to_string(),
            storage: Tier::SecureEnclave.as_str().to_string(),
            fingerprint,
            public_key,
        })
    }

    fn meta(&self, label: &KeyLabel) -> Result<KeyMeta> {
        if is_pq(label) {
            return self.meta_pq(label);
        }
        let key = find(&label.full())?.ok_or_else(|| {
            CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            ))
        })?;
        let public_key = pub_x963(&key)?;
        let fingerprint = signet_crypto::pubkey::fingerprint(&public_key)?;
        Ok(KeyMeta {
            label: label.full(),
            purpose: label.purpose().as_str().to_string(),
            // No sidecar: derive the v1 algorithm from the purpose (one alg per purpose).
            algorithm: label.purpose().default_alg().to_string(),
            storage: Tier::SecureEnclave.as_str().to_string(),
            fingerprint,
            public_key,
        })
    }

    fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]> {
        if label.purpose() != Purpose::Signing {
            return Err(CliError::unsupported_algorithm(
                "sign requires a signing (ES256) key",
            ));
        }
        let key = find(&label.full())?.ok_or_else(|| {
            CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            ))
        })?;
        sign_with(&key, msg)
    }

    fn ecdh(&self, label: &KeyLabel, peer_pub_x963: &[u8]) -> Result<[u8; 32]> {
        if label.purpose() != Purpose::Kem {
            return Err(CliError::unsupported_algorithm(
                "ecdh requires a KEM (ECDH) key",
            ));
        }
        let key = find(&label.full())?.ok_or_else(|| {
            CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            ))
        })?;
        ecdh_with(&key, peer_pub_x963)
    }

    fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]> {
        if label.purpose() != Purpose::KemPq {
            return Err(CliError::unsupported_algorithm(
                "ml-kem decapsulation requires a kem-pq (ML-KEM-1024) key",
            ));
        }
        let blob = pq_blob_find(&label.full())?.ok_or_else(|| {
            CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            ))
        })?;
        // The decapsulation runs inside the Enclave; the shim wrapper's transit
        // buffer is Zeroizing, and this returned copy follows the same caller-
        // managed contract as `ecdh`'s raw Z.
        Ok(*se_shim::mlkem1024_decap(&blob, ek)?)
    }

    fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        if label.purpose() != Purpose::SigningPq {
            return Err(CliError::unsupported_algorithm(
                "ml-dsa signing requires a signing-pq (ML-DSA-87) key",
            ));
        }
        let blob = pq_blob_find(&label.full())?.ok_or_else(|| {
            CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            ))
        })?;
        se_shim::mldsa87_sign(&blob, msg, ctx)
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        // Enumerate the keychain ITEM attribute dictionaries, not SecKey refs.
        //
        // The refs-based enumeration found every key, but then read each label via
        // `SecKeyCopyAttributes` (SecKey::attributes) — the key's *crypto* attribute
        // dictionary, which for Secure-Enclave keys does not carry the keychain
        // item's `kSecAttrLabel`. Every key looked label-less, the "only our keys"
        // filter dropped them all, and `keys list` showed empty while every
        // label-queried operation (sign/ecdh/delete/fingerprint via `find`) worked
        // — S059 finding #3, root-caused S061 with a live query-matrix probe on
        // real hardware. The item dictionaries DO carry `kSecAttrLabel`; each
        // labelled key is then resolved through the proven `find` path for its
        // public half.
        use security_framework_sys::item::kSecAttrLabel;
        let results = match ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .ignore_legacy_keychains()
            .load_attributes(true)
            .limit(Limit::All)
            .search()
        {
            Ok(results) => results,
            // No keys yet surfaces as errSecItemNotFound — an empty list, not an error.
            Err(e) if e.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(e) if e.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
                return Err(se_locked_err("the key list"));
            }
            Err(e) => return Err(CliError::generic(format!("Secure Enclave key list: {e}"))),
        };
        let mut out = Vec::new();
        for r in results {
            let SearchResult::Dict(attrs) = r else {
                continue;
            };
            // Only our keys: the item label must parse as `<handle>-<purpose>`.
            // Anything else sharing the keychain access group is skipped.
            let Some(label_str) = attrs
                .find(unsafe { kSecAttrLabel }.to_void())
                .map(|v| unsafe { CFString::wrap_under_get_rule(v.cast()) }.to_string())
            else {
                continue;
            };
            let Ok(label) = KeyLabel::parse(&label_str, None) else {
                continue;
            };
            let Some(key) = find(&label.full())? else {
                continue; // raced a concurrent delete — skip, don't fail the list
            };
            let public_key = pub_x963(&key)?;
            let fingerprint = signet_crypto::pubkey::fingerprint(&public_key)?;
            out.push(KeyMeta {
                label: label.full(),
                purpose: label.purpose().as_str().to_string(),
                algorithm: label.purpose().default_alg().to_string(),
                storage: Tier::SecureEnclave.as_str().to_string(),
                fingerprint,
                public_key,
            });
        }
        // The PQ keys (sealed-blob custody, PQR item 1): enumerate the blob
        // items and restore each public key from its blob. Anything not
        // parseable as one of our PQ labels is skipped, same as above.
        for label_str in pq_blob_labels()? {
            let Ok(label) = KeyLabel::parse(&label_str, None) else {
                continue;
            };
            if !is_pq(&label) {
                continue;
            }
            match self.meta_pq(&label) {
                Ok(meta) => out.push(meta),
                // Raced a concurrent delete — skip, don't fail the list.
                Err(e) if e.code == "key_not_found" => continue,
                Err(e) => return Err(e),
            }
        }
        out.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(out)
    }

    fn delete(&self, label: &KeyLabel) -> Result<()> {
        if !self.exists(label)? {
            return Err(CliError::key_not_found(format!(
                "no key '{}'",
                label.full()
            )));
        }
        if is_pq(label) {
            return pq_blob_delete(&label.full());
        }
        ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .ignore_legacy_keychains()
            .label(&label.full())
            .delete()
            .map_err(|e| {
                CliError::generic(format!(
                    "deleting Secure Enclave key '{}': {e}",
                    label.full()
                ))
            })
    }

    fn exists(&self, label: &KeyLabel) -> Result<bool> {
        if is_pq(label) {
            return Ok(pq_blob_find(&label.full())?.is_some());
        }
        Ok(find(&label.full())?.is_some())
    }
}

#[cfg(test)]
mod tests {
    //! SE-backend tests, Apple-Silicon-Mac-only (cfg'd out on linux CI).
    //!
    //! All are `#[ignore]` (SE ops need real hardware + an **unlocked** macOS
    //! session — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` returns -25308
    //! when the screen is locked — neither of which holds under CI or a headless
    //! `cargo test`). Run them manually on this M4, screen unlocked:
    //! `cargo test -p signet-cli --lib -- --ignored`.
    //!
    //! Two tiers:
    //! - The **crypto** tests use a *transient* SE key (no keychain add → no
    //!   entitlement) to exercise the real `sign_with` / `ecdh_with` helpers
    //!   against `signet-crypto` on an **unsigned** build.
    //! - The **persistent** trait-path test additionally needs a signed +
    //!   provisioning-profile-entitled binary.
    use super::*;

    /// A transient SE key (no `set_location` ⇒ not added to the keychain ⇒ no
    /// entitlement needed). Lets the crypto helpers be tested on an unsigned build.
    fn transient_key() -> SecKey {
        let ac = access_control().expect("access control");
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(ac);
        SecKey::new(&opts).expect("transient SE key generation")
    }

    #[test]
    #[ignore = "SE keygen needs an unlocked macOS session (-25308 when locked); run with --ignored"]
    fn se_sign_verifies_under_signet_crypto() {
        let key = transient_key();
        let pubkey = pub_x963(&key).expect("pubkey");
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04);
        let msg = b"SIGNET-V1 canonical bytes to sign";
        let raw = sign_with(&key, msg).expect("se sign");
        // The raw r‖s the trait returns verifies under the shared crypto crate.
        signet_crypto::ecdsa::verify_es256(&pubkey, msg, &raw).expect("verify");
    }

    #[test]
    #[ignore = "SE keygen needs an unlocked macOS session (-25308 when locked); run with --ignored"]
    fn se_ecdh_matches_software_path() {
        let key = transient_key();
        let se_pub = pub_x963(&key).expect("se pubkey");
        // Ephemeral software keypair; we hold its scalar to compute Z the other way.
        let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
        let z_se = ecdh_with(&key, &eph_pub).expect("se ecdh");
        let z_sw = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &se_pub).expect("sw ecdh");
        assert_eq!(z_se, z_sw, "SE Z must equal the software P-256 Z");
    }

    // --- SE-PQC crypto tests (PQR item 1) — unsigned tier. -----------------------
    //
    // CryptoKit SE PQ keygen/decap/sign need NO keychain entitlement — only blob
    // *persistence* does (the S103 probe ran unsigned; Gus's feasibility fact #5).
    // The generated key lives only as its returned sealed blob here (dropping the
    // blob is the cleanup), so these run under a plain `cargo test -- --ignored`
    // on Apple Silicon + macOS 26, screen unlocked. They are the first live legs
    // of the spec §11.2 RustCrypto ↔ CryptoKit/SE two-lineage differential.
    // The *persistent* PQ trait path (keychain blob custody) is exercised by the
    // entitled `pq_se_hw` example (see cli/examples/pq_se_hw.rs).

    #[test]
    #[ignore = "needs Apple Silicon + macOS 26 + an unlocked session; run with --ignored"]
    fn se_mlkem_blob_roundtrip_and_decap_differential_vs_rustcrypto() {
        use kem::Encapsulate;
        use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};

        let out = se_shim::mlkem1024_keygen().expect("SE ML-KEM-1024 keygen");
        assert_eq!(out.public_key.len(), 1568, "FIPS 203 ek length");

        // Blob round-trip: the sealed blob restores to the same public key.
        let ek2 = se_shim::mlkem1024_ek_from_blob(&out.blob).expect("blob restore");
        assert_eq!(out.public_key, ek2, "ek must survive the blob round-trip");

        // Differential (spec §11.2): RustCrypto encapsulates to the SE key's ek;
        // the Enclave decapsulates; the two independent lineages must agree.
        let ek_arr = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(
            out.public_key.as_slice(),
        )
        .expect("ek size");
        let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
        let (ct, ss_rust) = ek.encapsulate(&mut rand_core::OsRng).expect("encaps");
        let ss_se = se_shim::mlkem1024_decap(&out.blob, ct.as_slice()).expect("SE decap");
        assert_eq!(
            ss_se.as_slice(),
            ss_rust.as_slice(),
            "RustCrypto and CryptoKit/SE must derive the same shared secret"
        );

        // FIPS 203 implicit rejection (spec §10): a tampered ciphertext
        // decapsulates WITHOUT error, to a different (pseudorandom) secret.
        let mut ct_bad = ct.as_slice().to_vec();
        ct_bad[0] ^= 0x01;
        let ss_bad =
            se_shim::mlkem1024_decap(&out.blob, &ct_bad).expect("implicit rejection returns Ok");
        assert_ne!(ss_bad.as_slice(), ss_rust.as_slice());
    }

    #[test]
    #[ignore = "needs Apple Silicon + macOS 26 + an unlocked session; run with --ignored"]
    fn se_mldsa_sign_verifies_under_rustcrypto_with_ctx_bound() {
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};

        let out = se_shim::mldsa87_keygen().expect("SE ML-DSA-87 keygen");
        assert_eq!(out.public_key.len(), 2592, "FIPS 204 vk length");
        let vk2 = se_shim::mldsa87_vk_from_blob(&out.blob).expect("blob restore");
        assert_eq!(out.public_key, vk2, "vk must survive the blob round-trip");

        let msg = b"SIGNET-V1 canonical dual-sign base";
        let ctx = b"signet:attest:v1";
        let sig = se_shim::mldsa87_sign(&out.blob, msg, ctx).expect("SE sign");
        assert_eq!(sig.len(), 4627, "FIPS 204 signature length");

        // Differential: the SE's hedged signature verifies under RustCrypto.
        let vk_arr =
            EncodedVerifyingKey::<MlDsa87>::try_from(out.public_key.as_slice()).expect("vk size");
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
        let sig_arr = EncodedSignature::<MlDsa87>::try_from(sig.as_slice()).expect("sig size");
        let sig_dec = Signature::<MlDsa87>::decode(&sig_arr).expect("sig decode");
        assert!(
            vk.verify_with_context(msg, ctx, &sig_dec),
            "SE signature must verify under the RustCrypto lineage"
        );
        // The FIPS 204 context is bound (spec §8 point 4): a different purpose
        // string must not verify — and neither must a different message.
        assert!(!vk.verify_with_context(msg, b"signet:req:v1", &sig_dec));
        assert!(!vk.verify_with_context(b"other message", ctx, &sig_dec));
    }

    #[test]
    #[ignore = "needs Apple Silicon + macOS 26 + an unlocked session; run with --ignored"]
    fn hybrid_wrap_roundtrip_with_real_se_decap() {
        use kem::Encapsulate;
        use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
        use signet_crypto::hybrid_wrap;

        // Recipient hybrid KEM keys: classical = a software P-256 pair (we hold
        // the scalar to play the recipient); PQ = a REAL Secure-Enclave key.
        let (rk_scalar, rk_ec) = signet_crypto::ecdh::generate_keypair();
        let kem_key = se_shim::mlkem1024_keygen().expect("SE keygen");

        // Writer side (spec §4.5): ephemeral ECDH + RustCrypto ML-KEM encaps.
        let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
        let z_ecdh_w = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &rk_ec).expect("writer ecdh");
        let ek_arr = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(
            kem_key.public_key.as_slice(),
        )
        .expect("ek size");
        let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
        let (ct, ss) = ek.encapsulate(&mut rand_core::OsRng).expect("encaps");
        let z_mlkem_w: [u8; 32] = ss.as_slice().try_into().unwrap();

        let dek = [0x42u8; 32];
        let env = hybrid_wrap::wrap_from_secrets(
            &z_ecdh_w,
            &z_mlkem_w,
            &eph_pub,
            ct.as_slice(),
            &rk_ec,
            &kem_key.public_key,
            &dek,
            b"",
        )
        .expect("hybrid wrap");

        // Recipient side (spec §5.3): Z_ecdh from the recipient scalar; Z_mlkem
        // from the REAL Secure-Enclave decapsulation.
        let z_ecdh_r =
            signet_crypto::ecdh::ecdh_p256(&rk_scalar, &eph_pub).expect("recipient ecdh");
        let z_mlkem_r = se_shim::mlkem1024_decap(&kem_key.blob, ct.as_slice()).expect("SE decap");
        let dek2 = hybrid_wrap::unwrap_with_shared_secrets(
            &z_ecdh_r,
            &z_mlkem_r,
            &env,
            &rk_ec,
            &kem_key.public_key,
            b"",
        )
        .expect("hybrid unwrap");
        assert_eq!(dek, dek2, "the DEK must round-trip through the real SE leg");
    }

    // --- Persistent trait path: needs a signed + entitled (provisioned) build. ---

    #[test]
    #[ignore = "persistent SE path needs a provisioning-profile-entitled binary; run manually"]
    fn persistent_generate_sign_ecdh_list_delete() {
        let ks = SecureEnclaveKeystore::open().unwrap();
        let s = KeyLabel::parse("hlin-ai-test-signing", Some(Purpose::Signing)).unwrap();
        let k = KeyLabel::parse("hlin-ai-test-kem", Some(Purpose::Kem)).unwrap();
        // Clean any prior run.
        let _ = ks.delete(&s);
        let _ = ks.delete(&k);

        let sm = ks.generate(&s, "ES256").unwrap();
        assert_eq!(sm.storage, "secure-enclave");
        assert_eq!(sm.public_key.len(), 65);
        let km = ks.generate(&k, "ECDH-ES+A256KW").unwrap();

        // Duplicate keygen is rejected.
        assert_eq!(ks.generate(&s, "ES256").unwrap_err().exit_code, 11);

        // Sign via cross-lookup, verify under signet-crypto.
        let msg = b"persistent path";
        let sig = ks.sign(&s, msg).unwrap();
        signet_crypto::ecdsa::verify_es256(&sm.public_key, msg, &sig).unwrap();

        // ECDH agrees with the software computation from the peer side.
        let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
        let z_se = ks.ecdh(&k, &eph_pub).unwrap();
        let z_sw = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &km.public_key).unwrap();
        assert_eq!(z_se, z_sw);

        // Purpose guards.
        assert_eq!(ks.sign(&k, b"x").unwrap_err().exit_code, 41);
        assert_eq!(ks.ecdh(&s, &[0x04; 65]).unwrap_err().exit_code, 41);

        // list shows both, sorted.
        let listed = ks.list().unwrap();
        assert!(listed.iter().any(|m| m.label == "hlin-ai-test-signing"));
        assert!(listed.iter().any(|m| m.label == "hlin-ai-test-kem"));

        // delete + exists.
        ks.delete(&s).unwrap();
        assert!(!ks.exists(&s).unwrap());
        assert_eq!(ks.delete(&s).unwrap_err().exit_code, 12);
        ks.delete(&k).unwrap();
    }

    /// bug057 — the lock-gated translation, pinned. NOT #[ignore]: these test the
    /// mapping helpers, not the enclave, so they run in the normal native slice.
    #[test]
    fn se_locked_error_is_translated_and_coded() {
        let e = se_locked_err("the PQ key lookup 'x-signing-pq'");
        assert_eq!(e.exit_code, 52);
        assert_eq!(e.code, "se_locked");
        // The situation, not the mechanism: says locked + retryable, and does NOT
        // leak Apple's wording as the primary line.
        assert!(e.message.contains("this Mac is locked"));
        assert!(e.message.contains("retry after unlock"));
        assert!(!e.message.starts_with("User interaction"));
    }

    #[test]
    fn se_locked_detail_detection() {
        // The two shapes a CFError debug/display can carry for -25308.
        assert!(detail_is_se_locked("Error { code: -25308, ... }"));
        assert!(detail_is_se_locked(
            "The operation couldn\u{2019}t be completed. User interaction is not allowed."
        ));
        // Negative: the entitlement error must keep its own branch.
        assert!(!detail_is_se_locked("Error { code: -34018, ... }"));
        assert!(!detail_is_se_locked("errSecItemNotFound"));
    }
}
