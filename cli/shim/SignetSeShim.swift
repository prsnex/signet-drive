// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//
// SignetSeShim.swift — the Swift/CryptoKit Secure-Enclave PQC shim (PQR item 1).
//
// `SecureEnclave.MLKEM1024` and `SecureEnclave.MLDSA87` are CryptoKit-Swift-only —
// the macOS 26 SDK's Security.framework carries zero ML-KEM/ML-DSA symbols (verified
// against the SDK headers, S103) — so the Rust keystore reaches the Enclave's PQC
// through this shim over a C ABI. It is compiled by `cli/build.rs` (swiftc, macOS
// targets only; Linux CI never sees it) and statically linked into `signet`.
//
// Design rules (PQR Crypto Spec §6/§8 + Build-Plan item 1):
// - Keys are GENERATED IN the Secure Enclave; the only thing that crosses this ABI
//   is the SE-sealed `dataRepresentation` blob (opaque, useless off this device),
//   public-key bytes, ciphertexts, signatures, and the decapsulated shared secret.
//   Private key material never exists in extractable form on either side.
// - Access policy matches the existing SE P-256 keys: `kSecAttrAccessibleWhen-
//   UnlockedThisDeviceOnly`, no biometry flag (CLI Spec §"Key storage") — passed
//   explicitly because CryptoKit's default is the weaker AfterFirstUnlock.
// - ML-DSA signing is HEDGED (the SE default; FIPS 204) and the context string is
//   supplied as the FIPS 204 context PARAMETER — never prepended to the message
//   (spec §8.7). The ≤255-byte ceiling is re-validated here (defense in depth; the
//   wire dispatch already enforced it).
// - No Swift types cross the ABI: caller-allocated buffers + explicit lengths in,
//   `Int32` status codes out, with a truncated UTF-8 error message written to the
//   caller's err buffer on failure. All functions are runtime-availability-guarded
//   (`#available(macOS 26.0, *)`) so the binary still loads and fails closed with
//   SIGNET_SE_ERR_UNAVAILABLE on older macOS.
// - Zeroization: the decapsulated secret is copied straight from CryptoKit's buffer
//   into the caller's (which the Rust side wraps in `Zeroizing`). CryptoKit's own
//   internal copies are not reachable to wipe — the same named best-effort residual
//   as the hkdf crate's internal PRK (crypto/src/hybrid_wrap.rs §4.6 note).

import CryptoKit
import Foundation
import Security

// Status codes — keep in sync with cli/src/keystore/se_shim.rs.
private let SIGNET_SE_OK: Int32 = 0
private let SIGNET_SE_ERR_UNAVAILABLE: Int32 = -1 // macOS < 26: no SE-PQC API
private let SIGNET_SE_ERR_KEYGEN: Int32 = -2
private let SIGNET_SE_ERR_BAD_BLOB: Int32 = -3 // dataRepresentation rejected
private let SIGNET_SE_ERR_DECAP: Int32 = -4
private let SIGNET_SE_ERR_SIGN: Int32 = -5
private let SIGNET_SE_ERR_BUFFER: Int32 = -6 // caller buffer too small
private let SIGNET_SE_ERR_BAD_INPUT: Int32 = -7 // wrong input length / bad args

/// Write `msg` (UTF-8, truncated to fit) into the caller's error buffer.
private func fillErr(
    _ msg: String,
    _ errOut: UnsafeMutablePointer<UInt8>?,
    _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) {
    guard let errOut = errOut, errCap > 0 else {
        errLen?.pointee = 0
        return
    }
    let bytes = Array(msg.utf8.prefix(errCap))
    bytes.withUnsafeBufferPointer { src in
        errOut.update(from: src.baseAddress!, count: src.count)
    }
    errLen?.pointee = bytes.count
}

/// Copy `data` into a caller-allocated buffer, or fail with SIGNET_SE_ERR_BUFFER.
private func copyOut(
    _ data: Data,
    _ out: UnsafeMutablePointer<UInt8>?,
    _ cap: Int,
    _ len: UnsafeMutablePointer<Int>?
) -> Bool {
    guard let out = out, let len = len, data.count <= cap else { return false }
    data.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
        if let base = src.baseAddress, src.count > 0 {
            out.update(from: base.assumingMemoryBound(to: UInt8.self), count: src.count)
        }
    }
    len.pointee = data.count
    return true
}

/// The suite access policy for SE keys: WhenUnlockedThisDeviceOnly, no
/// biometry/user-presence flags — identical to the P-256 keys' policy
/// (cli/src/keystore/secure_enclave.rs `access_control()`).
private func suiteAccessControl() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [],
        nil
    )
}

/// 1 if the SE-PQC API is available at runtime (macOS 26+), else 0. Purely an
/// availability probe — does not touch the Enclave.
@_cdecl("signet_se_pq_available")
public func signet_se_pq_available() -> Int32 {
    if #available(macOS 26.0, *) { return 1 }
    return 0
}

// ── ML-KEM-1024 ───────────────────────────────────────────────────────────────

/// Generate an ML-KEM-1024 key in the Secure Enclave. Out: the SE-sealed
/// `dataRepresentation` blob + the FIPS 203 encapsulation key (1568 B).
@_cdecl("signet_se_mlkem1024_keygen")
public func signet_se_mlkem1024_keygen(
    _ blobOut: UnsafeMutablePointer<UInt8>?, _ blobCap: Int,
    _ blobLen: UnsafeMutablePointer<Int>?,
    _ ekOut: UnsafeMutablePointer<UInt8>?, _ ekCap: Int,
    _ ekLen: UnsafeMutablePointer<Int>?,
    _ errOut: UnsafeMutablePointer<UInt8>?, _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        fillErr("SecureEnclave ML-KEM-1024 requires macOS 26", errOut, errCap, errLen)
        return SIGNET_SE_ERR_UNAVAILABLE
    }
    guard let ac = suiteAccessControl() else {
        fillErr("SecAccessControlCreateWithFlags failed", errOut, errCap, errLen)
        return SIGNET_SE_ERR_KEYGEN
    }
    do {
        let key = try SecureEnclave.MLKEM1024.PrivateKey(accessControl: ac)
        guard copyOut(key.dataRepresentation, blobOut, blobCap, blobLen) else {
            fillErr("blob buffer too small (need \(key.dataRepresentation.count))",
                    errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        guard copyOut(key.publicKey.rawRepresentation, ekOut, ekCap, ekLen) else {
            fillErr("ek buffer too small", errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        return SIGNET_SE_OK
    } catch {
        fillErr("SE ML-KEM-1024 keygen: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_KEYGEN
    }
}

/// Recover the encapsulation key (1568 B) from a sealed blob.
@_cdecl("signet_se_mlkem1024_ek_from_blob")
public func signet_se_mlkem1024_ek_from_blob(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int,
    _ ekOut: UnsafeMutablePointer<UInt8>?, _ ekCap: Int,
    _ ekLen: UnsafeMutablePointer<Int>?,
    _ errOut: UnsafeMutablePointer<UInt8>?, _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        fillErr("SecureEnclave ML-KEM-1024 requires macOS 26", errOut, errCap, errLen)
        return SIGNET_SE_ERR_UNAVAILABLE
    }
    guard let blob = blob, blobLen > 0 else {
        fillErr("empty key blob", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_INPUT
    }
    do {
        let key = try SecureEnclave.MLKEM1024.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen))
        guard copyOut(key.publicKey.rawRepresentation, ekOut, ekCap, ekLen) else {
            fillErr("ek buffer too small", errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        return SIGNET_SE_OK
    } catch {
        fillErr("SE ML-KEM-1024 blob restore: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_BLOB
    }
}

/// Decapsulate a 1568-byte ML-KEM-1024 ciphertext in the Enclave → the 32-byte
/// shared secret. NOTE (spec §10, FIPS 203 implicit rejection): a tampered
/// ciphertext does NOT error here — it yields a pseudorandom secret; the failure
/// surfaces downstream at AES-KW integrity check.
@_cdecl("signet_se_mlkem1024_decap")
public func signet_se_mlkem1024_decap(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int,
    _ ct: UnsafePointer<UInt8>?, _ ctLen: Int,
    _ ssOut: UnsafeMutablePointer<UInt8>?, _ ssCap: Int,
    _ errOut: UnsafeMutablePointer<UInt8>?, _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        fillErr("SecureEnclave ML-KEM-1024 requires macOS 26", errOut, errCap, errLen)
        return SIGNET_SE_ERR_UNAVAILABLE
    }
    guard let blob = blob, blobLen > 0 else {
        fillErr("empty key blob", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_INPUT
    }
    guard let ct = ct, ctLen == 1568 else {
        fillErr("ml-kem ciphertext must be 1568 bytes, got \(ctLen)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_INPUT
    }
    guard let ssOut = ssOut, ssCap >= 32 else {
        fillErr("shared-secret buffer must be >= 32 bytes", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BUFFER
    }
    let key: SecureEnclave.MLKEM1024.PrivateKey
    do {
        key = try SecureEnclave.MLKEM1024.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen))
    } catch {
        fillErr("SE ML-KEM-1024 blob restore: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_BLOB
    }
    do {
        let ss = try key.decapsulate(Data(bytes: ct, count: ctLen))
        let ok = ss.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Bool in
            guard src.count == 32, let base = src.baseAddress else { return false }
            ssOut.update(from: base.assumingMemoryBound(to: UInt8.self), count: 32)
            return true
        }
        guard ok else {
            fillErr("decapsulation returned a non-32-byte secret", errOut, errCap, errLen)
            return SIGNET_SE_ERR_DECAP
        }
        return SIGNET_SE_OK
    } catch {
        fillErr("SE ML-KEM-1024 decapsulation: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_DECAP
    }
}

// ── ML-DSA-87 ─────────────────────────────────────────────────────────────────

/// Generate an ML-DSA-87 key in the Secure Enclave. Out: the SE-sealed blob +
/// the FIPS 204 verification key (2592 B).
@_cdecl("signet_se_mldsa87_keygen")
public func signet_se_mldsa87_keygen(
    _ blobOut: UnsafeMutablePointer<UInt8>?, _ blobCap: Int,
    _ blobLen: UnsafeMutablePointer<Int>?,
    _ vkOut: UnsafeMutablePointer<UInt8>?, _ vkCap: Int,
    _ vkLen: UnsafeMutablePointer<Int>?,
    _ errOut: UnsafeMutablePointer<UInt8>?, _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        fillErr("SecureEnclave ML-DSA-87 requires macOS 26", errOut, errCap, errLen)
        return SIGNET_SE_ERR_UNAVAILABLE
    }
    guard let ac = suiteAccessControl() else {
        fillErr("SecAccessControlCreateWithFlags failed", errOut, errCap, errLen)
        return SIGNET_SE_ERR_KEYGEN
    }
    do {
        let key = try SecureEnclave.MLDSA87.PrivateKey(accessControl: ac)
        guard copyOut(key.dataRepresentation, blobOut, blobCap, blobLen) else {
            fillErr("blob buffer too small (need \(key.dataRepresentation.count))",
                    errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        guard copyOut(key.publicKey.rawRepresentation, vkOut, vkCap, vkLen) else {
            fillErr("vk buffer too small", errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        return SIGNET_SE_OK
    } catch {
        fillErr("SE ML-DSA-87 keygen: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_KEYGEN
    }
}

/// Recover the verification key (2592 B) from a sealed blob.
@_cdecl("signet_se_mldsa87_vk_from_blob")
public func signet_se_mldsa87_vk_from_blob(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int,
    _ vkOut: UnsafeMutablePointer<UInt8>?, _ vkCap: Int,
    _ vkLen: UnsafeMutablePointer<Int>?,
    _ errOut: UnsafeMutablePointer<UInt8>?, _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        fillErr("SecureEnclave ML-DSA-87 requires macOS 26", errOut, errCap, errLen)
        return SIGNET_SE_ERR_UNAVAILABLE
    }
    guard let blob = blob, blobLen > 0 else {
        fillErr("empty key blob", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_INPUT
    }
    do {
        let key = try SecureEnclave.MLDSA87.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen))
        guard copyOut(key.publicKey.rawRepresentation, vkOut, vkCap, vkLen) else {
            fillErr("vk buffer too small", errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        return SIGNET_SE_OK
    } catch {
        fillErr("SE ML-DSA-87 blob restore: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_BLOB
    }
}

/// Sign `msg` with the SE-resident ML-DSA-87 key (HEDGED — the SE default), with
/// `ctx` supplied as the FIPS 204 context parameter (spec §8.7 — never prepended
/// to the message). Out: the 4627-byte FIPS 204 signature.
@_cdecl("signet_se_mldsa87_sign")
public func signet_se_mldsa87_sign(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int,
    _ msg: UnsafePointer<UInt8>?, _ msgLen: Int,
    _ ctx: UnsafePointer<UInt8>?, _ ctxLen: Int,
    _ sigOut: UnsafeMutablePointer<UInt8>?, _ sigCap: Int,
    _ sigLen: UnsafeMutablePointer<Int>?,
    _ errOut: UnsafeMutablePointer<UInt8>?, _ errCap: Int,
    _ errLen: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        fillErr("SecureEnclave ML-DSA-87 requires macOS 26", errOut, errCap, errLen)
        return SIGNET_SE_ERR_UNAVAILABLE
    }
    guard let blob = blob, blobLen > 0 else {
        fillErr("empty key blob", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_INPUT
    }
    // The FIPS 204 context ceiling — re-validated at the shim boundary (defense in
    // depth; the wire dispatch + forwarding backends validated it already).
    guard ctxLen <= 255 else {
        fillErr("ML-DSA context must be at most 255 bytes, got \(ctxLen)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_INPUT
    }
    let msgData = (msgLen > 0 && msg != nil) ? Data(bytes: msg!, count: msgLen) : Data()
    let ctxData = (ctxLen > 0 && ctx != nil) ? Data(bytes: ctx!, count: ctxLen) : Data()
    let key: SecureEnclave.MLDSA87.PrivateKey
    do {
        key = try SecureEnclave.MLDSA87.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen))
    } catch {
        fillErr("SE ML-DSA-87 blob restore: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_BAD_BLOB
    }
    do {
        let sig = try key.signature(for: msgData, context: ctxData)
        guard copyOut(sig, sigOut, sigCap, sigLen) else {
            fillErr("signature buffer too small (need \(sig.count))", errOut, errCap, errLen)
            return SIGNET_SE_ERR_BUFFER
        }
        return SIGNET_SE_OK
    } catch {
        fillErr("SE ML-DSA-87 signing: \(error)", errOut, errCap, errLen)
        return SIGNET_SE_ERR_SIGN
    }
}
