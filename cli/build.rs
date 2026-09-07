// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Build script — compiles the Swift/CryptoKit Secure-Enclave PQC shim
//! (`shim/SignetSeShim.swift`) into a static library and links it into the CLI,
//! **macOS targets only** (PQR item 1).
//!
//! Why here and not a pipeline script: `cargo build` is the one step every path
//! shares — dev iteration, the entitled hardware-proof wrap
//! (`sign-example-for-se.sh`), and the notarized release
//! (`build-signet-release.sh`) — so compiling the shim inside it means no wrapper
//! script can ever ship a binary that forgot the shim. Linux CI and the
//! static-musl container helper build never reach this (target_os gate below);
//! the shim's Rust callers are equally `cfg(target_os = "macos")`.
//!
//! The Swift runtime has been ABI-stable since Swift 5 — the produced binary
//! links the OS-provided Swift runtime (`/usr/lib/swift`), not a bundled one.
//! CryptoKit/Foundation/Security are linked as frameworks. The shim itself
//! availability-guards the macOS-26 SE-PQC API at runtime, so the binary still
//! loads on older macOS and the PQ ops fail closed (`unsupported_platform`).
//!
//! Determinism note (R2/R4): the swiftc invocation deliberately keeps a minimal,
//! fixed flag set. The release-pipeline determinism work (fixed flags audit +
//! the manifest `swiftc` field) is PQR item 1 PR 2.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Target the *compilation target*, not the host: the Docker static-musl Linux
    // helper build runs on macOS hosts but targets linux — no shim there either.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let shim_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("shim/SignetSeShim.swift");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let lib_path = out_dir.join("libsignet_se_shim.a");

    println!("cargo:rerun-if-changed={}", shim_src.display());

    // arm64 is the only supported Apple target (Apple Silicon; 1-Pager §Users).
    // Keep the deployment target aligned with Rust's aarch64-apple-darwin default
    // (macOS 11) so the binary loads everywhere the CLI already ran; the SE-PQC
    // calls inside are #available-guarded to macOS 26.
    let status = Command::new("swiftc")
        .args([
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-module-name",
            "SignetSeShim",
            "-target",
            "arm64-apple-macosx11.0",
            "-O",
        ])
        .arg("-o")
        .arg(&lib_path)
        .arg(&shim_src)
        .status()
        .expect(
            "failed to run swiftc — building signet-cli on macOS requires a Swift \
             toolchain (Xcode or Command Line Tools) for the Secure-Enclave PQC shim",
        );
    assert!(status.success(), "swiftc failed compiling the SE PQC shim");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=signet_se_shim");

    // The Swift runtime: link against the SDK's .tbd stubs; at run time the
    // OS-provided ABI-stable runtime resolves from the dyld cache.
    if let Ok(sdk_path) = Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    {
        println!("cargo:rustc-link-search=native={sdk_path}/usr/lib/swift");
    }
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    // The Swift back-compatibility static libs (libswiftCompatibility56 etc.):
    // targeting macOS 11 makes swiftc force-load them, and they live in the
    // Xcode *toolchain*, not the SDK. They only activate on pre-13 hosts.
    if let Ok(swiftc) = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    {
        // …/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc → …/usr/lib/swift/macosx
        if let Some(usr) = PathBuf::from(&swiftc).parent().and_then(|p| p.parent()) {
            println!(
                "cargo:rustc-link-search=native={}",
                usr.join("lib/swift/macosx").display()
            );
        }
    }
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
}
