#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PRSN EX Inc.
#
# Build the two committed wasm pkgs the web client imports (PQR item 4/6; §1-67).
#
#   web/src/lib/crypto/mlkem-wasm/  `--features mlkem`: ML-KEM-1024, loaded by every session
#   web/src/lib/crypto/vrf-wasm/    `--features vrf`:   the account-index verifier, loaded only
#                                   by a share (Launch Punch-List §1-67), with no randomness
#
# The wasm-pack output is COMMITTED, not
# built by web-ci: the web pipeline stays Node-only, and the committed .wasm is
# the deterministic artifact the bundle manifest + SRI story hashes (PQR Spec
# §7/§9.3). Drift is impossible: the `wasm-pkg-repro` step in ci.yml re-runs
# this script and byte-compares the result against the committed files on
# every touching PR.
#
# THE BUILD RUNS INSIDE A DIGEST-PINNED LINUX CONTAINER (the S002 pattern the
# release pipeline uses for the Linux binary) — on developer Macs AND on CI.
# PR #253's repro gate proved host-native builds are not byte-stable across
# platforms even with rustc + wasm-pack pinned and source paths remapped
# (three variance layers caught: embedded host paths → per-platform binaryen
# wasm-opt output [now disabled in Cargo.toml] → residual host-arch/cargo
# metadata variance). Fixing each layer piecemeal is whack-a-mole; the
# container fixes ALL of them by construction: same OS, same arch
# (linux/amd64, emulated on Apple Silicon), same paths (/build,
# /usr/local/cargo), same toolchain (rust-toolchain.toml inside the mount).
#
# THE TWO STEPS wasm-pack ran, by hand, and one flag more (v1.1.1; Gus's ruling,
# 2026-11-01): `cargo build --lib --release` for wasm32, then the wasm-bindgen CLI with
# exactly wasm-pack 0.14.0's arguments (`--typescript --target web --out-name`, read
# from its src/bindgen.rs) plus `--remove-name-section`, which drops only the debug
# names (154 KB of the ML-KEM asset's 213 KB) and leaves every code byte as the vectors
# saw it. wasm-pack offered no way to pass that flag. The CLI is built from crates.io
# source inside this container at the Cargo.lock version, `--locked`, so no release
# asset is trusted in the crypto artifact's path (Gus, over Bob's prebuilt-by-checksum);
# its own sha256 is printed, so two builds show the same CLI. No optimizer runs: wasm-pack's
# `wasm-opt` is binaryen "latest", unpinned (a later, measured change of its own).
#
# Requires Docker (already a dev-stack requirement). Regeneration is rare —
# only when crypto-wasm/ or the toolchain pin changes.
#
# Usage: crypto-wasm/build-web-pkg.sh          (from anywhere; paths are repo-relative)

set -euo pipefail

# The wasm-bindgen CLI must be the version Cargo.lock resolves for the `wasm-bindgen`
# crate (the glue and the module must agree); a mismatch stops the build here.
WASM_BINDGEN_VERSION="0.2.122"
# rust:1.99.1-bookworm, digest-pinned (multi-arch manifest; --platform selects
# amd64). Bump together with rust-toolchain.toml — the image toolchain must
# match the pin or rustup downloads inside the container.
RUST_IMAGE="rust@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
locked="$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/version = |"/, ""); print; exit}' "$REPO_ROOT/Cargo.lock")"
[ "$locked" = "$WASM_BINDGEN_VERSION" ] || {
  echo "build-web-pkg: Cargo.lock resolves wasm-bindgen $locked, but this script builds the CLI at $WASM_BINDGEN_VERSION: bump them together" >&2
  exit 1
}
# Each pkg: <out-dir under web/src/lib/crypto> <out-name> <cargo feature>.
PKGS="mlkem-wasm:signet_crypto_wasm:mlkem vrf-wasm:signet_vrf_wasm:vrf"

docker run --rm --platform linux/amd64 \
  -v "$REPO_ROOT":/build -w /build \
  -e WASM_BINDGEN_VERSION="$WASM_BINDGEN_VERSION" \
  -e PKGS="$PKGS" \
  "$RUST_IMAGE" \
  bash -euo pipefail -c '
    # The wasm-bindgen CLI from crates.io source at the exact version, under the
    # lockfile the crate ships (--locked refuses a drifted dependency set). Built
    # before RUSTFLAGS is set, in its own target dir, so nothing below sees it.
    CARGO_TARGET_DIR=/tmp/wasm-bindgen-target cargo install --quiet --locked \
      wasm-bindgen-cli --version "=${WASM_BINDGEN_VERSION}" --root /tmp/wasm-bindgen
    WASM_BINDGEN=/tmp/wasm-bindgen/bin/wasm-bindgen
    echo "wasm-bindgen CLI: $("$WASM_BINDGEN" --version) sha256 $(sha256sum "$WASM_BINDGEN" | cut -c1-64)"

    rustup target add wasm32-unknown-unknown >/dev/null 2>&1

    # Belt-and-braces path hygiene (uniform inside the container, so the flag
    # strings — which feed cargo symbol metadata — are identical everywhere).
    export RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo-home --remap-path-prefix=/build=/src"
    # Keep the host repo target/ free of container artifacts.
    export CARGO_TARGET_DIR=/tmp/wasm-target

    # One artifact per feature, built alone, so each carries only its own code. The two
    # commands are what wasm-pack 0.14.0 ran for `build --release --no-pack`.
    for pkg in $PKGS; do
      dir="${pkg%%:*}"; rest="${pkg#*:}"; name="${rest%%:*}"; feature="${rest#*:}"
      (cd /build/crypto-wasm && CARGO_BUILD_TARGET=wasm32-unknown-unknown \
        cargo build --quiet --lib --release --no-default-features --features "$feature")
      "$WASM_BINDGEN" "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/signet_crypto_wasm.wasm" \
        --out-dir "/build/web/src/lib/crypto/$dir" --typescript --target web --out-name "$name" \
        --remove-name-section
    done
  '

# (wasm-pack dropped a `*`-matching .gitignore into each out-dir; the CLI does not, and
# the removal stays so a stale one from an older build cannot hide a committed file.)
for pkg in $PKGS; do rm -f "$REPO_ROOT/web/src/lib/crypto/${pkg%%:*}/.gitignore"; done

# ── The readout (bug204, S179) ──────────────────────────────────────────────────
#
# ⚠⚠ TWO DEFECTS FIXED HERE, and together they made a CORRECT regen look like a
# NO-OP. They did exactly that at the v0.5.40 and v0.5.41 bumps, and the workaround
# was to ignore this script's output and read `git diff` instead.
#
#   1. The block was labelled "committed-pkg hashes:" but hashed $OUT_DIR — which
#      wasm-pack had *just overwritten*. Nothing committed was ever read, so the
#      "before" and "after" were the same bytes and the readout could not, even in
#      principle, show that anything had changed.
#
#   2. `(cd D && shasum … || cd D && sha256sum …)` parses as
#      `((cd && shasum) || cd) && sha256sum` — so when `shasum` SUCCEEDED the whole
#      block still ran `sha256sum`, printing the hashes TWICE. Two identical blocks
#      under a "committed" label read exactly like "before == after, nothing
#      changed".
#
# ⭐ The fix is to print what `git` knows (BEFORE) beside what is now on disk
# (AFTER), because git is the authority the `wasm-pkg-repro` CI gate uses too
# (`git diff --exit-code`). A local readout that disagrees with the gate is worse
# than none.
sha_of_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}
sha_of_stdin() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

echo
echo "pkg hashes — COMMITTED (git) vs BUILT (on disk):"
changed=0
for pkg in $PKGS; do
  OUT_DIR_REL="web/src/lib/crypto/${pkg%%:*}"; rest="${pkg#*:}"; name="${rest%%:*}"
  OUT_DIR="$REPO_ROOT/$OUT_DIR_REL"
  echo "  $OUT_DIR_REL/"
  for f in "${name}_bg.wasm" "${name}.js" "${name}.d.ts" "${name}_bg.wasm.d.ts"; do
    built="$(sha_of_file "$OUT_DIR/$f")"
    if committed="$(git -C "$REPO_ROOT" cat-file blob "HEAD:$OUT_DIR_REL/$f" 2>/dev/null | sha_of_stdin)" \
       && [ -n "$committed" ]; then
      if [ "$committed" = "$built" ]; then
        printf '    %-30s unchanged  %s\n' "$f" "$built"
      else
        printf '    %-30s CHANGED    %s -> %s\n' "$f" "$committed" "$built"
        changed=1
      fi
    else
      # No git, or the file is not committed yet (a first generation).
      printf '    %-30s (not in git) %s\n' "$f" "$built"
      changed=1
    fi
  done
done

echo
if [ "$changed" -eq 1 ]; then
  echo "=> the pkg CHANGED. Commit it IN THE SAME PR as the version bump (deploy-runbook §3)."
else
  # Expected for a rebuild with no source change, and since #671 for a version
  # bump too: the crate version reached the .wasm only through rustc's symbol
  # hashes in the debug `name` section, which --remove-name-section now drops
  # (measured at v1.1.1's bump: the rebuild at 1.1.1 reproduced 1.1.0's pkg byte
  # for byte; v1.1.0's bump, with names, had moved it). Stated rather than silent.
  echo "=> the pkg is UNCHANGED. Expected for a rebuild with no source change, and"
  echo "   since #671 (names stripped) for a version bump alone."
fi
echo
echo "   (git is the authority; CI's wasm-pkg-repro gate uses \`git diff --exit-code\`.)"
