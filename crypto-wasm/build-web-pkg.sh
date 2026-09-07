#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PRSN EX Inc.
#
# Build the committed wasm pkg the web client imports (PQR item 4/6).
#
# The wasm-pack output (`web/src/lib/crypto/mlkem-wasm/`) is COMMITTED, not
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
# Requires Docker (already a dev-stack requirement). Regeneration is rare —
# only when crypto-wasm/ or the toolchain pin changes.
#
# Usage: crypto-wasm/build-web-pkg.sh          (from anywhere; paths are repo-relative)

set -euo pipefail

WASM_PACK_VERSION="0.14.0"
WASM_PACK_SHA256="278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d"
# rust:1.96.0-bookworm, digest-pinned (multi-arch manifest; --platform selects
# amd64). Bump together with rust-toolchain.toml — the image toolchain must
# match the pin or rustup downloads inside the container.
RUST_IMAGE="rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR_REL="web/src/lib/crypto/mlkem-wasm"

docker run --rm --platform linux/amd64 \
  -v "$REPO_ROOT":/build -w /build \
  -e WASM_PACK_VERSION="$WASM_PACK_VERSION" \
  -e WASM_PACK_SHA256="$WASM_PACK_SHA256" \
  "$RUST_IMAGE" \
  bash -euo pipefail -c '
    # Pinned wasm-pack from the checksummed release tarball (musl = static,
    # runs anywhere).
    curl -sSfL -o /tmp/wasm-pack.tar.gz \
      "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    echo "${WASM_PACK_SHA256}  /tmp/wasm-pack.tar.gz" | sha256sum -c - >/dev/null
    tar -xzf /tmp/wasm-pack.tar.gz -C /tmp
    install -m 0755 "/tmp/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack" /usr/local/bin/wasm-pack

    rustup target add wasm32-unknown-unknown >/dev/null 2>&1

    # Belt-and-braces path hygiene (uniform inside the container, so the flag
    # strings — which feed cargo symbol metadata — are identical everywhere).
    export RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo-home --remap-path-prefix=/build=/src"
    # Keep the host repo target/ free of container artifacts.
    export CARGO_TARGET_DIR=/tmp/wasm-target

    wasm-pack build /build/crypto-wasm --target web --release --no-pack \
      --out-dir "/build/web/src/lib/crypto/mlkem-wasm"
  '

OUT_DIR="$REPO_ROOT/$OUT_DIR_REL"
# wasm-pack drops a `*`-matching .gitignore into the out-dir; the whole point
# here is that the pkg IS committed, so remove it.
rm -f "$OUT_DIR/.gitignore"

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
for f in signet_crypto_wasm_bg.wasm signet_crypto_wasm.js signet_crypto_wasm.d.ts \
         signet_crypto_wasm_bg.wasm.d.ts; do
  built="$(sha_of_file "$OUT_DIR/$f")"
  if committed="$(git -C "$REPO_ROOT" cat-file blob "HEAD:$OUT_DIR_REL/$f" 2>/dev/null | sha_of_stdin)" \
     && [ -n "$committed" ]; then
    if [ "$committed" = "$built" ]; then
      printf '  %-32s unchanged  %s\n' "$f" "$built"
    else
      printf '  %-32s CHANGED    %s -> %s\n' "$f" "$committed" "$built"
      changed=1
    fi
  else
    # No git, or the file is not committed yet (a first generation).
    printf '  %-32s (not in git) %s\n' "$f" "$built"
    changed=1
  fi
done

echo
if [ "$changed" -eq 1 ]; then
  echo "=> the pkg CHANGED. Commit it IN THE SAME PR as the version bump (deploy-runbook §3)."
else
  # ⚠ Not necessarily an error: a rebuild with no source or version change SHOULD
  # be identical — that is what byte-reproducibility means. But after a VERSION
  # BUMP it is a red flag: the crate version feeds rustc symbol metadata, so every
  # bump must move the .wasm. Stated rather than silently green.
  echo "=> the pkg is UNCHANGED. Expected for a rebuild with no source/version change;"
  echo "   ⚠ after a VERSION BUMP this is wrong — every bump must move the .wasm."
fi
echo
echo "   (git is the authority; CI's wasm-pkg-repro gate uses \`git diff --exit-code\`.)"
