#!/usr/bin/env bash
# verify-release.sh: rebuild Signet Drive release artifacts from source and
# byte-compare against the published release manifest.
#
# Specification: signet-verify-release-spec v01 (Gus, 2026-07-21).
# Verdicts (exit codes, never conflated with tool errors):
#   0  REPRODUCED-FULL      byte-identical on every requested target
#   10 REPRODUCED-CONTENT   macOS only: difference is exactly LC_UUID-derived
#                           (requires the manifest's uuid-stripped anchor)
#   20 NOT-REPRODUCED       content differs; diagnostics emitted
#   64 PREREQ/ANCHOR FAILURE  the verification did not run
#
# Usage:
#   verify-release.sh --tag <tag> [--target macos|linux|wasm|all]
#                     [--repo <path-or-url>] [--manifest-file <path>]
#                     [--anchor-source <path-or-url>] [--out <dir>] [--keep]
#
# Defaults are the public repository and the public-hashes anchor history.
# --manifest-file and --anchor-source exist for fixture testing and pre-launch
# operation; their use is printed loudly in the transcript (a verification with
# overrides says so on its face).
set -u

VERSION="0.1.0"
SELF_SHA=$(shasum -a 256 "$0" | awk '{print $1}')
say() { echo "$*" >&2; }
tool_err() { say "verify-release: $*"; exit 64; }

TAG="" TARGET="all" OUT="" KEEP=false MANIFEST_FILE="" ANCHOR_SRC=""
REPO_DEFAULT="https://github.com/prsnex/signet-drive"
REPO="${VR_REPO:-$REPO_DEFAULT}"
ANCHOR_DEFAULT="https://github.com/prsnex/signet-drive-public-hashes"
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --repo) REPO="${2:-}"; shift 2 ;;
    --manifest-file) MANIFEST_FILE="${2:-}"; shift 2 ;;
    --anchor-source) ANCHOR_SRC="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --keep) KEEP=true; shift ;;
    *) tool_err "unknown argument: $1" ;;
  esac
done
[ -n "$TAG" ] || tool_err "--tag is required"
case "$TARGET" in macos|linux|wasm|all) : ;; *) tool_err "--target must be macos, linux, wasm, or all" ;; esac

say "verify-release $VERSION"
say "sha256 $SELF_SHA"
[ -n "$MANIFEST_FILE" ] && say "OVERRIDE: manifest from local file, not the published location"
[ -n "$ANCHOR_SRC" ] && say "OVERRIDE: anchor source is not the default public-hashes history"

WORK="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/verify-release.XXXXXX")}"
mkdir -p "$WORK" || tool_err "cannot create workdir $WORK"
$KEEP || trap 'rm -rf "$WORK"' EXIT
say "workdir $WORK"

# ---- 1. obtain the manifest ------------------------------------------------
MANIFEST="$WORK/manifest.json"
if [ -n "$MANIFEST_FILE" ]; then
  cp "$MANIFEST_FILE" "$MANIFEST" || tool_err "cannot read $MANIFEST_FILE"
else
  # Published location: alongside release artifacts. Network step 1 of 2.
  VER="${TAG#v}"
  URL="https://drive.mysignet.ca/cli/signet-${VER}-macos.manifest.json"
  say "fetching manifest: $URL"
  curl -fsS -o "$MANIFEST" "$URL" || tool_err "manifest fetch failed: $URL"
fi
mjq() { python3 -c "import json,sys;d=json.load(open('$MANIFEST'));print(d$1)" 2>/dev/null; }
MVER=$(mjq ".get('manifest_version',1)")
[ "$MVER" = "1" ] || tool_err "unknown manifest_version '$MVER' (this tool knows version 1)"
mjq "['manifest_version']" >/dev/null 2>&1 || say "note: manifest has no manifest_version field; treating as version 1 (pre-versioning manifest)"
MSHA=$(shasum -a 256 "$MANIFEST" | awk '{print $1}')
SRC_TAG=$(mjq "['source_tag']"); COMMIT=$(mjq "['build_commit_sha']")
[ "$SRC_TAG" = "$TAG" ] || tool_err "manifest source_tag '$SRC_TAG' does not match requested tag '$TAG'"
say "manifest sha256 $MSHA (source_tag $SRC_TAG, commit $COMMIT)"

# ---- 2. anchor the manifest BEFORE building --------------------------------
ANCHOR="${ANCHOR_SRC:-$ANCHOR_DEFAULT}"
ADIR="$WORK/anchor"
case "$ANCHOR" in
  http*) git clone --quiet --depth 50 "$ANCHOR" "$ADIR" 2>/dev/null || tool_err "anchor clone failed: $ANCHOR" ;;
  *) [ -d "$ANCHOR" ] || tool_err "anchor source not found: $ANCHOR"; cp -R "$ANCHOR" "$ADIR" ;;
esac
if grep -rq "$MSHA" "$ADIR" --include="*" 2>/dev/null; then
  say "anchor OK: manifest hash present in the anchor history"
else
  tool_err "ANCHOR FAILURE: manifest hash $MSHA not found in $ANCHOR (the claim under test is unanchored; nothing to verify)"
fi

# ---- 3. checkout the source ------------------------------------------------
# The public repository is a per-release curated export with its own history, so
# the manifest's build_commit_sha (a private-tree commit) does not exist there.
# The release TAG is the anchor the export mirrors: checkout by tag first, and
# fall back to the commit sha for a private or fixture --repo where it resolves.
SRC="$WORK/src"
case "$REPO" in
  http*) say "cloning $REPO"; git clone --quiet "$REPO" "$SRC" || tool_err "clone failed" ;;
  *) git clone --quiet --shared "$REPO" "$SRC" || tool_err "local clone failed" ;;
esac
if git -C "$SRC" rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
  git -C "$SRC" checkout --quiet "refs/tags/$TAG" || tool_err "checkout of tag $TAG failed"
  say "source at tag $TAG ($(git -C "$SRC" rev-parse --short HEAD))"
elif git -C "$SRC" rev-parse --verify --quiet "$COMMIT^{commit}" >/dev/null; then
  git -C "$SRC" checkout --quiet "$COMMIT" || tool_err "checkout of $COMMIT failed"
  say "source at commit $COMMIT (tag $TAG not present in this repo; private or fixture checkout)"
else
  tool_err "neither tag $TAG nor commit $COMMIT resolves in $REPO (the public export carries the tag; a private checkout carries the commit)"
fi

FULL=true; CONTENT_ONLY=false; DIAG=""

# ---- 4a. macOS signet (the full ladder) ------------------------------------
verify_macos() {
  local want; want=$(mjq "['unsigned_binary_sha256']['macos_signet']")
  [ -n "$want" ] || tool_err "manifest lacks unsigned_binary_sha256.macos_signet"
  command -v rustup >/dev/null || tool_err "rustup required for the macOS target (R3 neutral-toolchain pin)"
  local pins_target pins_tc
  pins_target=$(mjq "['reproducibility_pins']['cargo_target_dir']")
  pins_tc=$(mjq "['reproducibility_pins']['toolchain_path']")
  local mrustc; mrustc=$(mjq "['toolchain']['rustc']")
  local have_rustc; have_rustc=$(rustc --version)
  if [ "$mrustc" != "$have_rustc" ]; then
    tool_err "toolchain gate: manifest built with '$mrustc', this machine has '$have_rustc'. Install the recorded toolchain (rustup) and rerun."
  fi
  # Replicate the release pins exactly (both link-input path sets, resolved form).
  if [ ! -x "$pins_tc/bin/rustc" ] || [ "$("$pins_tc/bin/rustc" --version)" != "$have_rustc" ]; then
    say "caching toolchain at the neutral pin path"
    rm -rf "$pins_tc"; mkdir -p "$(dirname "$pins_tc")"
    cp -R "$(rustc --print sysroot)" "$pins_tc"
  fi
  rustup toolchain link signet-release-neutral "$pins_tc" >/dev/null 2>&1 || true
  rm -rf "$pins_target"
  local ch="${CARGO_HOME:-$HOME/.cargo}"
  local rf="--remap-path-prefix=$SRC=/signet-src --remap-path-prefix=$ch=/cargo-home --remap-path-prefix=$pins_tc=/rustc-sysroot"
  say "building macOS signet (release, locked, pinned paths). This takes minutes."
  ( cd "$SRC" && RUSTFLAGS="$rf" CARGO_TARGET_DIR="$pins_target" \
      cargo +signet-release-neutral build --release --locked --bin signet ) >>"$WORK/build-macos.log" 2>&1 \
    || tool_err "macOS build failed (log: $WORK/build-macos.log)"
  local got; got=$(shasum -a 256 "$pins_target/release/signet" | awk '{print $1}')
  if [ "$got" = "$want" ]; then say "macos_signet: REPRODUCED-FULL"; return 0; fi
  FULL=false
  # Decompose before concluding. The content rung needs a published
  # uuid-stripped anchor; without it an outside verifier cannot claim
  # REPRODUCED-CONTENT (S112 had both binaries; a watcher has one hash).
  local want_stripped; want_stripped=$(mjq "['unsigned_binary_sha256'].get('macos_signet_uuid_stripped','')")
  local stripped="$WORK/signet.uuid-zeroed"
  python3 - "$pins_target/release/signet" "$stripped" <<'PY'
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
off = 0x20  # first load command (arm64 mach_header_64)
import struct
ncmds = struct.unpack_from('<I', data, 0x10)[0]
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', data, off)
    if cmd == 0x1b:  # LC_UUID
        data[off+8:off+24] = b'\x00'*16
    off += size
open(sys.argv[2], 'wb').write(bytes(data))
PY
  local got_stripped; got_stripped=$(shasum -a 256 "$stripped" | awk '{print $1}')
  say "macos_signet: full-hash MISMATCH (built $got, manifest $want)"
  say "macos_signet: uuid-zeroed hash of the rebuilt binary: $got_stripped"
  if [ -n "$want_stripped" ]; then
    if [ "$got_stripped" = "$want_stripped" ]; then
      CONTENT_ONLY=true
      say "macos_signet: REPRODUCED-CONTENT (difference is exactly LC_UUID-derived)"
      say "toolchain expected: $mrustc"
      say "toolchain found:    $have_rustc"
      return 0
    fi
  else
    say "macos_signet: manifest lacks macos_signet_uuid_stripped; the CONTENT rung cannot be claimed by an outside verifier (known manifest-schema gap, flagged)"
  fi
  DIAG="$WORK/section-map.txt"
  { size -l -m "$pins_target/release/signet" 2>/dev/null || otool -l "$pins_target/release/signet" | head -80; } > "$DIAG" 2>&1
  say "macos_signet: NOT-REPRODUCED (section map: $DIAG)"
  return 1
}

# ---- 4b. Linux signet (the ten-minute rung) --------------------------------
verify_linux() {
  local want; want=$(mjq "['unsigned_binary_sha256']['linux_helper']")
  [ -n "$want" ] || tool_err "manifest lacks unsigned_binary_sha256.linux_helper"
  command -v docker >/dev/null || tool_err "docker required for the linux target"
  docker info >/dev/null 2>&1 || tool_err "docker is not running"
  local img; img=$(mjq "['toolchain']['linux_builder_image']")
  say "building Linux signet in $img"
  local vol="verify-release-linux-$$"
  docker volume create "$vol" >/dev/null
  docker run --rm --platform linux/arm64 -v "$SRC":/src:ro -v "$vol":/target -w /src \
    -e CARGO_TARGET_DIR=/target "$img" \
    sh -c "apk add --no-cache musl-dev gcc make perl >/dev/null 2>&1 && cargo build --release --locked --bin signet" \
    >>"$WORK/build-linux.log" 2>&1 || { docker volume rm "$vol" >/dev/null; tool_err "linux build failed (log: $WORK/build-linux.log)"; }
  docker run --rm --platform linux/arm64 -v "$vol":/target -v "$WORK":/out alpine \
    sh -c "cp /target/release/signet /out/signet-linux" >/dev/null 2>&1
  docker volume rm "$vol" >/dev/null
  local got; got=$(shasum -a 256 "$WORK/signet-linux" | awk '{print $1}')
  if [ "$got" = "$want" ]; then say "linux_helper: REPRODUCED-FULL"; return 0; fi
  FULL=false
  say "linux_helper: NOT-REPRODUCED (built $got, manifest $want). No UUID rung exists on this target."
  cmp -l "$WORK/signet-linux" /dev/null >/dev/null 2>&1 || true
  return 1
}

# ---- 4c. WASM pkg (committed-pkg compare) ----------------------------------
verify_wasm() {
  command -v docker >/dev/null || tool_err "docker required for the wasm target"
  [ -x "$SRC/crypto-wasm/build-web-pkg.sh" ] || tool_err "crypto-wasm/build-web-pkg.sh not found at this tag"
  say "building wasm pkg via the committed container recipe"
  ( cd "$SRC" && ./crypto-wasm/build-web-pkg.sh ) >>"$WORK/build-wasm.log" 2>&1 \
    || tool_err "wasm build failed (log: $WORK/build-wasm.log)"
  if git -C "$SRC" diff --quiet -- web/src/lib/crypto/mlkem-wasm; then
    say "wasm_pkg: REPRODUCED-FULL (rebuild matches the committed pkg byte-for-byte)"
    return 0
  fi
  FULL=false
  git -C "$SRC" diff --stat -- web/src/lib/crypto/mlkem-wasm | tail -3 >&2
  say "wasm_pkg: NOT-REPRODUCED (rebuild differs from the committed pkg)"
  return 1
}

RC=0
case "$TARGET" in
  macos) verify_macos || RC=1 ;;
  linux) verify_linux || RC=1 ;;
  wasm)  verify_wasm  || RC=1 ;;
  all)   verify_linux || RC=1; verify_macos || RC=1; verify_wasm || RC=1 ;;
esac

# ---- verdict ---------------------------------------------------------------
if [ $RC -eq 0 ] && $FULL; then V="REPRODUCED-FULL"; CODE=0
elif [ $RC -eq 0 ] && $CONTENT_ONLY; then V="REPRODUCED-CONTENT"; CODE=10
else V="NOT-REPRODUCED"; CODE=20; fi
echo "verdict=$V tag=$TAG manifest_sha=$MSHA script_sha=$SELF_SHA target=$TARGET"
exit $CODE
