#!/usr/bin/env bash
# build-signet-release.sh — build the shippable, notarized Signet app (ONE artifact).
#
# Produces a single Developer-ID-signed + notarized + stapled `signet.app`:
#   Contents/MacOS/signet                  release macOS `signet` (host CLI + `host-signer` mode)
#   Contents/Resources/signet-linux-arm64  the STATIC Linux `signet` the host app delivers to
#                                          containerized PRSNs (host-delegation — bundled, never
#                                          a separate download)
# ...plus a distributable .zip + its sha256 + a BUILD MANIFEST (`*.manifest.json`) recording
# the source tag, build_commit_sha, unsigned-binary hashes, and toolchain versions (for the
# public hash commit / reproducible-build verification — see Signet-Drive-Open-Source-Plan).
#
# PUBLISH-FROM-TAG GATE (Bug027 / PQR Build-Plan item 0): a notarized (distributable)
# build REFUSES to run unless HEAD is exactly a pushed tag and the tree is clean —
# so a drifted release (built past its advertised tag, the 0.4.0 incident) is
# structurally impossible, not a discipline hope. `--skip-notarize` (local iteration,
# never distributable) bypasses the gate with a loud warning.
#
# EMERGENCY RELEASE PROCEDURE — there is deliberately NO bypass flag; the tag IS
# the escape hatch (Chris + Hlin, S105): bump the patch version, tag the exact
# commit you are shipping, `git push --tags`, re-run this script. Under a minute,
# against a notarize cycle that takes several. Never force-move a published tag:
# the tag↔version check means an emergency re-cut always takes a NEW version —
# one version, one binary, by construction. Accepted cost: a GitHub outage blocks
# notarized releases until it recovers (rebuild verification is GitHub-dependent
# anyway, and nothing in Drive's operation needs same-hour client releases).
#
# This is the PRODUCTION promotion of the S054/S057 dev entitled-.app recipe (that
# recipe's living successor is sign-example-for-se.sh — the lean local entitle path):
# a release build + a secure --timestamp + the bundled Linux binary + notarize +
# staple. The dev recipe grants LOCAL Secure-Enclave access; this one makes the app
# DISTRIBUTABLE to other Macs (notarization governs distribution, not local
# entitlement — S057).
#
# Prereqs (verified present S058 — see memory/reference_apple_developer_account):
#   - Developer ID Application cert "...(F2FY22A25D)" with a local private key
#   - the provisioning profile (App ID ai.prsnex.signet; keychain-access-groups)
#   - the `signet-notary` notarytool keychain profile (App Store Connect Team Key)
#   - Docker (for the static-musl Linux build)
#
# Usage: build-signet-release.sh [--skip-notarize] [--out DIR] [--self-test]
#   --skip-notarize : build + codesign only (fast local iteration; NOT distributable)
#   --out DIR       : output directory (default: target/release-app)
#   --self-test     : drive the §1b dirty-path carve against fixtures and exit (no
#                     keychain, no docker, no network — safe in CI, run by scripts-ci)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO/target/release-app"
SKIP_NOTARIZE=0
SELF_TEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-notarize) SKIP_NOTARIZE=1; shift ;;
    --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1 (try --help)" >&2; exit 2 ;;
  esac
done

APP="$OUT/signet.app"
PROFILE="${SIGNET_PROVISION_PROFILE:-$HOME/Downloads/Signet_CLI_Developer_ID.provisionprofile}"
SIGN_ID="${SIGNET_SIGN_ID:-Developer ID Application: ID Lynx Ltd. (F2FY22A25D)}"
NOTARY_PROFILE="${SIGNET_NOTARY_PROFILE:-signet-notary}"
TEAM_ID="F2FY22A25D"
BUNDLE_ID="ai.prsnex.signet"
LINUX_VOLUME="signet-linux-target"
LINUX_BIN_NAME="signet-linux-arm64"
# The Linux-helper builder image, PINNED BY DIGEST (R5 / the Bug026 copy-exact
# lesson): a floating `rust:alpine` re-resolves per machine/day and silently
# changes the toolchain under the byte-identical-rebuild claim. This digest is
# the image that produced the S002 byte-for-byte Linux match (Gus, 260704).
# Bump deliberately: update the digest + note the rustc/alpine versions in the
# commit message; the manifest records it per-release either way.
LINUX_BUILDER_IMAGE="rust@sha256:66f48b19d6e88519e2e58bebe0d945779a6a4ca41c2db17db78c9569655b50ac"

log()  { echo "→ $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ── the §1b dirty-path carve (pure; --self-test drives it) ────────────────────
# Two carve-outs. Each survives only because the carved path CANNOT move the
# shipped bytes — that is the whole reproducibility argument, so each one is
# stated rather than assumed:
# ⭐ THE CARVE NOW LIVES IN ONE HOME (S201): deploy-gate-carve-lib.sh, sourced by
# BOTH this builder and deploy.sh's provenance gate. It used to live only here,
# which is why the deploy gate did not know about it and refused the v0.5.57
# release over two ledgers that cannot reach the box. The rule, its two halves and
# the reasoning for each moved there VERBATIM -- read them at the lib, not here.
# ⚠ This script's --self-test remains the regression test for that file.
_CARVE_LIB="$(dirname "${BASH_SOURCE[0]}")/deploy-gate-carve-lib.sh"
if [ ! -r "$_CARVE_LIB" ]; then
    echo "FATAL: cannot read $_CARVE_LIB -- the dirty-tree carve has no definition." >&2
    echo "       Refusing rather than proceeding: an ABSENT carve blocks on every ops" >&2
    echo "       ledger, and an EMPTY one passes everything. Neither should be quiet." >&2
    exit 1
fi
# shellcheck source=infrastructure/scripts/deploy-gate-carve-lib.sh
. "$_CARVE_LIB"

# The carve's premise, as a check that can actually fail (Gus, S166). Verified
# born green — 0 hits — before the carve shipped; a permanently-red gate would be
# worse than no gate. It fires the day someone adds an include_str!/include_bytes!
# pointing at docs/operations, which is exactly when the carve stops being sound.
# ('*.rs' covers build.rs — build.rs IS a .rs file.)
ops_build_input_refs() { git -C "$REPO" grep -lE 'docs/operations' -- '*.rs' 2>/dev/null || true; }

self_test() {
  local fails=0
  _carve_case() { # <label> <porcelain fixture> <expected BLOCKING output>
    local label="$1" fixture="$2" want="$3" got
    got="$(printf '%s' "$fixture" | dirty_blocking)"
    if [ "$got" = "$want" ]; then echo "PASS  $label"
    else echo "FAIL  $label — blocking='$got' expected='$want'"; fails=$((fails+1)); fi
  }

  # CARVED — the ledgers the carve exists for, unstaged and staged.
  _carve_case "ops .tsv (unstaged) is carved" \
    ' M docs/operations/staging/release-timings.tsv
' ''
  _carve_case "ops .tsv (staged) is carved" \
    'M  docs/operations/staging/gate-outcomes.tsv
' ''
  # CARVED — the S118 regression: an untracked space-named doc, git-quoted.
  _carve_case "untracked space-named doc is carved (S118)" \
    '?? "docs/design/Signet Foo - v01 - 260808.md"
' ''
  _carve_case "quoted ops .tsv is carved" \
    ' M "docs/operations/staging/release timings.tsv"
' ''

  # ⭐ BLOCKS — the property that makes the extension a class marker. A pin file
  # under the SAME directory must still block, or the carve is a directory carve.
  _carve_case "ops .json still BLOCKS (extension is the class marker)" \
    ' M docs/operations/pins.json
' ' M docs/operations/pins.json'
  _carve_case "tracked-modified ops .md still BLOCKS (carve did not widen)" \
    ' M docs/operations/runbooks/deploy-runbook.md
' ' M docs/operations/runbooks/deploy-runbook.md'
  _carve_case "tracked Rust change BLOCKS" \
    ' M server/src/lifecycle.rs
' ' M server/src/lifecycle.rs'
  _carve_case "untracked file OUTSIDE docs/ BLOCKS (a stray build.rs)" \
    '?? build.rs
' '?? build.rs'
  _carve_case "rename OUT of the ledger class BLOCKS" \
    'R  docs/operations/a.tsv -> cli/src/x.rs
' 'R  docs/operations/a.tsv -> cli/src/x.rs'

  # Mixed: the carve must not swallow a real blocker sharing the batch.
  _carve_case "a real blocker survives alongside carved paths" \
    ' M docs/operations/staging/release-timings.tsv
 M cli/src/main.rs
?? "docs/design/Foo - v01.md"
' ' M cli/src/main.rs'

  # The gate's most important happy path: a clean tree must block NOTHING.
  # (I first justified this case with a phantom-empty-line hazard. MEASURED at
  # S167: command substitution strips trailing newlines, so no such line can ever
  # reach `[ -z ]` — the hazard was not real. The case stays because the happy
  # path is worth pinning; the false mechanism does not.)
  _carve_case "clean tree blocks nothing" '' ''

  # The carved set is what gets LOGGED by name, so it must be non-empty when there
  # is something to name — the negative control for the log line below.
  local carved
  carved="$(printf '%s' ' M docs/operations/staging/release-timings.tsv
 M cli/src/main.rs
' | dirty_carved)"
  if [ "$carved" = ' M docs/operations/staging/release-timings.tsv' ]; then
    echo "PASS  carved set names exactly the carved path (feeds the gate-OK log)"
  else
    echo "FAIL  carved set was '$carved'"; fails=$((fails+1))
  fi

  # The carve's premise, asserted against THIS tree (born green at S166).
  local refs; refs="$(ops_build_input_refs)"
  if [ -z "$refs" ]; then
    echo "PASS  no Rust source references docs/operations (the carve's premise holds)"
  else
    echo "FAIL  Rust source references docs/operations — the carve is UNSOUND: $refs"; fails=$((fails+1))
  fi

  if [ "$fails" -eq 0 ]; then echo "self-test: ALL PASS"; return 0; else echo "self-test: $fails FAIL"; return 1; fi
}

if [ "$SELF_TEST" -eq 1 ]; then self_test; exit $?; fi

# ── 1. prerequisites ──────────────────────────────────────────────────────────
log "checking prerequisites…"
security find-identity -v -p codesigning 2>/dev/null | grep -q "$TEAM_ID" \
  || die "Developer ID Application cert ($TEAM_ID) not found in the login keychain"
[ -f "$PROFILE" ] || die "provisioning profile not found: $PROFILE (set SIGNET_PROVISION_PROFILE)"
command -v docker >/dev/null || die "docker not found (needed for the static-musl Linux build)"
docker info >/dev/null 2>&1 || die "docker is not running"
if [ "$SKIP_NOTARIZE" -eq 0 ]; then
  # C5 (S140): a SINGLE negative probe of the notary keychain profile is UNKNOWN, not
  # FAIL. At S140 this exact probe returned "No Keychain password item found" while the
  # credential was present and usable — the profile lives in the session-gated
  # data-protection keychain, which can be momentarily unreadable (and which the legacy
  # `security` CLI cannot see AT ALL, so never probe with it). Re-probe, spaced, before
  # giving up. The retries cost NOTHING on the happy path — the loop breaks on first
  # success. On genuine failure the message PRESERVES THE AMBIGUITY (absent OR unreadable)
  # and never asserts absence: a "recreate the profile" reflex on a false-negative
  # destroys the evidence and "confirms" a vanishing that never happened.
  notary_ok=0
  for attempt in 1 2 3; do
    if xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
      notary_ok=1; break
    fi
    [ "$attempt" -lt 3 ] && { log "notary profile not visible (probe $attempt/3) — re-probing in 3s…"; sleep 3; }
  done
  [ "$notary_ok" -eq 1 ] || die "notarytool profile '$NOTARY_PROFILE' NOT VISIBLE after 3 spaced probes — this could mean the credential is ABSENT *or* the keychain is currently UNREADABLE. Do NOT assume absence and do NOT auto-run 'store-credentials' (a recreate on a false-negative destroys the evidence). See deploy-runbook §2.1-5 + friction log C5. If you have independently confirmed the profile exists, re-run."
fi

# ── 1b. publish-from-tag gate (Bug027 / R1) ───────────────────────────────────
# A distributable release must be built from EXACTLY a pushed tag, on a clean
# tree, so the advertised source ref always reproduces the shipped bytes. No
# escape hatch on the notarize path — an escape hatch is how drift recurs.
SOURCE_TAG="$(git -C "$REPO" describe --tags --exact-match HEAD 2>/dev/null || true)"
BUILD_SHA="$(git -C "$REPO" rev-parse HEAD)"
# Anything not carved out above (tracked modifications anywhere, untracked
# outside docs/ — e.g. a stray build.rs cargo would pick up) blocks the release.
# The two carve-outs and WHY each is safe are documented at GATE_CARVE_RE.
DIRTY_BLOCKING="$(git -C "$REPO" status --porcelain | dirty_blocking)"
DIRTY_CARVED="$(git -C "$REPO" status --porcelain | dirty_carved)"
if [ "$SKIP_NOTARIZE" -eq 0 ]; then
  [ -n "$SOURCE_TAG" ] \
    || die "publish-from-tag gate: HEAD ($BUILD_SHA) is not exactly a tag — tag the release commit first (Bug027)"
  OPS_BUILD_INPUT_REFS="$(ops_build_input_refs)"
  [ -z "$OPS_BUILD_INPUT_REFS" ] \
    || die "publish-from-tag gate: the docs/operations carve-out is UNSOUND on this tree — Rust source references docs/operations, so an ops file CAN be a build input (Gus, S166):
$OPS_BUILD_INPUT_REFS
Either remove the reference, or narrow GATE_CARVE_RE so the referenced path blocks again."
  [ -z "$DIRTY_BLOCKING" ] \
    || die "publish-from-tag gate: working tree not clean (Bug027):
$DIRTY_BLOCKING"
  git -C "$REPO" ls-remote --tags origin "refs/tags/$SOURCE_TAG" | grep -q . \
    || die "publish-from-tag gate: tag '$SOURCE_TAG' is not pushed to origin (Bug027)"
  # ⭐ Name the carved-out paths in the release log (Gus, S166): "an ignored file
  # that is named in every release log can be noticed; one that vanishes into a
  # regex cannot." A control's exclusions must report themselves.
  if [ -n "$DIRTY_CARVED" ]; then
    log "publish-from-tag gate: dirty paths CARVED OUT as non-build-inputs —"
    printf '%s\n' "$DIRTY_CARVED" | while IFS= read -r carved_line; do log "      $carved_line"; done
  else
    log "publish-from-tag gate: no carved-out dirty paths (tree clean outright)"
  fi
  log "publish-from-tag gate OK: $SOURCE_TAG @ $BUILD_SHA (clean tree, tag on origin)"
else
  echo "⚠  --skip-notarize: publish-from-tag gate BYPASSED (local iteration only —" >&2
  echo "   this artifact is not distributable; a notarized release enforces the gate)" >&2
  [ -n "$SOURCE_TAG" ] || SOURCE_TAG="(untagged)"
fi

rm -rf "$OUT"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# ── 2. release macOS signet ───────────────────────────────────────────────────
# The Swift/CryptoKit SE-PQC shim (PQR item 1) compiles INSIDE cargo build
# (cli/build.rs, macOS targets only) — this step inherits it with no extra
# recipe, so no pipeline can ship a binary that forgot the shim.
#
# F-REPRO-R2(a) + R3 (S112): cross-path AND cross-machine reproducibility for
# the macOS FULL-binary hash. Two layers, both required:
#
#   * `--remap-path-prefix` pins every path EMBEDDED in compiled objects
#     (checkout, cargo home, sysroot) to fixed labels — this made all content
#     byte-identical cross-path (R2a).
#   * BUT the linker (ld-1267 "ld-prime") derives the LC_UUID from link-input
#     *paths*, not output content — contradicting its man page; found
#     empirically at the D2 increment review (Gus, S112; `-Wl,-reproducible`
#     silently no-ops). So the two path sets a verifier's machine would vary
#     must be PINNED to fixed, machine-neutral locations: the cargo TARGET
#     DIR (where our .o/.rlib link inputs live) and the TOOLCHAIN/sysroot
#     (where the stdlib rlib link inputs live). `/private/tmp` is used in its
#     resolved form deliberately — `/tmp` is a symlink and a resolved-vs-not
#     difference is itself a path-shape difference.
#
# The toolchain copy at the neutral path is cached across builds and refreshed
# when the active rustc version changes; the target dir is wiped every build
# (release builds are rare — determinism beats incremental speed here). The
# manifest records both pins; the Open-Source-Plan verification flow tells a
# watcher to reproduce with the same two pins.
# (`cargo trim-paths` is still nightly at Rust 1.96 — the RUSTFLAGS form is
# the stable equivalent; swap when it stabilizes.)
command -v rustup >/dev/null || die "rustup is required (the R3 neutral-toolchain pin uses 'rustup toolchain link')"
REPRO_ROOT="/private/tmp/signet-repro"
REPRO_TARGET="$REPRO_ROOT/target"
REPRO_TOOLCHAIN="$REPRO_ROOT/toolchain"
ACTIVE_SYSROOT="$(rustc --print sysroot)"
if [ ! -x "$REPRO_TOOLCHAIN/bin/rustc" ] || \
   [ "$("$REPRO_TOOLCHAIN/bin/rustc" --version)" != "$(rustc --version)" ]; then
  log "caching the toolchain at the neutral path (first run or version change)…"
  rm -rf "$REPRO_TOOLCHAIN"
  mkdir -p "$REPRO_ROOT"
  cp -R "$ACTIVE_SYSROOT" "$REPRO_TOOLCHAIN"
fi
rustup toolchain link signet-release-neutral "$REPRO_TOOLCHAIN" >/dev/null 2>&1 || \
  rustup toolchain link signet-release-neutral "$REPRO_TOOLCHAIN"
rm -rf "$REPRO_TARGET"
SIGNET_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
REPRO_RUSTFLAGS="--remap-path-prefix=$REPO=/signet-src"
REPRO_RUSTFLAGS="$REPRO_RUSTFLAGS --remap-path-prefix=$SIGNET_CARGO_HOME=/cargo-home"
REPRO_RUSTFLAGS="$REPRO_RUSTFLAGS --remap-path-prefix=$REPRO_TOOLCHAIN=/rustc-sysroot"
log "building release macOS signet (includes the Swift SE-PQC shim via cli/build.rs)…"
( cd "$REPO" && RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$REPRO_RUSTFLAGS" \
    CARGO_TARGET_DIR="$REPRO_TARGET" \
    cargo +signet-release-neutral build --release --locked --bin signet )
cp "$REPRO_TARGET/release/signet" "$APP/Contents/MacOS/signet"
VERSION="$("$REPRO_TARGET/release/signet" --version | awk '{print $NF}')"
log "signet version: $VERSION ($(du -h "$APP/Contents/MacOS/signet" | awk '{print $1}'))"
# Tag ↔ binary-version consistency (the other half of Bug027: the right tag on
# the wrong commit). Enforced only when the gate is live (notarized path).
if [ "$SKIP_NOTARIZE" -eq 0 ] && [ "$SOURCE_TAG" != "v$VERSION" ]; then
  die "tag/version mismatch: HEAD tag is '$SOURCE_TAG' but the built signet reports '$VERSION' (Bug027)"
fi
# The UNSIGNED macOS binary hash — captured BEFORE codesign. This (not the zip
# .sha256) is the reproducible-build anchor a watcher can actually match: the
# Developer-ID signature + notarization ticket are Apple-side nondeterminism
# (R2; Gus's S002 note §8).
MACOS_UNSIGNED_SHA="$(shasum -a 256 "$APP/Contents/MacOS/signet" | awk '{print $1}')"

# ── 3. static Linux signet (the bundled host-delegation helper) ───────────────
# Built natively in an arm64 alpine (musl) container → a STATIC aarch64-musl binary,
# portable across container distros (no glibc dependency). target/ goes to a Docker
# NAMED VOLUME, never a macOS bind-mount: the file-sharing layer has write-then-read
# lag that yields nondeterministic "can't find crate" failures
# (reference_linux_cross_build_use_named_volume). The repo is mounted read-only (we
# only read source; all build output lands in the volume via CARGO_TARGET_DIR).
log "building static Linux signet (aarch64-musl) in Docker…"
docker volume create "$LINUX_VOLUME" >/dev/null
docker run --rm --platform linux/arm64 \
  -v "$REPO":/src:ro -v "$LINUX_VOLUME":/target -w /src \
  -e CARGO_TARGET_DIR=/target \
  "$LINUX_BUILDER_IMAGE" \
  sh -c "apk add --no-cache musl-dev gcc make perl >/dev/null 2>&1 && cargo build --release --locked --bin signet"
docker run --rm --platform linux/arm64 \
  -v "$LINUX_VOLUME":/target -v "$OUT":/out \
  alpine sh -c "cp /target/release/signet /out/$LINUX_BIN_NAME"
cp "$OUT/$LINUX_BIN_NAME" "$APP/Contents/Resources/$LINUX_BIN_NAME"
chmod +x "$APP/Contents/Resources/$LINUX_BIN_NAME"
log "bundled Linux helper: $(file "$APP/Contents/Resources/$LINUX_BIN_NAME")"
# The Linux helper is fully byte-reproducible (S002: exact match, zero
# exclusions) — its hash is the strongest anchor in the manifest.
LINUX_SHA="$(shasum -a 256 "$APP/Contents/Resources/$LINUX_BIN_NAME" | awk '{print $1}')"

# ── 4. bundle metadata ────────────────────────────────────────────────────────
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"

# bug099: the app-bundle icon — the Finder / Launchpad / Get-Info representation of
# signet.app. The app is LSUIElement (no Dock icon while running), but the .app file
# itself still needs an icon or macOS shows a blank placeholder. Committed static
# .icns (byte-reproducible; regenerate from the brand seal via cli/assets/gen-appicon.sh).
cp "$REPO/cli/assets/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleExecutable</key><string>signet</string>
  <key>CFBundleName</key><string>signet</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <!-- Agent app: in host-signer mode the app shows only a menu-bar status item
       (no Dock icon, no app menu). LSUIElement makes it an agent from launch — no
       Dock-icon flash for the login agent — reinforcing the runtime
       setActivationPolicy(.accessory) the menu-bar code sets (menubar.rs). -->
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

cat > "$OUT/entitlements.plist" <<ENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>keychain-access-groups</key>
  <array><string>${TEAM_ID}.${BUNDLE_ID}</string></array>
  <key>com.apple.application-identifier</key>
  <string>${TEAM_ID}.${BUNDLE_ID}</string>
  <key>com.apple.developer.team-identifier</key>
  <string>${TEAM_ID}</string>
</dict>
</plist>
ENT

# ── 5. codesign (hardened runtime + SECURE TIMESTAMP — required for notarization) ──
log "codesigning (hardened runtime + secure timestamp + entitlements)…"
codesign --force --options runtime --timestamp \
  --entitlements "$OUT/entitlements.plist" \
  --sign "$SIGN_ID" "$APP"
codesign --verify --strict --verbose=2 "$APP"

if [ "$SKIP_NOTARIZE" -eq 0 ]; then
  # ── 6. notarize + staple ────────────────────────────────────────────────────
  log "notarizing (submitting to Apple's notary service — this takes a few minutes)…"
  ditto -c -k --keepParent "$APP" "$OUT/notarize.zip"
  xcrun notarytool submit "$OUT/notarize.zip" --keychain-profile "$NOTARY_PROFILE" --wait
  log "stapling the notarization ticket…"
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  spctl -a -t exec -vv "$APP" 2>&1 || true
fi

# ── 7. zip + public hash + build manifest (BOTH paths) ────────────────────────
# The manifest is emitted for --skip-notarize builds too (`"notarized": false`),
# so the toolchain capture and the unsigned-binary repro anchors are locally
# verifiable without a notarize round-trip (PQR item 1 PR 2). A skip-notarize
# zip is named -UNNOTARIZED and is NEVER distributable — the gate was bypassed
# and the app carries no ticket; one-version-one-binary applies to the
# notarized artifact name only.
if [ "$SKIP_NOTARIZE" -eq 1 ]; then
  DIST="$OUT/signet-${VERSION}-macos-UNNOTARIZED.zip"
else
  DIST="$OUT/signet-${VERSION}-macos.zip"
fi
# bug041: stage the bundle VERSION-NAMED (signet-<X.Y.Z>.app) so the guardian's
# extraction is distinguishable in Downloads (two releases both extracting to a
# bare "signet" was indistinguishable — Chris, S120). The bundle DIRECTORY name is
# not covered by the code signature or the stapled ticket (proven empirically S120:
# spctl accepted + codesign verify + stapler validate all pass on a renamed copy),
# and the installer accepts any *.app name (`running_app_bundle` checks the
# extension; the installed destination stays the fixed `signet.app`). The assisted
# update's `find_dot_app` falls back to the first top-level *.app. Gatekeeper is
# re-asserted on the staged copy below (notarized path only) — fail-closed, never
# ship a rename that somehow broke assessment.
STAGED="$OUT/signet-${VERSION}.app"
rm -rf "$STAGED"
/usr/bin/ditto "$APP" "$STAGED"
# bug144: strip extended attributes from the staged copy BEFORE zipping. ditto -c -k
# stores xattrs as AppleDouble entries, and `unzip` (which cannot apply xattrs)
# materialises them as ._* files INSIDE the bundle — adding files to a sealed bundle,
# so Gatekeeper reports "damaged" on a perfectly good artifact. The bundle's xattrs
# are build/download debris (com.apple.provenance, lastuseddate…), not signature
# material — proven empirically on v0.5.30: post-strip the bundle stays `spctl
# accepted` + stapler-valid, and the zip round-trips clean through BOTH extractors
# (ditto/Archive Utility AND unzip). The spctl re-assert below runs on the stripped
# copy, so "strip broke assessment" fails closed here rather than shipping.
xattr -cr "$STAGED"
if [ "$SKIP_NOTARIZE" -eq 0 ]; then
  spctl -a -t exec "$STAGED" || die "renamed staging bundle failed Gatekeeper assessment"
fi
ditto -c -k --keepParent "$STAGED" "$DIST"
rm -rf "$STAGED"
# bug144 negative control, in-pipeline: the shipped zip must contain no AppleDouble
# entries. If a future change reintroduces xattrs (or drops the strip above), this
# fires at build time instead of as a "damaged app" report from the field.
if unzip -l "$DIST" | awk '{print $4}' | grep -qE '(^|/)\._|__MACOSX'; then
  die "release zip contains AppleDouble (._*/__MACOSX) entries — unzip would corrupt the sealed bundle (bug144)"
fi
# The .sha256 companion ships next to the zip (served at /cli/*; the deploy
# uploads both — deploy-runbook §"Publish the CLI release"). `shasum -c`-checkable.
(cd "$OUT" && shasum -a 256 "$(basename "$DIST")" > "$(basename "$DIST").sha256")
SHA="$(awk '{print $1}' "$DIST.sha256")"

# The build manifest (Bug027 R2 / OSP {cli_hash, build_commit_sha, ...}): the
# record that would have caught the 0.4.0 tag-drift the moment it happened, and
# the anchor set a watcher rebuilds against. The zip sha256 is download-integrity
# only; the UNSIGNED binary hashes are the reproducibility anchors. Toolchains
# are recorded per-release (the hard version-pin sweep is Punch-List R5; the
# Xcode/Swift axis becomes load-bearing with the CryptoKit shim — PQR item 1 —
# and its fields are present from day one so the S002 verification extends to
# the Swift objects without a schema change). Uploaded alongside the zip at
# publish (deploy-runbook §"Publish the CLI release"); `deployed_at` is stamped
# by the publish step, not the build.
XCODE_VERSION="$( (xcodebuild -version 2>/dev/null | tr '\n' ' ' | sed 's/ $//') || true)"
[ -n "$XCODE_VERSION" ] || XCODE_VERSION="none (CommandLineTools only)"
MACOS_SDK="$(xcrun --show-sdk-version 2>/dev/null || echo unknown)"
# The Swift axis (Gus C2 / R2): the shim is in this binary as of PQR item 1, so
# the exact swiftc is a load-bearing toolchain coordinate. Reproducibility note
# (named exclusion, S002 §8-style): verify the LINKED unsigned binary, never
# the shim's .a intermediate — the intermediate carries a per-compile random
# `__swift_modhash` (an __LLVM metadata section the final link strips); the
# linked binary is byte-identical across rebuilds (verified empirically, S106).
SWIFTC_VERSION="$(swiftc --version 2>/dev/null | head -1 || true)"
[ -n "$SWIFTC_VERSION" ] || SWIFTC_VERSION="unknown (swiftc not found — the shim cannot have been built)"
# Named after the zip it describes (so a skip-notarize manifest is
# -UNNOTARIZED too and can never be mistaken for a published one).
MANIFEST="${DIST%.zip}.manifest.json"
cat > "$MANIFEST" <<MANIFEST_JSON
{
  "artifact": "$(basename "$DIST")",
  "version": "${VERSION}",
  "source_tag": "${SOURCE_TAG}",
  "build_commit_sha": "${BUILD_SHA}",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "notarized": $([ "$SKIP_NOTARIZE" -eq 0 ] && echo true || echo false),
  "zip_sha256": "${SHA}",
  "unsigned_binary_sha256": {
    "macos_signet": "${MACOS_UNSIGNED_SHA}",
    "linux_helper": "${LINUX_SHA}"
  },
  "toolchain": {
    "rustc": "$(rustc --version)",
    "cargo": "$(cargo --version)",
    "linux_builder_image": "${LINUX_BUILDER_IMAGE}",
    "xcode": "${XCODE_VERSION}",
    "macos_sdk": "${MACOS_SDK}",
    "swiftc": "${SWIFTC_VERSION}"
  },
  "reproducibility_pins": {
    "cargo_target_dir": "${REPRO_TARGET}",
    "toolchain_path": "${REPRO_TOOLCHAIN}",
    "note": "F-REPRO-R3: ld-prime derives LC_UUID from link-input paths; a verifier must build with BOTH pins at these exact locations (see Open-Source-Plan, Verification flow)"
  }
}
MANIFEST_JSON

echo ""
if [ "$SKIP_NOTARIZE" -eq 1 ]; then
  echo "✓ signed (NOT notarized) app: $APP"
  echo "✓ local zip:      $DIST  (UNNOTARIZED — local iteration/verification only, never distributable)"
  echo "✓ manifest:       $MANIFEST  (notarized=false; toolchain + unsigned-binary anchors locally checkable)"
  echo "  (re-run without --skip-notarize, from a pushed tag on a clean tree, to distribute)"
else
  echo "✓ shippable app:  $APP"
  echo "✓ distributable:  $DIST"
  echo "✓ sha256:         $SHA  (written to $DIST.sha256)"
  echo "✓ manifest:       $MANIFEST  (source_tag=$SOURCE_TAG, build_commit_sha=$BUILD_SHA)"
  echo "  (publish the manifest alongside the zip — deploy-runbook §\"Publish the CLI release\";"
  echo "   commit the hashes publicly at release — Open-Source-Plan reproducible-build verification)"
fi
