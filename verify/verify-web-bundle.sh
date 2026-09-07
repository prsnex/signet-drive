#!/usr/bin/env bash
# verify-web-bundle.sh: check that the deployed Signet Drive web bundle
# matches its served manifest, and that the manifest is anchored in the
# public-hashes history.
#
# Flow (OSP "Verification flow (web client)" steps 1-4; step 5, rebuilding
# from source, is verify-release.sh's wasm target):
#   1. Fetch /.well-known/signet-bundle-manifest.json from the origin.
#   2. Canonicalize (RFC 8785) and hash the manifest.
#   3. Confirm that hash appears in the public-hashes history (anchor).
#   4. Fetch every file the manifest lists; compare each sha256.
# A mismatch at step 4 means the served code differs from the manifest the
# server itself published: the alert condition.
#
# Exit codes: 0 VERIFIED · 20 MISMATCH (details name paths, never content)
#             64 PREREQ/ANCHOR FAILURE (the verification did not run)
#
# Usage: verify-web-bundle.sh [--origin URL] [--anchor-source <path-or-url>]
#                             [--skip-anchor] [--out DIR] [--keep]
# --skip-anchor checks the bundle against the served manifest only (steps 1,
# 2, 4). Weaker: it proves internal consistency, not history. Printed loudly.
set -u

VERSION="0.1.0"
SELF_SHA=$(shasum -a 256 "$0" | awk '{print $1}')
say() { echo "$*" >&2; }
tool_err() { say "verify-web-bundle: $*"; exit 64; }

ORIGIN="https://drive.mysignet.ca"
ANCHOR_DEFAULT="https://github.com/prsnex/signet-drive-public-hashes"
ANCHOR_SRC="" SKIP_ANCHOR=false OUT="" KEEP=false
while [ $# -gt 0 ]; do
  case "$1" in
    --origin) ORIGIN="${2:-}"; shift 2 ;;
    --anchor-source) ANCHOR_SRC="${2:-}"; shift 2 ;;
    --skip-anchor) SKIP_ANCHOR=true; shift ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --keep) KEEP=true; shift ;;
    *) tool_err "unknown argument: $1" ;;
  esac
done

say "verify-web-bundle $VERSION"
say "sha256 $SELF_SHA"
say "origin $ORIGIN"
$SKIP_ANCHOR && say "OVERRIDE: anchor check skipped; this run proves served-bundle internal consistency only"
[ -n "$ANCHOR_SRC" ] && say "OVERRIDE: anchor source is not the default public-hashes history"

WORK="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/verify-web-bundle.XXXXXX")}"
mkdir -p "$WORK" || tool_err "cannot create workdir"
$KEEP || trap 'rm -rf "$WORK"' EXIT

# ---- 1. fetch the manifest -------------------------------------------------
MANIFEST="$WORK/bundle-manifest.json"
curl -fsS --max-time 30 -o "$MANIFEST" "$ORIGIN/.well-known/signet-bundle-manifest.json" \
  || tool_err "manifest fetch failed: $ORIGIN/.well-known/signet-bundle-manifest.json"

# ---- 2. canonicalize + hash ------------------------------------------------
# RFC 8785 canonicalization. For this manifest's value domain (ASCII string
# paths, hex hashes, small integers) compact sorted-key JSON is equivalent.
# EQUIVALENCE BOUND (Hlin review, S131): re-check this approximation if the
# manifest schema ever gains a non-ASCII string, float, or big-integer field;
# those are where JCS and compact-sorted JSON diverge.
MSHA=$(python3 - "$MANIFEST" <<'PY'
import hashlib, json, sys
d = json.load(open(sys.argv[1]))
c = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
print(hashlib.sha256(c).hexdigest())
PY
) || tool_err "manifest parse/canonicalization failed"
BUILD_SHA=$(python3 -c "import json;print(json.load(open('$MANIFEST')).get('build_commit_sha','unknown'))")
say "manifest hash $MSHA (build_commit_sha $BUILD_SHA)"

# ---- 3. anchor -------------------------------------------------------------
if ! $SKIP_ANCHOR; then
  ANCHOR="${ANCHOR_SRC:-$ANCHOR_DEFAULT}"
  ADIR="$WORK/anchor"
  case "$ANCHOR" in
    http*) git clone --quiet --depth 50 "$ANCHOR" "$ADIR" 2>/dev/null || tool_err "anchor clone failed: $ANCHOR" ;;
    *) [ -d "$ANCHOR" ] || tool_err "anchor source not found: $ANCHOR"; cp -R "$ANCHOR" "$ADIR" ;;
  esac
  grep -rq "$MSHA" "$ADIR" 2>/dev/null \
    || tool_err "ANCHOR FAILURE: manifest hash $MSHA not in the anchor history (a manifest the operator never committed publicly)"
  say "anchor OK"
fi

# ---- 4. fetch and compare every listed file --------------------------------
# The served manifest's `files` is a map of path -> sha256. The file list is
# extracted first and a parse failure or an empty list is a hard stop: a
# verifier that checks zero files must never report VERIFIED.
FLIST="$WORK/files.tsv"
python3 - "$MANIFEST" > "$FLIST" <<'PY' || tool_err "manifest files parse failed"
import json, sys
d = json.load(open(sys.argv[1]))
files = d["files"]
items = files.items() if isinstance(files, dict) else ((f["path"], f["sha256"]) for f in files)
for path, sha in items:
    print(f"{path}\t{sha}")
PY
[ -s "$FLIST" ] || tool_err "manifest lists zero files; nothing to verify is a failure, not a pass"

FAIL=0; N=0
while IFS=$'\t' read -r path want; do
  N=$((N+1))
  got=$(curl -fsS --max-time 30 "$ORIGIN/$path" | shasum -a 256 | awk '{print $1}') || got="FETCH-FAILED"
  if [ "$got" != "$want" ]; then
    FAIL=$((FAIL+1))
    say "MISMATCH: $path"
  fi
done < "$FLIST"
say "checked $N files, $FAIL mismatched"

if [ "$FAIL" -eq 0 ]; then
  echo "verdict=VERIFIED origin=$ORIGIN manifest_sha=$MSHA files=$N script_sha=$SELF_SHA"
  exit 0
else
  echo "verdict=MISMATCH origin=$ORIGIN manifest_sha=$MSHA files=$N mismatches=$FAIL script_sha=$SELF_SHA"
  exit 20
fi
