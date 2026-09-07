#!/usr/bin/env bash
# verify-translog.sh: watcher-style verification of the Signet Drive public
# key transparency log.
#
# What it checks (Transparency-Log-Spec v0.13 + the PQR v2 entry format):
#   1. Downloads the full log via /v1/transparency/log/range (paginated).
#   2. Recomputes every entry_hash locally from canonical bytes (v1 and v2
#      layouts, version-aware); the server's reported hash is never trusted.
#   3. Verifies the prev_entry_hash chain link on every entry.
#   4. Verifies the epoch checkpoint structure (at most one; v2 only after it).
#   5. Flags §3a completeness anomalies (post-epoch accounts must carry
#      complete hybrid key sets; PQ-stripping-by-omission detection).
#   6. Recomputes the RFC 6962 Merkle root (0x00 leaf / 0x01 internal domain
#      separation) over the recomputed hashes; compares to the served root.
#   7. Anchors the last publicly committed root against the
#      signet-drive-transparency-log history (roots.jsonl).
# Receipt signature spot-checks are v0.2 (needs an ES256 verifier dependency);
# their absence is declared in the transcript, never silent.
#
# Exit codes: 0 VERIFIED · 20 LOG-MISBEHAVIOR (any local recomputation or
# chain/completeness/root check fails) · 64 PREREQ/ANCHOR FAILURE.
#
# Usage: verify-translog.sh [--origin URL] [--anchor-source <path-or-url>]
#                           [--skip-anchor] [--out DIR] [--keep]
set -u

VERSION="0.1.0"
SELF_SHA=$(shasum -a 256 "$0" | awk '{print $1}')
say() { echo "$*" >&2; }
tool_err() { say "verify-translog: $*"; exit 64; }

ORIGIN="https://drive.mysignet.ca"
ANCHOR_DEFAULT="https://github.com/prsnex/signet-drive-transparency-log"
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

say "verify-translog $VERSION"
say "sha256 $SELF_SHA"
say "origin $ORIGIN"
$SKIP_ANCHOR && say "OVERRIDE: anchor check skipped; root consistency is checked against the server only"
[ -n "$ANCHOR_SRC" ] && say "OVERRIDE: anchor source is not the default transparency-log history"
say "note: receipt signature spot-checks are not implemented in v0.1 (declared, not silent)"

WORK="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/verify-translog.XXXXXX")}"
mkdir -p "$WORK" || tool_err "cannot create workdir"
$KEEP || trap 'rm -rf "$WORK"' EXIT

# ---- 1. fetch root state ---------------------------------------------------
curl -fsS --max-time 30 -o "$WORK/root.json" "$ORIGIN/v1/transparency/log/root" \
  || tool_err "root fetch failed: $ORIGIN/v1/transparency/log/root"

# ---- 2. fetch the full log --------------------------------------------------
: > "$WORK/entries.jsonl"
CUR=1
while :; do
  curl -fsS --max-time 60 -o "$WORK/page.json" \
    "$ORIGIN/v1/transparency/log/range?start=$CUR&end=$((CUR+499))" \
    || tool_err "range fetch failed at entry $CUR"
  N=$(python3 -c "
import json
d = json.load(open('$WORK/page.json'))
es = d.get('entries', [])
with open('$WORK/entries.jsonl','a') as f:
    for e in es:
        f.write(json.dumps(e)+'\n')
print(len(es))
") || tool_err "range parse failed at entry $CUR"
  [ "$N" -eq 0 ] && break
  CUR=$((CUR+N))
done
TOTAL=$(wc -l < "$WORK/entries.jsonl" | tr -d ' ')
[ "$TOTAL" -gt 0 ] || tool_err "log has zero entries; nothing to verify is a failure, not a pass"
say "downloaded $TOTAL entries"

# ---- 3-6. local recomputation (hashes, chain, epoch, completeness, root) ----
python3 - "$WORK/entries.jsonl" "$WORK/root.json" <<'PY'
import base64, hashlib, json, struct, sys, uuid

PURPOSE = {"epoch": 0, "signing": 1, "kem": 2, "signing_pq": 3, "kem_pq": 4}

def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

entries = [json.loads(l) for l in open(sys.argv[1])]
root_state = json.load(open(sys.argv[2]))

bad_hash, bad_chain, notes = [], [], []
prev_hash = b"\x00" * 32
epoch_seen_at = None
recomputed = []

for e in entries:
    eid = e["entry_id"]
    ver = e.get("entry_version", 1)
    acct = uuid.UUID(e["account_id"]).bytes if e.get("account_id") else b"\x00" * 16
    purpose = PURPOSE[e["key_purpose"]]
    alg = e["algorithm"].encode()
    pk = b64u(e["public_key"]) if e.get("public_key") else b""
    created = int(e["created_at"])
    served_prev = bytes.fromhex(e["prev_entry_hash"])
    served_hash = bytes.fromhex(e["entry_hash"])

    if served_prev != prev_hash:
        bad_chain.append(eid)

    if ver == 2:
        cb = (b"\x02" + struct.pack(">Q", eid) + acct + bytes([purpose])
              + struct.pack(">I", len(alg)) + alg
              + struct.pack(">I", len(pk)) + pk
              + struct.pack(">Q", created) + served_prev)
    else:
        cb = (struct.pack(">Q", eid) + acct + bytes([purpose])
              + struct.pack(">I", len(alg)) + alg + pk
              + struct.pack(">Q", created) + served_prev)
    h = hashlib.sha256(cb).digest()
    if h != served_hash:
        bad_hash.append(eid)
    prev_hash = served_hash
    recomputed.append(h)

    if purpose == 0:
        if epoch_seen_at is not None:
            notes.append(f"second epoch checkpoint at entry {eid}")
        epoch_seen_at = eid
    elif purpose in (3, 4) and epoch_seen_at is None:
        notes.append(f"v2 pq entry {eid} before any epoch checkpoint")

# 5. completeness (post-epoch accounts carry complete hybrid sets)
if epoch_seen_at is not None:
    post = {}
    for e in entries:
        if e["entry_id"] > epoch_seen_at and e.get("account_id"):
            post.setdefault(e["account_id"], set()).add(e["key_purpose"])
    for acct, ps in post.items():
        if "kem" in ps and "kem_pq" not in ps:
            notes.append(f"account {acct[:8]}… has kem without kem_pq (post-epoch)")
        if "signing" in ps and "signing_pq" not in ps:
            notes.append(f"account {acct[:8]}… has signing without signing_pq (post-epoch)")

# 6. Merkle root over recomputed hashes.
# RFC 6962 MTH: non-power-of-two sizes split at the largest power of two
# less than n. This is the authoritative (and only) root computation here.
def mth(hashes):
    n = len(hashes)
    if n == 0:
        return None
    if n == 1:
        return hashlib.sha256(b"\x00" + hashes[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + mth(hashes[:k]) + mth(hashes[k:])).digest()

served_size = root_state["current_log_size"]
served_root = root_state["current_merkle_root"]
ok = True
if bad_hash:
    ok = False
    print(f"MISBEHAVIOR entry_hash mismatch at entries: {bad_hash[:10]}")
if bad_chain:
    ok = False
    print(f"MISBEHAVIOR prev-chain break at entries: {bad_chain[:10]}")
for n_ in notes:
    ok = False
    print(f"ANOMALY {n_}")
if served_size != len(recomputed):
    print(f"note: served log_size {served_size} vs downloaded {len(recomputed)} (log may have grown mid-run)")
local_root = mth(recomputed[:served_size]).hex() if served_size <= len(recomputed) else None
if local_root != served_root:
    ok = False
    print(f"MISBEHAVIOR recomputed root {local_root} != served root {served_root}")
else:
    print(f"root OK: {served_root} over {served_size} entries, recomputed locally")
sys.exit(0 if ok else 3)
PY
PYRC=$?
[ $PYRC -eq 0 ] || { echo "verdict=LOG-MISBEHAVIOR origin=$ORIGIN entries=$TOTAL script_sha=$SELF_SHA"; exit 20; }

# ---- 7. anchor --------------------------------------------------------------
if ! $SKIP_ANCHOR; then
  COMMITTED_ROOT=$(python3 -c "
import json
d = json.load(open('$WORK/root.json'))
lc = d.get('last_publicly_committed') or {}
print(lc.get('merkle_root',''))")
  if [ -z "$COMMITTED_ROOT" ]; then
    tool_err "server reports no publicly committed root; anchor cannot be checked (pre-launch state or publication failure; investigate)"
  fi
  ANCHOR="${ANCHOR_SRC:-$ANCHOR_DEFAULT}"
  ADIR="$WORK/anchor"
  case "$ANCHOR" in
    http*) git clone --quiet --depth 100 "$ANCHOR" "$ADIR" 2>/dev/null || tool_err "anchor clone failed: $ANCHOR" ;;
    *) [ -d "$ANCHOR" ] || tool_err "anchor source not found: $ANCHOR"; cp -R "$ANCHOR" "$ADIR" ;;
  esac
  grep -rq "$COMMITTED_ROOT" "$ADIR" 2>/dev/null \
    || { echo "verdict=LOG-MISBEHAVIOR origin=$ORIGIN reason=committed-root-not-in-public-history script_sha=$SELF_SHA"; exit 20; }
  say "anchor OK: last committed root present in the public history"
fi

echo "verdict=VERIFIED origin=$ORIGIN entries=$TOTAL script_sha=$SELF_SHA"
exit 0
