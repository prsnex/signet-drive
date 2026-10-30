#!/usr/bin/env bash
# verify-translog.sh: watcher-style verification of the Signet Drive public
# key transparency log, one epoch at a time.
#
# What it checks (the Transparency-Log Spec + the PQR transparency-log entry doc):
#   1. Reads the served epoch from /v1/transparency/log/root, then downloads
#      that epoch's whole log via /range?epoch=N (paginated). A serve during
#      the run is refused by the server at the next page, never mixed in.
#   2. Recomputes every entry_hash locally from canonical bytes (v1, v2 and v3
#      layouts, version-aware); the server's reported hash is never trusted.
#   3. Verifies the prev_entry_hash chain on every entry, from 32 zero bytes.
#   4. Verifies the epoch's structure. Epoch 1: at most one checkpoint, and v2
#      PQ entries only after it. Epoch 2 and later: entry 1 is the genesis (v3,
#      purpose epoch, no account index), whose payload binds this epoch's
#      number, the previous epoch's final size and root (as /root's
#      previous_epoch reports them) and SHA-256 of the epoch's VRF key (as
#      /v1/server-info serves it); every other entry is v3 and names a 64-byte
#      account index; there is no second genesis.
#   5. Flags §3a completeness anomalies (post-checkpoint accounts must carry
#      complete hybrid key sets), per account id in epoch 1 and per account
#      index from epoch 2.
#   6. Recomputes the RFC 6962 Merkle root (0x00 leaf / 0x01 internal domain
#      separation) over the recomputed hashes; compares to the served root.
#   7. Anchors against the public history (signet-drive-transparency-log): the
#      last publicly committed root is present; from epoch 2, the previous
#      epoch's end line and this epoch's vrf-keys.jsonl line agree with the
#      genesis (the CLI's genesis check, design §10.7).
# Every mismatch line states its total count and marks a cut list (bug255).
# Receipt signature spot-checks are not implemented (they need an ES256
# verifier dependency); their absence is declared in the transcript.
#
# Exit codes: 0 VERIFIED · 20 LOG-MISBEHAVIOR (any local recomputation or
# chain/structure/completeness/root/anchor disagreement) · 64 PREREQ/ANCHOR
# FAILURE (a fetch failed, or the public history does not yet carry the epoch).
#
# Usage: verify-translog.sh [--origin URL] [--anchor-source <path-or-url>]
#                           [--skip-anchor] [--out DIR] [--keep]
#        verify-translog.sh --self-test
set -u

VERSION="0.2.0"
SELF_SHA=$(shasum -a 256 "$0" | awk '{print $1}')
say() { echo "$*" >&2; }
tool_err() { say "verify-translog: $*"; exit 64; }

# The checks over files on disk: an epoch's entries (one JSON object per
# line), its /root, /v1/server-info, and the anchor clone ("" to skip). Exit 0
# when everything verifies, 3 on any misbehavior, 4 when the public history
# does not carry what the epoch needs. The live run and the self-test both
# call this, so the self-test drives the code a run uses.
check_log() {
  python3 - "$@" <<'PY'
import base64, hashlib, json, os, struct, sys, uuid

PURPOSE = {"epoch": 0, "signing": 1, "kem": 2, "signing_pq": 3, "kem_pq": 4}
GENESIS_ALG = "signet-translog-v3"
GENESIS_TAG = b"signet-pubkey-log-v3-epoch"

def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

entries = [json.loads(l) for l in open(sys.argv[1])]
root_state = json.load(open(sys.argv[2]))
server_info = json.load(open(sys.argv[3]))
anchor_dir = sys.argv[4]
epoch = root_state.get("epoch", 1)

bad_hash, bad_chain, notes = [], [], []
prev_hash = b"\x00" * 32
checkpoint_at = None
recomputed = []
genesis = None

def report(kind, ids):
    """bug255: the total, always, and a mark when the list is cut."""
    n = len(ids)
    shown = ids if n <= 10 else ids[:10]
    cut = "" if n <= 10 else f" ... and {n - 10} more (list cut at 10)"
    print(f"MISBEHAVIOR {kind} at {n} entr{'y' if n == 1 else 'ies'}: {shown}{cut}")

for e in entries:
    eid = e["entry_id"]
    ver = e.get("entry_version", 1)
    purpose = PURPOSE[e["key_purpose"]]
    alg = e["algorithm"].encode()
    pk = b64u(e["public_key"]) if e.get("public_key") else b""
    created = int(e["created_at"])
    served_prev = bytes.fromhex(e["prev_entry_hash"])
    served_hash = bytes.fromhex(e["entry_hash"])

    if served_prev != prev_hash:
        bad_chain.append(eid)

    if ver == 3:
        idx = e.get("account_index")
        index = bytes.fromhex(idx) if idx else b"\x00" * 64
        if len(index) != 64:
            notes.append(f"entry {eid} has an account index of {len(index)} bytes, not 64")
        cb = (b"\x03" + struct.pack(">Q", eid) + index + bytes([purpose])
              + struct.pack(">I", len(alg)) + alg
              + struct.pack(">I", len(pk)) + pk
              + struct.pack(">Q", created) + served_prev)
    elif ver == 2:
        acct = uuid.UUID(e["account_id"]).bytes if e.get("account_id") else b"\x00" * 16
        cb = (b"\x02" + struct.pack(">Q", eid) + acct + bytes([purpose])
              + struct.pack(">I", len(alg)) + alg
              + struct.pack(">I", len(pk)) + pk
              + struct.pack(">Q", created) + served_prev)
    else:
        acct = uuid.UUID(e["account_id"]).bytes if e.get("account_id") else b"\x00" * 16
        cb = (struct.pack(">Q", eid) + acct + bytes([purpose])
              + struct.pack(">I", len(alg)) + alg + pk
              + struct.pack(">Q", created) + served_prev)
    h = hashlib.sha256(cb).digest()
    if h != served_hash:
        bad_hash.append(eid)
    prev_hash = served_hash
    recomputed.append(h)

    if epoch >= 2:
        # 4, from epoch 2: the genesis first, v3 throughout, an index on every key.
        if ver != 3:
            notes.append(f"entry {eid} is v{ver} in epoch {epoch}, where every entry is v3")
        if eid == 1:
            if purpose != 0 or e["algorithm"] != GENESIS_ALG or e.get("account_index"):
                notes.append(f"entry 1 of epoch {epoch} is not a genesis entry")
            else:
                genesis = (h, pk)
        elif purpose == 0:
            notes.append(f"second genesis entry at entry {eid}")
        elif not e.get("account_index"):
            notes.append(f"entry {eid} names no account index")
    elif purpose == 0:
        if checkpoint_at is not None:
            notes.append(f"second epoch checkpoint at entry {eid}")
        checkpoint_at = eid
    elif purpose in (3, 4) and checkpoint_at is None:
        notes.append(f"v2 pq entry {eid} before any epoch checkpoint")

# 4, from epoch 2: what the genesis payload binds.
prev_bound = None
vrf_key = None
if epoch >= 2:
    vrf_hex = (server_info.get("translog") or {}).get("vrf_public_key")
    vrf_key = bytes.fromhex(vrf_hex) if vrf_hex else None
    if genesis is None:
        notes.append(f"epoch {epoch} has no genesis entry")
    else:
        payload = genesis[1]
        head = GENESIS_TAG + b"\x00"
        if len(payload) != len(head) + 2 + 8 + 32 + 32 or not payload.startswith(head):
            notes.append("the genesis payload is not the v3 epoch payload")
        else:
            body = payload[len(head):]
            g_epoch = struct.unpack(">H", body[:2])[0]
            g_size = struct.unpack(">Q", body[2:10])[0]
            g_root = body[10:42].hex()
            g_key_hash = body[42:74]
            prev_bound = (g_size, g_root)
            if g_epoch != epoch:
                notes.append(f"the genesis names epoch {g_epoch}, but the served epoch is {epoch}")
            pe = root_state.get("previous_epoch") or {}
            if (pe.get("epoch"), pe.get("log_size"), pe.get("merkle_root")) != (epoch - 1, g_size, g_root):
                notes.append(f"the genesis binds epoch {epoch - 1} at size {g_size}, root {g_root}, "
                             f"but /root reports previous_epoch {pe}")
            if vrf_key is None or hashlib.sha256(vrf_key).digest() != g_key_hash:
                notes.append("the genesis does not bind the VRF key /v1/server-info serves")

# 5. completeness: post-checkpoint accounts carry complete hybrid sets.
post = {}
for e in entries:
    who = e.get("account_index") or e.get("account_id")
    if not who or e["key_purpose"] == "epoch":
        continue
    if epoch >= 2 or (checkpoint_at is not None and e["entry_id"] > checkpoint_at):
        post.setdefault(who, set()).add(e["key_purpose"])
for who, ps in post.items():
    if "kem" in ps and "kem_pq" not in ps:
        notes.append(f"account {who[:8]}… has kem without kem_pq (post-checkpoint)")
    if "signing" in ps and "signing_pq" not in ps:
        notes.append(f"account {who[:8]}… has signing without signing_pq (post-checkpoint)")

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
    report("entry_hash mismatch", bad_hash)
if bad_chain:
    ok = False
    report("prev-chain break", bad_chain)
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
    print(f"root OK: {served_root} over {served_size} entries of epoch {epoch}, recomputed locally")

# 7, from epoch 2: the public history agrees with the genesis.
incomplete = False
if anchor_dir and epoch >= 2 and genesis is not None and prev_bound is not None:
    def lines(name):
        path = os.path.join(anchor_dir, name)
        return [json.loads(l) for l in open(path) if l.strip()] if os.path.exists(path) else []
    end = [l for l in lines("roots.jsonl")
           if l.get("epoch_end") and l.get("epoch", 1) == epoch - 1]
    keys = [l for l in lines("vrf-keys.jsonl") if l.get("epoch") == epoch]
    if not end:
        incomplete = True
        print(f"ANCHOR the public history carries no end line for epoch {epoch - 1} yet")
    elif (end[-1].get("log_size"), end[-1].get("merkle_root")) != prev_bound:
        ok = False
        print(f"MISBEHAVIOR the genesis binds epoch {epoch - 1} at {prev_bound}, but its published "
              f"end line says ({end[-1].get('log_size')}, {end[-1].get('merkle_root')})")
    if not keys:
        incomplete = True
        print(f"ANCHOR vrf-keys.jsonl carries no line for epoch {epoch} yet")
    elif len(keys) > 1:
        ok = False
        print(f"MISBEHAVIOR vrf-keys.jsonl carries {len(keys)} lines for epoch {epoch}")
    else:
        if vrf_key is None or keys[0].get("vrf_public_key") != vrf_key.hex():
            ok = False
            print(f"MISBEHAVIOR the served VRF key is not the one vrf-keys.jsonl publishes for epoch {epoch}")
        if keys[0].get("genesis_entry_hash") != genesis[0].hex():
            ok = False
            print(f"MISBEHAVIOR the genesis does not recompute to the published genesis_entry_hash")
    if ok and not incomplete:
        print(f"anchor OK: epoch {epoch - 1}'s end line and epoch {epoch}'s VRF key line agree with the genesis")
sys.exit(3 if not ok else 4 if incomplete else 0)
PY
}

# --self-test: the checks over fixtures on disk, no network. The epoch-2
# fixture's hashes and root come from the crypto crate's own entry_hash_v3,
# epoch_payload_v3 and merkle_root (pinned below), so the Python v3 rule is
# checked against the Rust one.
self_test() {
  local dir; dir=$(mktemp -d "${TMPDIR:-/tmp}/verify-translog-selftest.XXXXXX") || exit 1
  trap 'rm -rf "$dir"' RETURN
  local pass=0 ran=0 out rc
  expect() { # expect <name> <want-rc> <grep-pattern> <fixture-dir>
    ran=$((ran + 1))
    out=$(cd "$4" && check_log entries.jsonl root.json server-info.json "$(cat anchor-arg)" 2>&1); rc=$?
    if [ "$rc" -eq "$2" ] && printf '%s\n' "$out" | grep -E -- "$3" >/dev/null; then
      pass=$((pass + 1)); echo "  ok   $1"
    else
      echo "  FAIL $1 (rc=$rc, want $2; /$3/)"; printf '%s\n' "$out" | sed 's/^/       /'
    fi
  }
  python3 - "$dir" <<'PY' || { echo "self-test: fixture build failed"; return 1; }
import base64, copy, hashlib, json, os, sys, uuid
d = sys.argv[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# Known answers from signet_crypto (translog::entry_hash_v3, epoch_payload_v3,
# merkle::merkle_root): epoch 2 opened on (11, 0x11 × 32) under crypto-wasm's
# VRF key, then a hybrid KEM pair under that key's known-answer index.
VRF = "3e440469a098036d89ffb2d77a4542928f2f74c2b5769da7480736ace829dc10"
INDEX = ("69f8f2ca9cc69e6e18aa9bef8dcbb0f6df0ff32e46b9c60f7b6da89850f82f98"
         "b9a038a32b8c22204821abcfdfd5ae5f2d1bcf55ff3c6d6300accbfa2e1cad55")
PAYLOAD = ("7369676e65742d7075626b65792d6c6f672d76332d65706f6368000002000000000000000b"
           "1111111111111111111111111111111111111111111111111111111111111111"
           "1579d610eebcc433138125b6a37e308966d84919d8eaffd68cf02caf988805fb")
GENESIS = "ec6f991305b821c0c6ee4ed046f3ef2f877ded00f2f59da54d2f6fdf5aee078b"
ENTRY2 = "ac5c499905f9b01570cb5877e9724f81ba0085782a7d54026069cb2b73d525e4"
ENTRY3 = "4163b3e6c1ec706a948792352fed1054b22afefe0ff961705485b0794b61930c"
ROOT = "63d052f5a2750939d2ddf02c93992b7bd0d821c33ef42d359f15c0370213a06a"

e2 = [
    {"epoch": 2, "entry_id": 1, "entry_version": 3, "account_index": None,
     "key_purpose": "epoch", "algorithm": "signet-translog-v3",
     "public_key": b64(bytes.fromhex(PAYLOAD)), "created_at": 1793000000,
     "prev_entry_hash": "00" * 32, "entry_hash": GENESIS},
    {"epoch": 2, "entry_id": 2, "entry_version": 3, "account_index": INDEX,
     "key_purpose": "kem", "algorithm": "ECDH-ES+A256KW",
     "public_key": b64(b"\x04" + b"\x22" * 64), "created_at": 1793000001,
     "prev_entry_hash": GENESIS, "entry_hash": ENTRY2},
    {"epoch": 2, "entry_id": 3, "entry_version": 3, "account_index": INDEX,
     "key_purpose": "kem_pq", "algorithm": "ML-KEM-1024",
     "public_key": b64(b"\x33" * 1568), "created_at": 1793000002,
     "prev_entry_hash": ENTRY2, "entry_hash": ENTRY3},
]
root2 = {"epoch": 2, "current_log_size": 3, "current_merkle_root": ROOT,
         "previous_epoch": {"epoch": 1, "log_size": 11, "merkle_root": "11" * 32}}
info2 = {"translog": {"epoch": 2, "vrf_public_key": VRF}}
roots_jsonl = [{"log_size": 11, "merkle_root": "11" * 32},
               {"epoch": 1, "epoch_end": True, "log_size": 11, "merkle_root": "11" * 32}]
keys_jsonl = [{"epoch": 2, "vrf_suite": "ECVRF-RISTRETTO255-SHA512", "vrf_public_key": VRF,
               "genesis_entry_hash": GENESIS}]

def fixture(name, entries, root, info, roots=None, keys=None, anchored=True):
    f = os.path.join(d, name); os.makedirs(f)
    with open(os.path.join(f, "entries.jsonl"), "w") as out:
        out.writelines(json.dumps(e) + "\n" for e in entries)
    json.dump(root, open(os.path.join(f, "root.json"), "w"))
    json.dump(info, open(os.path.join(f, "server-info.json"), "w"))
    a = os.path.join(f, "anchor")
    if anchored:
        os.makedirs(a)
        with open(os.path.join(a, "roots.jsonl"), "w") as out:
            out.writelines(json.dumps(l) + "\n" for l in (roots_jsonl if roots is None else roots))
        with open(os.path.join(a, "vrf-keys.jsonl"), "w") as out:
            out.writelines(json.dumps(l) + "\n" for l in (keys_jsonl if keys is None else keys))
    open(os.path.join(f, "anchor-arg"), "w").write(a if anchored else "")

fixture("e2-good", e2, root2, info2)
tampered = copy.deepcopy(e2); tampered[1]["created_at"] += 1
fixture("e2-tampered", tampered, root2, info2)
fixture("e2-wrong-prev", e2, {**root2, "previous_epoch": {"epoch": 1, "log_size": 12, "merkle_root": "11" * 32}}, info2)
fixture("e2-wrong-key", e2, root2, {"translog": {"epoch": 2, "vrf_public_key": "aa" * 32}})
fixture("e2-end-line-disagrees", e2, root2, info2,
        roots=[{"epoch": 1, "epoch_end": True, "log_size": 10, "merkle_root": "11" * 32}])
fixture("e2-no-key-line-yet", e2, root2, info2, keys=[])
nogen = copy.deepcopy(e2); nogen[1]["account_index"] = None
fixture("e2-key-without-index", nogen, root2, info2)
# Gus, at unit 4: a genesis whose payload names epoch 3 under a served epoch 2
# (the epoch number sits after the 26-byte tag and its 0x00).
wrong_epoch = copy.deepcopy(e2)
payload3 = bytearray(bytes.fromhex(PAYLOAD)); payload3[27:29] = (3).to_bytes(2, "big")
wrong_epoch[0]["public_key"] = b64(bytes(payload3))
fixture("e2-genesis-names-epoch-3", wrong_epoch, root2, info2)

# bug255: twelve epoch-1 entries whose served hashes are all wrong (the chain
# links the served hashes, so only the hash check fires).
e1, prev = [], "00" * 32
for i in range(1, 13):
    wrong = hashlib.sha256(b"wrong %d" % i).hexdigest()
    e1.append({"entry_id": i, "entry_version": 1, "account_id": str(uuid.UUID(int=i)),
               "key_purpose": "kem", "algorithm": "ECDH-ES+A256KW",
               "public_key": b64(b"\x04" + bytes([i]) * 64), "created_at": 1700000000 + i,
               "prev_entry_hash": prev, "entry_hash": wrong})
    prev = wrong
fixture("e1-twelve-mismatches", e1, {"current_log_size": 12, "current_merkle_root": "00" * 32},
        {}, anchored=False)
PY
  echo "verify-translog $VERSION --self-test"
  expect "epoch 2 recomputes to the crypto crate's own hashes and root" 0 'root OK: 63d052f5.* over 3 entries of epoch 2' "$dir/e2-good"
  expect "epoch 2's anchor lines agree with the genesis" 0 '^anchor OK' "$dir/e2-good"
  expect "a tampered v3 entry is a mismatch, counted" 3 'entry_hash mismatch at 1 entry: \[2\]$' "$dir/e2-tampered"
  expect "a genesis that does not bind /root's previous epoch" 3 'the genesis binds epoch 1 at size 11' "$dir/e2-wrong-prev"
  expect "a genesis that does not bind the served VRF key" 3 'does not bind the VRF key' "$dir/e2-wrong-key"
  expect "a published end line that disagrees with the genesis" 3 'its published end line says \(10,' "$dir/e2-end-line-disagrees"
  expect "a history not yet carrying the key line is incomplete, not verified" 4 'carries no line for epoch 2 yet' "$dir/e2-no-key-line-yet"
  expect "a key with no account index in epoch 2" 3 'entry 2 names no account index' "$dir/e2-key-without-index"
  expect "a genesis naming another epoch than the served one" 3 'the genesis names epoch 3, but the served epoch is 2' "$dir/e2-genesis-names-epoch-3"
  expect "bug255: twelve mismatches print the total and mark the cut" 3 'entry_hash mismatch at 12 entries: \[1, 2, 3, 4, 5, 6, 7, 8, 9, 10\] \.\.\. and 2 more \(list cut at 10\)' "$dir/e1-twelve-mismatches"
  echo "self-test: $pass/$ran passed (10 expected)"
  [ "$ran" -eq 10 ] && [ "$pass" -eq "$ran" ]
}

# The self-test is dispatched before anything else touches the network or
# the arguments (S164: a dispatch other options could swallow).
if [ "${1:-}" = "--self-test" ]; then
  self_test; exit $?
fi

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
say "note: receipt signature spot-checks are not implemented (declared, not silent)"

WORK="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/verify-translog.XXXXXX")}"
mkdir -p "$WORK" || tool_err "cannot create workdir"
$KEEP || trap 'rm -rf "$WORK"' EXIT

# ---- 1. the served epoch, and what the genesis is checked against -----------
curl -fsS --max-time 30 -o "$WORK/root.json" "$ORIGIN/v1/transparency/log/root" \
  || tool_err "root fetch failed: $ORIGIN/v1/transparency/log/root"
curl -fsS --max-time 30 -o "$WORK/server-info.json" "$ORIGIN/v1/server-info" \
  || tool_err "server-info fetch failed: $ORIGIN/v1/server-info"
EPOCH=$(python3 -c "import json; print(json.load(open('$WORK/root.json')).get('epoch', 1))") \
  || tool_err "root parse failed"
say "served epoch $EPOCH"

# ---- 2. fetch the epoch's whole log -----------------------------------------
: > "$WORK/entries.jsonl"
CUR=1
while :; do
  # At the epoch read above: a serve mid-run is refused (410/404), never mixed.
  curl -fsS --max-time 60 -o "$WORK/page.json" \
    "$ORIGIN/v1/transparency/log/range?epoch=$EPOCH&start=$CUR&end=$((CUR+499))" \
    || tool_err "range fetch failed at entry $CUR of epoch $EPOCH (a serve during the run is refused here: run again)"
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
[ "$TOTAL" -gt 0 ] || tool_err "epoch $EPOCH has zero entries; nothing to verify is a failure, not a pass"
say "downloaded $TOTAL entries of epoch $EPOCH"

# ---- the public history, before the checks that read it ----------------------
ADIR=""
if ! $SKIP_ANCHOR; then
  ANCHOR="${ANCHOR_SRC:-$ANCHOR_DEFAULT}"
  ADIR="$WORK/anchor"
  case "$ANCHOR" in
    http*) git clone --quiet --depth 100 "$ANCHOR" "$ADIR" 2>/dev/null || tool_err "anchor clone failed: $ANCHOR" ;;
    *) [ -d "$ANCHOR" ] || tool_err "anchor source not found: $ANCHOR"; cp -R "$ANCHOR" "$ADIR" ;;
  esac
fi

# ---- 3-7. local recomputation and the genesis anchor ----------------------------
check_log "$WORK/entries.jsonl" "$WORK/root.json" "$WORK/server-info.json" "$ADIR"
PYRC=$?
case $PYRC in
  0) ;;
  4) tool_err "the public history does not yet carry epoch $EPOCH's end line or key line (the cut publishes them before it serves; run again)" ;;
  *) echo "verdict=LOG-MISBEHAVIOR origin=$ORIGIN epoch=$EPOCH entries=$TOTAL script_sha=$SELF_SHA"; exit 20 ;;
esac

# ---- 7. the last committed root is in the public history ------------------------
if ! $SKIP_ANCHOR; then
  COMMITTED_ROOT=$(python3 -c "
import json
d = json.load(open('$WORK/root.json'))
lc = d.get('last_publicly_committed') or {}
print(lc.get('merkle_root',''))")
  if [ -z "$COMMITTED_ROOT" ]; then
    tool_err "server reports no publicly committed root for epoch $EPOCH; anchor cannot be checked (a fresh epoch before its first root, or a publication failure; investigate)"
  fi
  grep -rq "$COMMITTED_ROOT" "$ADIR" 2>/dev/null \
    || { echo "verdict=LOG-MISBEHAVIOR origin=$ORIGIN epoch=$EPOCH reason=committed-root-not-in-public-history script_sha=$SELF_SHA"; exit 20; }
  say "anchor OK: last committed root present in the public history"
fi

echo "verdict=VERIFIED origin=$ORIGIN epoch=$EPOCH entries=$TOTAL script_sha=$SELF_SHA"
exit 0
