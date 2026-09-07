#!/usr/bin/env bash
# signet-export.sh: produce the curated public tree from a private release tag,
# and run the Stage-1 export gate over it.
#
# Interface: signet-export-tool-interface-contract v01 (Gus, 2026-07-21).
#   signet-export.sh --tag <tag-or-sha> --out <dir> [--dry-run] [--repo <path>] [--allowlist <file>]
#
# The tool is a pure transform plus gate. It holds no credentials and performs
# no push. Exit codes: 0 GATE-PASS, 10 GATE-FAIL, 64+ TOOL-ERROR (never conflated).
# Verdicts are content-free: a failing check names the path and the check id,
# never the matching content.
#
# Stage 1 (this tool, private-side, pre-push) enforces every check.
# Stage 2 (public CI) re-proves the non-secret-dependent subset.
set -u

VERSION="0.2.1"
CONTRACT_VERSION=1
SELF_SHA=$(shasum -a 256 "$0" | awk '{print $1}')

# The optional-unmatched channel: LOUD, informational, never gating. Defined
# HERE, above every use — 0.2.0 called note() from the optional copy loop 94
# lines before note()'s definition, so both real warnings in the v0.5.58
# dry-run died as command-not-found inside a green run. note() is also the
# WRONG channel even once defined: it feeds FINDINGS (gate-failing), and an
# optional's absence is informational by design (the S202 comment at the call
# site: the operator reads the list; ratified-content absence is a content
# question, not a gate verdict). The count rides the final verdict line so a
# recorded run always states it.
OPT_UNMATCHED=0
warn_opt() { OPT_UNMATCHED=$((OPT_UNMATCHED+1)); echo "  ! optional-unmatched: $1" >&2; }

# Guard-sensitive literals, constructed so this SOURCE file never contains a
# contiguous credential-shaped token or infrastructure address (the estate
# content guard scans home trees before commit; 2026-07-26, Mira's sweep
# blocked on exactly these). The RUNTIME values are intact: fixtures generated
# from these variables still match the gate's own regexes exactly.
INFRA_IP='148.113.''205.244'                 # split: the quad never appears in source
INFRA_IP_RE="\\b${INFRA_IP//./\\.}\\b"       # ERE form, dots escaped
AWS_EX_KEY='AKIA''IOSFODNN7EXAMPLE'          # AWS documentation example key, split

# Substrate + local-environment terms (Chris's ruling, 2026-08-10: no model or
# vendor substrate may be associated with any public artifact; names Hlin, Gus,
# Chris are fine). Split so the guard never sees them contiguous in source.
# Case-insensitive: the vendor + assistant names. Case-sensitive word-bounded:
# model names that are also English words. Plus the LOCAL environment leaks the
# flattened tmp encoding hides from the slashed-path patterns (found live:
# web/e2e, 2026-08-10; a session scratchpad path shipped in a spec).
SUB_CI="$(printf '%s|%s' 'cla''ude' 'anthro''pic')"
SUB_CS="$(printf '\\b%s\\b|\\b%s\\b|\\b%s\\b' 'Op''us' 'Fab''le' 'Son''net')"
SUB_ENV="$(printf '%s|%s' 'chrisracz''kowski' 'arcadia''-grove')"

# ---- argument parsing (tool-errors are 64+) --------------------------------
TAG="" OUT="" DRY_RUN=false SELF_TEST=false
# Default: the repo containing the CWD (the normal case; run from inside the tree),
# else the CWD. Never a machine-specific absolute path: the tool must be runnable,
# testable, and auditable by anyone, on any checkout, with no write access anywhere
# (interface contract §1). Override with --repo or SIGNET_REPO.
REPO="${SIGNET_REPO:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
ALLOWLIST="$(cd "$(dirname "$0")" && pwd)/export-allowlist.txt"
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --repo) REPO="${2:-}"; shift 2 ;;
    --allowlist) ALLOWLIST="${2:-}"; shift 2 ;;
    --self-test) SELF_TEST=true; shift ;;
    *) echo "signet-export: unknown argument: $1" >&2; exit 64 ;;
  esac
done

# ---- POSITIVE CONTROL (--self-test) ----------------------------------------
# A gate that cannot be shown to fail is theater. This gate's failure mode is
# fail-OPEN: a neutered check returns GATE-PASS on a tree containing exactly
# what the check exists to stop, byte-identical to a real pass, and the
# content-free verdicts (correct by design) remove the only way a human would
# notice vacuity. The first evidence would be a secret in a public repository.
#
# So: one fixture per check id that MUST fail it, plus a clean tree that MUST
# pass, driven through THIS script as a subprocess; the real arg parsing, the
# real extraction, the real curation, the real checks. Testing extracted check
# bodies would test a copy of the logic, which is the same vacuity one level in.
#
# Isolation is asserted as SET EQUALITY: the set of failing check ids must
# equal the expected set exactly. "leak.paths failed" is not evidence the
# leak.paths fixture worked if three other checks failed alongside it.
# Spec: Hlin's F2 (2026-07-25), adopted as stated.
st_commit() { # $1 = repo dir; commit the current tree and (re)tag it
  # -f is load-bearing: a developer's GLOBAL gitignore commonly lists .env and
  # node_modules, which are exactly two of the fixtures. Without -f those files
  # go untracked, git archive omits them, and the leak.paths / bloat.vendored
  # cases would pass vacuously; the fixture reporting success while testing
  # nothing. That is the failure mode this whole harness exists to prevent, so
  # it must not be reintroduced by the harness itself.
  git -C "$1" add -A -f >/dev/null 2>&1
  git -C "$1" -c user.email=selftest@invalid -c user.name=selftest \
      -c commit.gpgsign=false commit -qm "fixture" >/dev/null 2>&1
  git -C "$1" tag -f st >/dev/null 2>&1
}

st_base_repo() { # $1 = repo dir; a tree that passes all 11 checks
  local r="$1"
  mkdir -p "$r/docs/design" "$r/src"
  git -C "$r" init -q >/dev/null 2>&1
  # Root file set (root.required). Prose avoids every style.lint construction.
  for f in README.md SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md TRADEMARKS.md CHANGELOG.md; do
    printf '# %s\n\nFixture content for the export gate self-test.\n' "${f%.md}" > "$r/$f"
  done
  printf 'Apache-2.0 fixture license text.\n' > "$r/LICENSE"
  printf 'gus\nhlin\n' > "$r/MAINTAINERS"
  # STYLE.md is exempt by design (it names the banned constructions to ban them).
  printf '# STYLE\n\nBanned: em dash, exclamation, Moreover, Furthermore, delve.\n' > "$r/STYLE.md"
  # A design doc in the real naming convention: source carries the version,
  # the export drops it via a map. refs.closure depends on exactly this shape.
  printf '# Spec\n\nPublic edition fixture. No private citations.\n' \
    > "$r/docs/design/Spec - v01 - 260101.md"
  printf '// SPDX-License-Identifier: Apache-2.0\npub fn f() {}\n' > "$r/src/lib.rs"
  # A miniature of the REAL hold-back shape: a workspace whose `server` member is
  # never exported. The transform must drop the member and prune the lock; the
  # server fixture deliberately lacks an SPDX header to prove held-back code
  # cannot trip an exported-tree check.
  mkdir -p "$r/app/src" "$r/server/src"
  printf '[workspace]\nresolver = "2"\nmembers = ["app", "server"]\n' > "$r/Cargo.toml"
  printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n' > "$r/app/Cargo.toml"
  printf '// SPDX-License-Identifier: Apache-2.0\npub fn a() {}\n' > "$r/app/src/lib.rs"
  printf '[package]\nname = "server"\nversion = "0.1.0"\nedition = "2021"\n' > "$r/server/Cargo.toml"
  printf 'pub fn s() {}\n' > "$r/server/src/lib.rs"
  cat > "$r/Cargo.lock" <<'LOCK'
version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "server"
version = "0.1.0"
LOCK
  st_commit "$r"
}

st_base_allowlist() { # $1 = allowlist path
  cat > "$1" <<'ALLOW'
README.md
LICENSE
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
TRADEMARKS.md
STYLE.md
MAINTAINERS
CHANGELOG.md
Cargo.toml
Cargo.lock
src/lib.rs
app
docs/design/Spec - v01 - 260101.md => docs/design/Spec.md
ALLOW
  printf '# fixture waiver baseline (empty)\n' > "$(dirname "$1")/leak-waivers.txt"
}

st_fail=0 st_pass=0
st_case() { # $1 name, $2 expected verdict, $3 expected-failing ids (space-sep, "" = none), $4 mutator fn
  local name="$1" want_verdict="$2" want_fail="$3" mutate="$4"
  local d r al out log got_verdict got_fail rc
  d=$(mktemp -d "${TMPDIR:-/tmp}/st.XXXXXX") || return 1
  r="$d/repo"; al="$d/al/export-allowlist.txt"; out="$d/out"; log="$d/log"
  mkdir -p "$r" "$d/al"
  st_base_repo "$r"; st_base_allowlist "$al"
  "$mutate" "$r" "$al"
  st_commit "$r"
  ( SIGNET_REPO="$r" "$ST_SELF" --tag st --out "$out" --repo "$r" --allowlist "$al" ) >"$log" 2>&1
  rc=$?
  if [ ! -f "$out/.export-verdict.json" ]; then
    echo "SELF-TEST FAIL  $name: no verdict written (tool exit $rc)" >&2
    sed 's/^/      /' "$log" >&2; st_fail=$((st_fail+1)); rm -rf "$d"; return 1
  fi
  got_verdict=$(sed -n 's/.*"verdict": "\([A-Z-]*\)".*/\1/p' "$out/.export-verdict.json")
  # Match the id/result PAIR intact. An earlier version split the record on
  # commas first, which severed "id" from "result" so the pattern could never
  # match and every case reported "no failing checks". The verdicts were right
  # the whole time; the assertion was blind. Had this harness asserted only on
  # the verdict, all 16 cases would have reported green while testing nothing;
  # the exact fail-open shape the harness exists to detect, reproduced inside
  # the harness on its first run. Keep the pair matched.
  got_fail=$(grep -o '"id":"[a-z.]*","result":"fail"' "$out/.export-verdict.json" \
    | sed 's/.*"id":"\([a-z.]*\)".*/\1/' | sort | tr '\n' ' ')
  got_fail="${got_fail% }"
  want_fail=$(echo "$want_fail" | tr ' ' '\n' | sort | tr '\n' ' '); want_fail="${want_fail% }"
  if [ "$got_verdict" = "$want_verdict" ] && [ "$got_fail" = "$want_fail" ]; then
    ST_LOG="$log"; ST_OUT="$out"; ST_DIR="$d"
    st_pass=$((st_pass+1)); echo "  ok    $name  ($got_verdict; failing: ${got_fail:-none})" >&2
    return 0
  fi
  echo "SELF-TEST FAIL  $name" >&2
  echo "      verdict: want $want_verdict got $got_verdict" >&2
  echo "      failing: want [${want_fail:-none}] got [${got_fail:-none}]" >&2
  st_fail=$((st_fail+1)); rm -rf "$d"; return 1
}

st_noop() { :; }
st_env()       { printf 'SECRET=x\n' > "$1/.env"; echo '.env' >> "$2"; }
st_secret()    { mkdir -p "$1/conf"; printf 'key = %s\n' "$AWS_EX_KEY" > "$1/conf/c.txt"; echo 'conf/c.txt' >> "$2"; }
st_host_stg()  { mkdir -p "$1/conf"; printf 'host: staging.example.com\n' > "$1/conf/h.txt"; echo 'conf/h.txt' >> "$2"; }
st_host_port() { mkdir -p "$1/conf"; printf 'addr: service.local:8443\n' > "$1/conf/h.txt"; echo 'conf/h.txt' >> "$2"; }
st_host_1918() { mkdir -p "$1/conf"; printf 'peer 10.0.0.5\n' > "$1/conf/h.txt"; echo 'conf/h.txt' >> "$2"; }
st_host_infra(){ mkdir -p "$1/conf"; printf 'box %s\n' "$INFRA_IP" > "$1/conf/h.txt"; echo 'conf/h.txt' >> "$2"; }
st_substrate_v(){ mkdir -p "$1/conf"; printf 'built with %s\n' "cla""ude" > "$1/conf/n.txt"; echo 'conf/n.txt' >> "$2"; }
st_substrate_m(){ mkdir -p "$1/conf"; printf 'the %s model\n' "Op""us" > "$1/conf/n.txt"; echo 'conf/n.txt' >> "$2"; }
st_substrate_p(){ mkdir -p "$1/conf"; printf 'out=/tmp/x/-Users-%s-h/s\n' "chrisracz""kowski" > "$1/conf/n.txt"; echo 'conf/n.txt' >> "$2"; }
st_map_survives() { # S202: an exclude naming a map TARGET must not eat the map's output.
  # Removes the base's direct README include; installs it via pub/ map + root exclude.
  sed -i.bak '/^README\.md$/d' "$2"; rm -f "$2.bak"
  mkdir -p "$1/pub"; printf '# README\n\nMapped fixture readme.\n' > "$1/pub/README.md"
  printf 'pub/\n? pub/README.md => README.md\n- README.md\n' >> "$2"
}
st_substrate_self() { # the self-exported allowlist may name the vendor; nothing else may
  mkdir -p "$1/infrastructure/scripts"
  printf '# exclusions\n- .%s/\n' "cla""ude" > "$1/infrastructure/scripts/export-allowlist.txt"
  echo 'infrastructure/scripts/export-allowlist.txt' >> "$2"
}
st_substrate_scoped() { # positive control: the exemption is one file, not a hole
  st_substrate_self "$1" "$2"
  mkdir -p "$1/conf"; printf 'built with %s\n' "cla""ude" > "$1/conf/n.txt"; echo 'conf/n.txt' >> "$2"
}
st_host_waived() { # a waived hit must still be REPORTED and TALLIED, never dropped
  mkdir -p "$1/conf"; printf 'peer 10.0.0.5\n' > "$1/conf/h.txt"; echo 'conf/h.txt' >> "$2"
  printf 'conf/h.txt | rfc1918 | fixture waiver, self-test\n' >> "$(dirname "$2")/leak-waivers.txt"
}
# Fix-A verification (inverted from the pre-fix fixture, which proved the '+'
# blind spot by failing here): a deliberately re-included doc is AUTHORIZED.
st_docsallow() { printf 'Re-included fixture doc.\n' > "$1/docs/design/Extraneous.md"; echo '+ docs/design/Extraneous.md' >> "$2"; }
st_lockfile()  { sed -i.bak '/^Cargo\.lock$/d' "$2"; rm -f "$2.bak"; }
st_spdx()      { printf 'pub fn g() {}\n' > "$1/src/bad.rs"; echo 'src/bad.rs' >> "$2"; }
st_vendored()  { mkdir -p "$1/web/node_modules/p"; printf 'x\n' > "$1/web/node_modules/p/i.js"; echo 'web' >> "$2"; }
st_style()     { printf '# Bad\n\nThis line has an em dash \xe2\x80\x94 which the register bans.\n' \
                   > "$1/docs/design/Bad - v01 - 260101.md"
                 echo 'docs/design/Bad - v01 - 260101.md => docs/design/Bad.md' >> "$2"; }
st_refs()      { printf '# Zzint\n\nprivate\n' > "$1/docs/design/Zzint - v01 - 260101.md"
                 printf '# Spec\n\nSee Zzint for details.\n' > "$1/docs/design/Spec - v01 - 260101.md"; }
st_rootreq()   { sed -i.bak '/^CHANGELOG\.md$/d' "$2"; rm -f "$2.bak"; }
st_copyinc()   { echo 'does/not/exist.md' >> "$2"; }
# Transform must-fail arms. verchange: bump a member version while the lock still
# records the old one; the offline prune then rewrites the pair and the subset
# check must catch the CHANGE (prune may only remove). corruptlock: a lock cargo
# cannot parse; the prune fails and --frozen must report the unresolvable tree.
st_lock_verchange() { sed -i.bak 's/^version = "0.1.0"$/version = "0.2.0"/' "$1/app/Cargo.toml"; rm -f "$1/app/Cargo.toml.bak"; }
st_lock_corrupt()   { printf 'version = 3\n\n[[package]]\nname = "app"\n' > "$1/Cargo.lock"; }

run_self_test() {
  ST_SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  command -v git >/dev/null 2>&1 || { echo "self-test: git required" >&2; return 64; }
  command -v cargo >/dev/null 2>&1 || { echo "self-test: cargo required (the workspace transform runs in every fixture)" >&2; return 64; }
  echo "signet-export self-test  (tool sha256=$SELF_SHA)" >&2
  echo "-- the clean tree MUST pass --" >&2
  st_case "clean tree"            GATE-PASS ""                  st_noop
  echo "-- each check MUST be demonstrably failable --" >&2
  st_case "leak.paths"            GATE-FAIL "leak.paths"        st_env
  st_case "leak.secrets"          GATE-FAIL "leak.secrets"      st_secret
  st_case "leak.hostnames/stg"    GATE-FAIL "leak.hostnames"    st_host_stg
  st_case "leak.hostnames/port"   GATE-FAIL "leak.hostnames"    st_host_port
  st_case "leak.hostnames/rfc1918" GATE-FAIL "leak.hostnames"   st_host_1918
  st_case "leak.hostnames/infra"  GATE-FAIL "leak.hostnames"    st_host_infra
  st_case "map-survives-exclude"  GATE-PASS ""                  st_map_survives
  st_case "substrate/self-exempt" GATE-PASS ""                  st_substrate_self
  st_case "substrate/scoped"      GATE-FAIL "leak.substrate"    st_substrate_scoped
  st_case "leak.substrate/vendor" GATE-FAIL "leak.substrate"    st_substrate_v
  st_case "leak.substrate/model"  GATE-FAIL "leak.substrate"    st_substrate_m
  st_case "leak.substrate/path"   GATE-FAIL "leak.substrate"    st_substrate_p
  # Removing Cargo.lock from a workspace export fails identity (the lock never
  # arrived from the tag) AND frozen (nothing pins resolution) — both honest.
  st_case "lockfile.identity"     GATE-FAIL "lockfile.identity lockfile.frozen" st_lockfile
  st_case "license.spdx"          GATE-FAIL "license.spdx"      st_spdx
  st_case "bloat.vendored"        GATE-FAIL "bloat.vendored"    st_vendored
  st_case "style.lint"            GATE-FAIL "style.lint"        st_style
  st_case "refs.closure"          GATE-FAIL "refs.closure"      st_refs
  st_case "root.required"         GATE-FAIL "root.required"     st_rootreq
  st_case "copy.complete"         GATE-FAIL "copy.complete"     st_copyinc
  st_case "lockfile.subset"       GATE-FAIL "lockfile.subset"   st_lock_verchange
  st_case "lockfile.frozen"       GATE-FAIL "lockfile.frozen"   st_lock_corrupt
  echo "-- docs.allowlist: guard-only in Stage-1 (Hlin B disposition, 2026-07-26) --" >&2
  echo "  INVARIANT  docs.allowlist; no reachable failure under current construction (guard only; Stage-2 carries the live check)" >&2
  if st_case "docs.allowlist/+reinclude authorized (fix A)" GATE-PASS "" st_docsallow; then
    # Pin the guard's continued EXISTENCE: the check must still run and record.
    # If a refactor deletes it, this line; not silence; is what fails.
    if grep -q '"id":"docs.allowlist","result":"pass"' "$ST_OUT/.export-verdict.json"; then
      echo "  ok    guard present: docs.allowlist still runs and records" >&2
    else
      echo "SELF-TEST FAIL  docs.allowlist guard has been removed from the gate" >&2
      st_fail=$((st_fail+1)); st_pass=$((st_pass-1))
    fi
    rm -rf "$ST_DIR"
  fi
  echo "-- a WAIVED hit passes the gate but must still be reported and tallied --" >&2
  if st_case "leak.hostnames/waived" GATE-PASS "" st_host_waived; then
    if grep -q "WAIVED conf/h.txt (rfc1918" "$ST_LOG" && grep -q "1 waived hit(s)" "$ST_LOG"; then
      echo "  ok    waived hit reported and tallied" >&2
    else
      echo "SELF-TEST FAIL  waived hit was silently dropped (pass without disclosure)" >&2
      st_fail=$((st_fail+1)); st_pass=$((st_pass-1))
    fi
    rm -rf "$ST_DIR"
  fi
  echo "-- an UNMATCHED optional is reported loudly, tallied, and does NOT gate --" >&2
  # The 0.2.0 defect: this exact case ran green with the warning dying as
  # command-not-found. The arm asserts all three properties, because each has
  # its own failure: silence (the defect) · a missing tally (a claim without
  # its count) · a flipped verdict (optionals wrongly gating).
  st_optmiss() { printf '? no/such/optional-file\n' >> "$2"; }
  if st_case "optional-unmatched/loud" GATE-PASS "" st_optmiss; then
    if grep -q "optional-unmatched: no/such/optional-file" "$ST_LOG" \
       && grep -q "optional_unmatched=1" "$ST_LOG"; then
      echo "  ok    unmatched optional reported, tallied, and did not gate" >&2
    else
      echo "SELF-TEST FAIL  unmatched optional vanished inside a green run (the 0.2.0 defect)" >&2
      st_fail=$((st_fail+1)); st_pass=$((st_pass-1))
    fi
    rm -rf "$ST_DIR"
  fi
  echo "-- a MATCHED optional stays SILENT (a warning that always fires carries no information) --" >&2
  st_optmatch() { printf 'Optional note fixture content.\n' > "$1/OPTNOTE.md"; printf '? OPTNOTE.md\n' >> "$2"; }
  if st_case "optional-matched/silent" GATE-PASS "" st_optmatch; then
    if ! grep -q "optional-unmatched:" "$ST_LOG" && grep -q "optional_unmatched=0" "$ST_LOG"; then
      echo "  ok    matched optional copied silently (count 0, no warning line)" >&2
    else
      echo "SELF-TEST FAIL  a PRESENT optional produced a warning — the constant-signal failure (D-15 class)" >&2
      st_fail=$((st_fail+1)); st_pass=$((st_pass-1))
    fi
    rm -rf "$ST_DIR"
  fi
  echo "self-test: $st_pass passed, $st_fail failed" >&2
  [ "$st_fail" -eq 0 ] || return 1
  return 0
}

if $SELF_TEST; then run_self_test; exit $?; fi
[ -n "$TAG" ] || { echo "signet-export: --tag is required" >&2; exit 64; }
[ -n "$OUT" ] || { echo "signet-export: --out is required" >&2; exit 64; }
[ -f "$ALLOWLIST" ] || { echo "signet-export: allowlist not found: $ALLOWLIST" >&2; exit 64; }
git -C "$REPO" rev-parse --verify --quiet "$TAG^{commit}" >/dev/null \
  || { echo "signet-export: tag/commit not found in $REPO: $TAG" >&2; exit 64; }
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "signet-export: --out exists and is not empty: $OUT" >&2; exit 64
fi
mkdir -p "$OUT" || { echo "signet-export: cannot create $OUT" >&2; exit 64; }

COMMIT=$(git -C "$REPO" rev-parse "$TAG^{commit}")
ALLOW_SHA=$(shasum -a 256 "$ALLOWLIST" | awk '{print $1}')
echo "signet-export $VERSION  sha256=$SELF_SHA" >&2
echo "input: $TAG ($COMMIT)  allowlist: $ALLOW_SHA" >&2

# ---- extract the tag (tracked content only, working tree untouched) --------
WORK=$(mktemp -d "${TMPDIR:-/tmp}/signet-export.XXXXXX") || exit 64
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/src"
mkdir -p "$SRC"
git -C "$REPO" archive "$COMMIT" | tar -x -C "$SRC" || { echo "signet-export: git archive failed" >&2; exit 64; }

# ---- parse allowlist -------------------------------------------------------
INCLUDES="$WORK/includes"; OPTIONALS="$WORK/optionals"; EXCLUDES="$WORK/excludes"; MAPS="$WORK/maps"; REINCLUDES="$WORK/reincludes"
: > "$INCLUDES"; : > "$OPTIONALS"; : > "$EXCLUDES"; : > "$MAPS"; : > "$REINCLUDES"
while IFS= read -r raw; do
  line="${raw%%#*}"; line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -n "$line" ] || continue
  case "$line" in
    "- "*) echo "${line#- }" >> "$EXCLUDES" ;;
    "+ "*) echo "${line#+ }" >> "$REINCLUDES" ;;
    "? "*" => "*) rest="${line#? }"; echo "$rest" >> "$MAPS"; echo "OPT ${rest%% => *}" >> "$OPTIONALS" ;;
    "? "*) echo "${line#? }" >> "$OPTIONALS" ;;
    *" => "*) echo "$line" >> "$MAPS"; echo "${line%% => *}" >> "$INCLUDES" ;;
    *) echo "$line" >> "$INCLUDES" ;;
  esac
done < "$ALLOWLIST"

copy_path() { # $1 = source path (relative), $2 = dest path (relative)
  local s="$SRC/$1" d="$OUT/$2"
  if [ -d "$s" ]; then
    mkdir -p "$d"
    (cd "$s" && find . -type f | sed 's|^\./||') | while IFS= read -r f; do
      mkdir -p "$d/$(dirname "$f")"; cp "$s/$f" "$d/$f"
    done
  elif [ -f "$s" ]; then
    mkdir -p "$(dirname "$d")"; cp "$s" "$d"
  else
    return 1
  fi
}

MISSING_REQ="$WORK/missing_required"; : > "$MISSING_REQ"
while IFS= read -r p; do
  p="${p%/}"
  copy_path "$p" "$p" || echo "$p" >> "$MISSING_REQ"
done < "$INCLUDES"
# ⚠ UNMATCHED OPTIONALS ARE NAMED, never silent (S202): '?' entries no-op when
# their source is absent, which twice hid RATIFIED content missing from the tree
# (7 files, then 10 more — nothing else can see an absence nothing references).
# Informational, not a check: the operator reads the list; ratified-content
# absence is a content question, not a gate verdict.
while IFS= read -r p; do
  case "$p" in OPT\ *) p="${p#OPT }";; esac
  p="${p%/}"
  copy_path "$p" "$p" 2>/dev/null || warn_opt "$p"
done < "$OPTIONALS"
# ⛔⛔ EXCLUDES RUN BEFORE MAPS (S202 fix, Gus). The original order — maps then
# excludes — let an exclude naming a map's TARGET destroy the map's output after
# installing it. MEASURED, three instances: '- README.md' deleted the mapped
# public README (root.required could never pass), and the two test-vectors
# README maps were eaten SILENTLY — nothing guards non-root mapped files.
# Excludes name SOURCE-form paths (verified: no exclude covers any map source),
# so filtering the copied set FIRST and installing finals SECOND preserves every
# exclude's intent and fixes all three. The st_map_survives arm is the mutation
# evidence: revert this order and it fails.
while IFS= read -r x; do
  x="${x%/}"; rm -rf "${OUT:?}/$x" 2>/dev/null || true
done < "$EXCLUDES"
while IFS= read -r m; do
  s="${m%% => *}"; d="${m##* => }"
  if [ -e "$OUT/$s" ]; then mkdir -p "$OUT/$(dirname "$d")"; mv "$OUT/$s" "$OUT/$d"; fi
done < "$MAPS"
# Re-includes ('+'): live-config FILES that survive the belt-and-braces excludes.
# Publishing THE config we run, not a staged copy (a map would drift into a false
# claim about our posture). FILES ONLY, enforced: a '+' directory would silently
# republish everything its exclude exists to hold back; hard error, not warning.
while IFS= read -r p; do
  if [ "${p%/}" != "$p" ] || [ -d "$SRC/$p" ]; then
    echo "signet-export: '+ $p' names a directory; '+' accepts exact file paths only" >&2
    exit 64
  fi
  copy_path "$p" "$p" || echo "$p" >> "$MISSING_REQ"
done < "$REINCLUDES"
find "$OUT" -name ".DS_Store" -delete 2>/dev/null
find "$OUT" -type d -empty -delete 2>/dev/null

# ---- workspace transform ----------------------------------------------------
# server/ (and migrations/) are held back, but the tag's Cargo.toml names server
# as a workspace member and the tag's Cargo.lock resolves its whole dependency
# tree. As curated, the public tree hard-fails every cargo command. So the
# export applies two DECLARED transforms (design tested 2026-08-19, punch-list
# §3a: 483 -> 282 pairs, zero version changes, --frozen passes):
#   T1: drop from `members` every member whose directory is absent from the
#       export (derived at export time; no drifting hand-kept manifest copy).
#   T2: prune the lock by resolving OFFLINE — the network is unreachable by
#       construction, so pruning can remove pairs but never add or change one.
# Checks 12/13 then hold the RESULT to "pure (name,version) subset of the tag's
# lock" + "cargo metadata --frozen passes". The transform without its checks
# would be an unaudited rewrite of a supply-chain artifact; they ship together.
TRANSFORMED=false
PRE_PRUNE_LOCK=false
if [ -f "$OUT/Cargo.toml" ] && grep -q '^\[workspace\]' "$OUT/Cargo.toml"; then
  command -v cargo >/dev/null 2>&1 \
    || { echo "signet-export: cargo is required for the workspace transform" >&2; exit 64; }
  TRANSFORMED=true
  [ -f "$OUT/Cargo.lock" ] && PRE_PRUNE_LOCK=true
  # T1 — scoped to the members array: an inline entry is spliced out of the
  # `members = [...]` line; a one-per-line entry has its line deleted. Never a
  # bare global substitution: the member name may legitimately appear elsewhere
  # in the manifest (a path dependency, a comment).
  while IFS= read -r m; do
    [ -n "$m" ] || continue
    if [ ! -d "$OUT/$m" ]; then
      sed -E -i.bak \
        -e "/^[[:space:]]*members[[:space:]]*=/ s/\"$m\"[[:space:]]*,[[:space:]]*//g" \
        -e "/^[[:space:]]*members[[:space:]]*=/ s/,[[:space:]]*\"$m\"//g" \
        -e "/^[[:space:]]*\"$m\",?[[:space:]]*$/d" \
        "$OUT/Cargo.toml"
      rm -f "$OUT/Cargo.toml.bak"
      echo "transform: dropped absent workspace member '$m' from Cargo.toml" >&2
    fi
  done < <(sed -n '/^[[:space:]]*members[[:space:]]*=/,/\]/p' "$OUT/Cargo.toml" \
           | grep -o '"[^"]*"' | tr -d '"')
  # T2 — the offline prune. Refused when the tag's lock never reached the
  # export: pruning means subsetting an existing lock, and generating a fresh
  # one here would let a missing lock ship silently (lockfile.identity owns
  # that failure). A failed prune is not fatal here — lockfile.frozen reports
  # the unresolvable tree as a gate failure, which is the honest verdict class.
  if $PRE_PRUNE_LOCK; then
    if ! (cd "$OUT" && cargo metadata --format-version 1 --offline \
          >/dev/null 2>"$WORK/prune.err"); then
      echo "transform: offline lock prune FAILED (lockfile.frozen will report)" >&2
      sed 's/^/  prune: /' "$WORK/prune.err" >&2 | head -5
    fi
  else
    echo "transform: no Cargo.lock in export; prune refused (lockfile.identity reports)" >&2
  fi
fi

# ---- Stage-1 checks --------------------------------------------------------
CHECKS="$WORK/checks.jsonl"; : > "$CHECKS"
FAILED=false
declare -a FINDINGS=()
record() { # $1 id, $2 result, $3 detail-count
  echo "{\"id\":\"$1\",\"result\":\"$2\",\"findings\":${3:-0}}" >> "$CHECKS"
  [ "$2" = "fail" ] && FAILED=true
  echo "check $1: $2 (findings: ${3:-0})" >&2
}
note() { FINDINGS+=("$1"); echo "  - $1" >&2; }

# 1. leak.paths; forbidden path patterns in the export
n=0
while IFS= read -r hit; do n=$((n+1)); note "leak.paths: $hit"; done < <(
  cd "$OUT" && find . \( -name ".env*" -o -name "docker-compose*" -o -name "*.pem" \
    -o -name "*.key" -o -name "id_rsa*" \) -print 2>/dev/null | sed 's|^\./||'
  cd "$OUT" && find . -path "./infrastructure/*" -type f 2>/dev/null | sed 's|^\./||' \
    | grep -v -e "^infrastructure/scripts/build-signet-release.sh$" -e "^infrastructure/scripts/linux-gate.sh$" \
              -e "^infrastructure/scripts/signet-export.sh$" -e "^infrastructure/scripts/export-allowlist.txt$"
)
record leak.paths "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 1b. leak.substrate; substrate/vendor names + local-environment identifiers in
# CONTENT (Chris's ruling 2026-08-10). Content-free reporting: path + pattern
# class only, never the matched text. Covers the flattened tmp-path encoding
# (-Users-...-) that the slashed-path checks cannot see.
n=0
while IFS= read -r hit; do n=$((n+1)); note "leak.substrate: $hit"; done < <(
  { cd "$OUT" && grep -rliE "$SUB_CI|$SUB_ENV" . 2>/dev/null | sed 's|^\./||' | sed 's/$/ (vendor-or-env)/'
    cd "$OUT" && grep -rlE  "$SUB_CS" . 2>/dev/null | sed 's|^\./||' | sed 's/$/ (model-name)/'
  } | sort -u \
    | grep -v '^infrastructure/scripts/export-allowlist\.txt ' || true
  # ⛔ SELF-EXEMPTION, exactly one file (S202, Gus): the DISCLOSED exclusion list
  # must name what it excludes; scanning it for the names it exists to exclude is
  # the instrument reading its own configuration. Scoped to this path and this
  # check only — the st_substrate_self/st_substrate_scoped arms prove the
  # exemption admits the allowlist and NOTHING else.
)
record leak.substrate "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 2. leak.secrets; credential-shaped content (content-free reporting: path only)
n=0
while IFS= read -r hit; do n=$((n+1)); note "leak.secrets: $hit"; done < <(
  grep -rlE -- "-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}" \
    "$OUT" 2>/dev/null | sed "s|^$OUT/||"
)
record leak.secrets "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 3. leak.hostnames; internal/staging host references in the export.
# Per-class scan against the DISCLOSED waiver baseline (leak-waivers.txt beside
# this allowlist; exported to verify/leak-waivers.txt). An entry names
# path | class | rationale and suppresses exactly that class in exactly that
# file; waived hits are still reported and tallied separately, so "pass" means
# "pass against the published baseline", never "pass modulo hidden ignores".
WAIVERS_FILE="$(cd "$(dirname "$ALLOWLIST")" && pwd)/leak-waivers.txt"
is_waived() { # $1 = relative path, $2 = class
  [ -f "$WAIVERS_FILE" ] || return 1
  awk -F'|' -v p="$1" -v c="$2" '
    /^[[:space:]]*(#|$)/ {next}
    { gsub(/^[[:space:]]+|[[:space:]]+$/,"",$1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2) }
    $1==p && $2==c {found=1} END{exit !found}' "$WAIVERS_FILE"
}
n=0; W=0
scan_hostclass() { # $1 = class, $2 = ERE pattern
  while IFS= read -r f; do
    if is_waived "$f" "$1"; then
      W=$((W+1)); note "leak.hostnames: WAIVED $f ($1; see leak-waivers.txt)"
    else
      n=$((n+1)); note "leak.hostnames: $f ($1)"
    fi
  done < <(grep -rlE "$2" "$OUT" 2>/dev/null | sed "s|^$OUT/||")
}
scan_hostclass staging-host 'staging\.[a-z]+\.[a-z]+'
scan_hostclass local-port '\.local:[0-9]+'
scan_hostclass rfc1918 '\b10\.[0-9]+\.[0-9]+\.[0-9]+|\b192\.168\.[0-9]+\.[0-9]+|\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+'
# infra-ip: OUR infrastructure's routable addresses, maintained as an explicit
# list. A generic bare-IPv4 rule was built and MEASURED here (2026-07-25): six
# FP files on the v0.5.15 tree; X.509 OIDs, RFC section refs, version quads;
# for zero marginal true catches; context-free text cannot discriminate an OID
# from an address. Add production IPs at provisioning as further constructed
# variables beside INFRA_IP at the top of this file.
scan_hostclass infra-ip "$INFRA_IP_RE"
[ $W -gt 0 ] && note "leak.hostnames: $W waived hit(s) against the published baseline"
record leak.hostnames "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 4. docs.allowlist; no doc under docs/ that the allowlist did not place.
# GUARD-ONLY in Stage-1 (Hlin's B disposition, 2026-07-26): with REINCLUDES in
# the union (fix A), everything in $OUT arrived via an allowlist mechanism by
# construction, so this check has no reachable failure HERE. It stays as a
# latent guard against a future curation restructure; and its lack of a
# positive control is reported by --self-test as an INVARIANT line, never
# hidden. Stage-2 carries the live version of this check (a public checkout
# can acquire docs the export never placed).
n=0
while IFS= read -r f; do
  ok=false
  while IFS= read -r a; do a="${a%/}"; case "$f" in "$a"|"$a"/*) ok=true; break;; esac; done \
    < <(cat "$INCLUDES" "$REINCLUDES"; sed 's/^OPT //' "$OPTIONALS"; awk -F' => ' '{print $2}' "$MAPS")
  $ok || { n=$((n+1)); note "docs.allowlist: $f"; }
done < <(cd "$OUT" && find docs -name "*.md" -type f 2>/dev/null | sed 's|^\./||')
record docs.allowlist "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 5. lockfile.identity; exported lockfiles byte-equal to the tag's.
# Cargo.lock carve-out when the workspace transform ran: byte-identity is
# IMPOSSIBLE by design there (the prune rewrites the lock), so governance moves
# to lockfile.subset + lockfile.frozen — but the lock must still have ARRIVED
# from the tag (PRE_PRUNE_LOCK); a lock the prune would have had to invent is an
# identity failure, never a silent regeneration.
n=0
for lf in Cargo.lock web/package-lock.json; do
  if [ "$lf" = "Cargo.lock" ] && $TRANSFORMED; then
    if [ -f "$SRC/$lf" ] && ! $PRE_PRUNE_LOCK; then
      n=$((n+1)); note "lockfile.identity: $lf absent from the export (tag has one)"
    else
      echo "  - lockfile.identity: Cargo.lock governed by lockfile.subset + lockfile.frozen (transform ran)" >&2
    fi
    continue
  fi
  if [ -f "$SRC/$lf" ]; then
    if [ ! -f "$OUT/$lf" ] || ! cmp -s "$SRC/$lf" "$OUT/$lf"; then n=$((n+1)); note "lockfile.identity: $lf"; fi
  fi
done
record lockfile.identity "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 6. license.spdx; source files carry SPDX headers; LICENSE present
n=0
[ -f "$OUT/LICENSE" ] || { n=$((n+1)); note "license.spdx: LICENSE missing"; }
while IFS= read -r f; do
  head -5 "$OUT/$f" | grep -q "SPDX-License-Identifier" || { n=$((n+1)); note "license.spdx: $f"; }
done < <(cd "$OUT" && find . -type f \( -name "*.rs" -o -name "*.ts" -o -name "*.svelte" \) 2>/dev/null \
         | sed 's|^\./||' | grep -v "test-vectors/" | grep -v "mlkem-wasm/")
record license.spdx "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 7. bloat.vendored; vendored dependency trees in the export
n=0
while IFS= read -r hit; do n=$((n+1)); note "bloat.vendored: $hit"; done < <(
  cd "$OUT" && find . -type d -name "node_modules" 2>/dev/null | sed 's|^\./||'
)
record bloat.vendored "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 8. style.lint; public-prose register on Markdown outside code fences.
# STYLE.md is exempt: it names the banned constructions in order to ban them.
# Inline code spans (`...`) are stripped before matching so code punctuation
# (println!, shell !) never false-positives; exclamation marks in real prose
# are flagged, matching STYLE.md's stated coverage (Hlin review, S131).
n=0
while IFS= read -r f; do
  [ "$f" = "STYLE.md" ] && continue
  bad=$(awk 'BEGIN{fence=0} /^```/{fence=!fence; next} !fence' "$OUT/$f" \
    | sed 's/`[^`]*`//g' \
    | grep -nE -- "—|!|not just [a-zA-Z]+, but|[Dd]elve|[Mm]oreover|[Ff]urthermore|worth noting" \
    | head -1)
  if [ -z "$bad" ]; then
    bad=$(awk 'BEGIN{fence=0} /^```/{fence=!fence; next} !fence' "$OUT/$f" \
      | perl -CSD -ne 'print "emoji\n" and exit if /[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]/' 2>/dev/null)
  fi
  [ -n "$bad" ] && { n=$((n+1)); note "style.lint: $f"; }
done < <(cd "$OUT" && find . -name "*.md" -type f 2>/dev/null | sed 's|^\./||')
record style.lint "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 9. refs.closure; exported docs must not cite unexported design docs
n=0
PRIVDOCS="$WORK/privdocs"; : > "$PRIVDOCS"
(cd "$SRC/docs/design" 2>/dev/null && ls *.md 2>/dev/null) | sed 's/ - v[0-9.]* - [0-9]*\.md$//' | sort -u \
  | while IFS= read -r base; do
      [ -e "$OUT/docs/design/$base.md" ] || echo "$base" >> "$PRIVDOCS"
    done
while IFS= read -r base; do
  [ -n "$base" ] || continue
  while IFS= read -r f; do
    n=$((n+1)); note "refs.closure: $f cites $base"
  done < <(grep -rl "$base" "$OUT" --include="*.md" 2>/dev/null | sed "s|^$OUT/||")
done < "$PRIVDOCS"
record refs.closure "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 10. root.required; the public root file set
n=0
for f in README.md LICENSE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md TRADEMARKS.md MAINTAINERS CHANGELOG.md; do
  [ -f "$OUT/$f" ] || { n=$((n+1)); note "root.required: $f missing"; }
done
record root.required "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 11. copy.complete; required (non-optional) allowlist entries that failed to copy
n=0
while IFS= read -r p; do [ -n "$p" ] && { n=$((n+1)); note "copy.complete: $p"; }; done < "$MISSING_REQ"
record copy.complete "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 12. lockfile.subset; the pruned Cargo.lock is a pure (name,version) subset of
# the tag's — removals only. Any pair in the export absent from the tag's lock
# is an ADDITION or a VERSION CHANGE, and an offline prune can produce neither;
# one appearing means the transform did something other than prune (measured at
# design time: 483 -> 282 pairs, zero changes). Names only in findings.
n=0
if [ -f "$OUT/Cargo.lock" ] && [ -f "$SRC/Cargo.lock" ]; then
  lock_pairs() { awk -F'"' '/^name = /{p=$2} /^version = /{if(p!=""){print p"@"$2; p=""}}' "$1" | sort; }
  while IFS= read -r extra; do
    [ -n "$extra" ] || continue
    n=$((n+1)); note "lockfile.subset: ${extra%%@*} (pair not in the tag's lock)"
  done < <(comm -13 <(lock_pairs "$SRC/Cargo.lock") <(lock_pairs "$OUT/Cargo.lock"))
fi
record lockfile.subset "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# 13. lockfile.frozen; the exported tree RESOLVES with the lock as shipped —
# --frozen forbids both the network and any lock rewrite, so a pass here means
# a public `cargo build --locked` will not stumble at resolution. This is the
# buildability column the gate never had (the empty column, drawn 2026-08-19).
n=0
if [ -f "$OUT/Cargo.toml" ] && grep -q '^\[workspace\]' "$OUT/Cargo.toml"; then
  if ! (cd "$OUT" && cargo metadata --format-version 1 --frozen \
        >/dev/null 2>"$WORK/frozen.err"); then
    n=1; note "lockfile.frozen: cargo metadata --frozen failed in the export tree"
    sed 's/^/  frozen: /' "$WORK/frozen.err" >&2 | head -3
  fi
fi
record lockfile.frozen "$([ $n -eq 0 ] && echo pass || echo fail)" $n

# ---- verdict ---------------------------------------------------------------
VERDICT=$($FAILED && echo "GATE-FAIL" || echo "GATE-PASS")
{
  echo "{"
  echo "  \"contract_version\": $CONTRACT_VERSION,"
  echo "  \"input_tag\": \"$TAG\","
  echo "  \"input_commit\": \"$COMMIT\","
  echo "  \"tool_version\": \"$VERSION\","
  echo "  \"tool_sha256\": \"$SELF_SHA\","
  echo "  \"allowlist_sha256\": \"$ALLOW_SHA\","
  echo "  \"dry_run\": $DRY_RUN,"
  echo "  \"checks\": ["
  paste -sd, - < "$CHECKS" | sed 's/^/    /'
  echo "  ],"
  echo "  \"verdict\": \"$VERDICT\""
  echo "}"
} > "$OUT/.export-verdict.json"

echo "verdict=$VERDICT tag=$TAG commit=$COMMIT tool_sha=$SELF_SHA allowlist_sha=$ALLOW_SHA dry_run=$DRY_RUN optional_unmatched=$OPT_UNMATCHED"
[ "$VERDICT" = "GATE-PASS" ] && exit 0 || exit 10
