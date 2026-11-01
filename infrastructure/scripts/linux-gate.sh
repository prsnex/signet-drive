#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PRSN EX Inc.
#
# linux-gate.sh — run the platform-independent Rust test gate inside a Linux
# container (S111 spike; the durable answer to the macOS Gatekeeper
# first-exec assessment tax, reference_syspolicyd_gatekeeper_first_exec_tax).
#
# WHY: the local full-suite gate on macOS pays a per-binary syspolicyd
# assessment (75 min observed vs CI's ~8) and the daemon periodically wedges
# outright. The authoritative gate (ci.yml) is ALREADY Linux — this script
# runs the same suites in the same-family environment locally: no Gatekeeper
# exists in a Linux container, and behavior matches CI by construction.
#
# WHAT THIS DOES NOT REPLACE: the genuinely-macOS coverage. The Secure-Enclave
# differential tests, the Swift shim, notarization, and broker/LaunchAgent
# behavior are either entitled/manual campaigns or cfg(macOS) tests — run
# those natively (they are few and small):
#     cargo test -p signet-cli keystore::secure_enclave
#
# Prereqs: the dev compose stack up on the host (Postgres :5432, MinIO :9000):
#     docker compose up -d
# ⚠ SHARED MAC (2026-10-19): another project's Postgres may hold :5432 (meridian's did,
# and every DB test then failed on ITS password, 28P01, before running). Point the gate
# at a Signet stack on other host ports instead; the defaults are unchanged:
#     SIGNET_GATE_PG_PORT=55432 SIGNET_GATE_S3_PORT=59000 infrastructure/scripts/linux-gate.sh
#
# Usage:
#     infrastructure/scripts/linux-gate.sh                 # full workspace suite
#     infrastructure/scripts/linux-gate.sh -p signet-server # pass-through cargo test args
#     infrastructure/scripts/linux-gate.sh --nextest       # CI-repro: nextest --profile ci
#     infrastructure/scripts/linux-gate.sh --clippy        # ROOTS §5.1/§5.6: clippy -D warnings,
#                                                          # BOTH feature configs, in-container
#     infrastructure/scripts/linux-gate.sh --nextest -E 'binary(lapse)'  # + nextest filters
#     infrastructure/scripts/linux-gate.sh --nextest --keep-db  # keep the test database (every
#                                                          # test run otherwise starts fresh)
#
# --nextest reproduces CI's exact scheduler (process-per-test, cross-binary
# parallelism, the ci profile's test-groups) inside the container. This is the
# ONLY sanctioned way to chase CI-only ordering failures locally: running the
# full native suite for CI repro is what stampeded syspolicyd into the
# S112-crash host starvation (reference_syspolicyd_gatekeeper_first_exec_tax).
#
# First run cold-compiles the workspace for Linux (~10-20 min on Apple
# Silicon, native arm64 — no emulation); the cargo registry and target live in
# named Docker volumes, so later runs are incremental.
#
# FRESHNESS (bug135): the container clock can drift AHEAD of host file mtimes
# (Docker Desktop VM drift after host sleep; +197s measured S160), after which
# cargo silently runs a STALE test binary and reports green — the staleness is
# persistent, not a transient window. The counter is two-sided:
#   PREVENT — container-freshness.sh runs as an in-container preamble before
#     cargo: it measures the skew, normalizes future-stamped artifacts, and
#     touches exactly the files edited in the at-risk band (see that script
#     for the reasoning; it is the single home for it).
#   DETECT — for targeted `--test <name>` runs, the executed-test count is
#     asserted EQUAL to the `#[test]`/`#[tokio::test]` count in the named
#     file(s). A stale binary shows up as a missing test, loudly, whatever
#     caused the staleness. (Full-workspace runs carry no assertion: the
#     cfg(macos)-gated native slice legitimately does not run here. Nextest
#     `-E` filters are not parsed; the assertion covers cargo-test mode.)
#     Escape hatch for a legitimate mismatch (e.g. macro-generated tests
#     someday): --allow-count-mismatch — same default-refuse design as C1's
#     --allow-empty.

set -euo pipefail

# The SAME digest-pinned image as crypto-wasm/build-web-pkg.sh (bump together
# with rust-toolchain.toml). Multi-arch manifest: on an Apple Silicon host the
# arm64 variant runs natively.
RUST_IMAGE="rust@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc"

# A thin derived image adding aws-lc-sys's build deps (cmake; the base image
# already carries gcc + perl) and cargo-nextest for the --nextest CI-repro
# mode (prebuilt binary, version-pinned to the host install — bump together).
# Rebuilt when the base digest or the tag suffix changes.
NEXTEST_VERSION="0.9.140"
GATE_IMAGE="signet-linux-gate:5e2214abe154-n1"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# --- C1 (S140): the 0-tests guard + its positive control ---------------------
# A filter/target that executes ZERO tests looks green (a wall of "0 passed") while
# proving nothing — the trap that nearly landed a bad commit at S140 (`-p signet-cli
# capacity` matched nothing without `--lib`). count_executed sums the tests actually
# run across the whole output (cargo-test AND nextest formats), reading stdin. Factored
# out so it is testable OFFLINE — a check that cannot fail is theater.
count_executed() {
  # strip ANSI (CARGO_TERM_COLOR=always) first, then sum executed counts
  sed $'s/\033\\[[0-9;]*m//g' | awk '
    # cargo: "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 147 filtered out"
    /test result:/ {
      for (i = 2; i <= NF; i++) {
        if ($i ~ /^passed;?$/ || $i ~ /^failed;?$/ || $i ~ /^ignored;?$/) e += $(i-1) + 0
      }
    }
    # nextest: "Summary [   1.2s] 42 tests run: 42 passed, 0 skipped"
    /Summary \[.*\].*tests? run/ {
      for (i = 2; i <= NF; i++) if (($i == "tests" || $i == "test") && $(i+1) ~ /^run/) e += $(i-1) + 0
    }
    END { print e + 0 }
  '
}

# --- bug135 DETECT: the targeted-run test-count assertion --------------------
# count_test_fns_in <file> — the static count of test-attribute lines. The
# three shapes in the tree (S161 survey): #[test], #[tokio::test],
# #[tokio::test(flavor = ...)]. tests/ dirs carry ZERO cfg gates and
# common/mod.rs is helpers-only (0 tests), so for a `--test <name>` run the
# executed count should EQUAL this. Factored out so it is testable offline.
count_test_fns_in() {
  grep -cE '^[[:space:]]*#\[(tokio::)?test(\]|\()' "$1" || true
}

# extract_test_targets <args...> — echo each NAME passed via `--test NAME` or
# `--test=NAME`. Factored out so it is testable offline.
extract_test_targets() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --test)   [ $# -ge 2 ] && printf '%s\n' "$2"; shift 2 ;;
      --test=*) printf '%s\n' "${1#--test=}"; shift ;;
      *)        shift ;;
    esac
  done
}

# fresh_db_planned <clippy_mode 0|1> <keep_db 0|1> — does this run start from a
# fresh database? Every test run does (CI starts fresh), unless --keep-db asks to
# debug a state; a lint run touches no database. Factored out for the self-test.
fresh_db_planned() {
  [ "$1" = "0" ] && [ "$2" = "0" ]
}

self_test() {
  local fails=0 n
  n="$(printf 'running 5 tests\ntest result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 147 filtered out\n' | count_executed)"
  [ "$n" = "5" ] && echo "PASS  count_executed: cargo 5 passed → 5" || { echo "FAIL  cargo count='$n' (want 5)"; fails=$((fails+1)); }
  n="$(printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 56 filtered out\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 212 filtered out\n' | count_executed)"
  [ "$n" = "0" ] && echo "PASS  count_executed: the C1 zero-match case → 0 (guard fires)" || { echo "FAIL  zero-match count='$n' (want 0)"; fails=$((fails+1)); }
  n="$(printf 'test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\ntest result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n' | count_executed)"
  [ "$n" = "7" ] && echo "PASS  count_executed: sums across binaries (3+1 + 2+1 = 7)" || { echo "FAIL  multi-binary sum='$n' (want 7)"; fails=$((fails+1)); }
  n="$(printf 'Summary [   1.2s] 42 tests run: 42 passed, 0 skipped\n' | count_executed)"
  [ "$n" = "42" ] && echo "PASS  count_executed: nextest 42 tests run → 42" || { echo "FAIL  nextest count='$n' (want 42)"; fails=$((fails+1)); }
  # bug135 DETECT self-tests
  local tf; tf="$(mktemp)"
  cat > "$tf" <<'RS'
#[test]
fn a() {}
#[tokio::test]
async fn b() {}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c() {}
    #[tokio::test]
    async fn indented() {}
// #[test]  — commented out, must NOT count
fn not_a_test() {}
RS
  n="$(count_test_fns_in "$tf")"; rm -f "$tf"
  [ "$n" = "4" ] && echo "PASS  count_test_fns_in: 3 shapes + indented, comment excluded → 4" || { echo "FAIL  count_test_fns_in='$n' (want 4)"; fails=$((fails+1)); }
  n="$(extract_test_targets cargo test --workspace -p signet-server --test folders --test shares -- --test-threads 4 | tr '\n' ' ')"
  [ "$n" = "folders shares " ] && echo "PASS  extract_test_targets: two --test names, --test-threads ignored" || { echo "FAIL  extract_test_targets='$n' (want 'folders shares ')"; fails=$((fails+1)); }
  n="$(extract_test_targets cargo test --test=quota | tr '\n' ' ')"
  [ "$n" = "quota " ] && echo "PASS  extract_test_targets: --test=NAME form" || { echo "FAIL  --test= form='$n' (want 'quota ')"; fails=$((fails+1)); }
  # Gus's proposal (2026-10-31): the gate starts each test run from a fresh database.
  fresh_db_planned 0 0 && echo "PASS  fresh_db_planned: a test run starts fresh" || { echo "FAIL  a test run would keep a stale database"; fails=$((fails+1)); }
  fresh_db_planned 0 1 && { echo "FAIL  --keep-db would still reset the database"; fails=$((fails+1)); } || echo "PASS  fresh_db_planned: --keep-db keeps it"
  fresh_db_planned 1 0 && { echo "FAIL  --clippy would touch the database"; fails=$((fails+1)); } || echo "PASS  fresh_db_planned: --clippy touches no database"
  n="$(extract_test_targets cargo test --workspace -p signet-server | tr '\n' ' ')"
  [ "$n" = "" ] && echo "PASS  extract_test_targets: no --test → empty (assertion skipped)" || { echo "FAIL  no-target case='$n' (want empty)"; fails=$((fails+1)); }

  # ⭐ VERDICT-LINE controls (bug197, S178). A verdict that only ever prints PASS is
  # theatre — the case that matters is the RED one, because that is the case an
  # operator misreads. Driven through a real non-zero exit path that needs no Docker:
  # `--clippy` with extra args refuses with exit 2. This asserts BOTH that the trap
  # fires on a non-happy path AND that the code it reports is the true one.
  local _self="${BASH_SOURCE[0]}" _out
  _out="$(bash "$_self" --clippy unexpected-arg 2>&1 || true)"
  if printf '%s' "$_out" | grep -q "LINUX-GATE VERDICT: FAIL (exit 2)"; then
    echo "PASS  verdict line: a refusing path reports FAIL + its TRUE code (exit 2)"
  else
    echo "FAIL  verdict line missing/wrong on the exit-2 path; got: $(printf '%s' "$_out" | tail -2 | tr '\n' ' ')"
    fails=$((fails+1))
  fi
  # And it must be the LAST line, or `| tail -N` — the exact call-site shape that
  # caused this — would still hide it.
  if [ "$(printf '%s' "$_out" | grep -c .)" -gt 0 ] && \
     printf '%s' "$_out" | grep -v '^[[:space:]]*$' | tail -1 | grep -q "LINUX-GATE VERDICT:"; then
    echo "PASS  verdict line: emitted LAST, so it survives a piped tail"
  else
    echo "FAIL  verdict line is not the last non-blank line — a piped tail would hide it"
    fails=$((fails+1))
  fi
  # TEST-SERVICE PORTS (2026-10-19, Bob's review): unset ⇒ the default; a valid value ⇒
  # itself; empty, non-numeric or out of range ⇒ REFUSED with exit 2 before any work.
  # Driven through the real script on `--clippy`, which a refused port stops before Docker.
  n="$( (unset SIGNET_GATE_PG_PORT; _gate_port SIGNET_GATE_PG_PORT 5432) )"
  [ "$n" = "5432" ] && echo "PASS  ports: unset ⇒ the default 5432" || { echo "FAIL  ports: unset gave '$n' (want 5432)"; fails=$((fails+1)); }
  n="$(SIGNET_GATE_PG_PORT=55432 _gate_port SIGNET_GATE_PG_PORT 5432)"
  [ "$n" = "55432" ] && echo "PASS  ports: 55432 ⇒ 55432" || { echo "FAIL  ports: 55432 gave '$n'"; fails=$((fails+1)); }
  for _bad in "" "abc" "70000"; do
    _out="$(SIGNET_GATE_PG_PORT="$_bad" bash "$_self" --clippy 2>&1 || true)"
    if printf '%s' "$_out" | grep -qF "REFUSING — SIGNET_GATE_PG_PORT='$_bad'" && \
       printf '%s' "$_out" | grep -q "LINUX-GATE VERDICT: FAIL (exit 2)"; then
      echo "PASS  ports: SIGNET_GATE_PG_PORT='$_bad' refused, exit 2 (never the 5432 fallback)"
    else
      echo "FAIL  ports: SIGNET_GATE_PG_PORT='$_bad' was not refused; got: $(printf '%s' "$_out" | tail -2 | tr '\n' ' ')"
      fails=$((fails+1))
    fi
  done
  echo "---"
  if [ "$fails" -eq 0 ]; then echo "self-test: ALL PASS"; return 0; else echo "self-test: $fails FAIL"; return 1; fi
}

# ⚠⚠ THE VERDICT LINE (bug197 retrospective, S178) — machinery for ROOTS §B-5.3.
#
# The rule says: judge the gate by CONTENT, never a piped exit code. It has now
# failed in three consecutive sessions (S176, S177, S178 ×3 in one evening) and the
# failure is always at the CALL SITE, never here — this script already preserves its
# own status correctly (`${PIPESTATUS[0]}` at the docker run, `exit "$_rc"` at the
# end). What breaks is an operator writing `linux-gate.sh --nextest | tail -30`,
# which hands them `tail`'s status and truncates the evidence. At S178 that combination
# produced a confident "GATE EXIT: 0" for a run whose result had not been read, and
# separately a "GATE EXIT: 1" for a gate that never executed at all (a `grep -c`
# returning 0 had broken the `&&` chain).
#
# ⭐ The fix is not more prose telling people not to pipe — three sessions of that
# have failed. It is to make the exit status ITSELF content, printed LAST so it
# survives `| tail -N`, and emitted from an EXIT trap so no exit path can skip it
# (this script has four: 3, 4, 5, and $_rc). Every existing invocation inherits it
# with no change at the call site. (Gus, S178: "a gate wrapper that captures the exit
# status before anything downstream touches the stream — every ad-hoc invocation
# inherits it"; the delivery was wrong, not the discipline.)
_gate_verdict() {
  local _vrc=$?
  local _word; [ "$_vrc" -eq 0 ] && _word=PASS || _word=FAIL
  printf '\n=== LINUX-GATE VERDICT: %s (exit %d) ===\n' "$_word" "$_vrc"
  return "$_vrc"
}
trap _gate_verdict EXIT

# ⛔ TEST-SERVICE PORTS (2026-10-19, Bob's review). The default applies ONLY when the
# variable is UNSET. An empty or non-numeric value is REFUSED, never read as the default:
# on this shared Mac :5432 may be another project's Postgres (meridian's was), and a
# silent fallback would point the suite at it. Validated before any work, so a bad
# value fails loud even under --clippy.
_gate_port() {  # <variable name> <default> → prints the port, or refuses (rc 1)
  local _name="$1" _def="$2" _val
  if ! declare -p "$_name" >/dev/null 2>&1; then printf '%s\n' "$_def"; return 0; fi
  eval "_val=\"\${$_name}\""
  if [[ "$_val" =~ ^[0-9]{1,5}$ ]] && [ "$_val" -ge 1 ] && [ "$_val" -le 65535 ]; then
    printf '%s\n' "$_val"; return 0
  fi
  echo "linux-gate: REFUSING — $_name='$_val' is not a port (1-65535); unset it to use the default $_def" >&2
  return 1
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi

GATE_PG_PORT="$(_gate_port SIGNET_GATE_PG_PORT 5432)" || exit 2
GATE_S3_PORT="$(_gate_port SIGNET_GATE_S3_PORT 9000)" || exit 2

# --allow-empty (C1) is the deliberate escape for a genuinely-empty run (e.g. a crate
# with no tests) — same design as the CI gate's 6/7-vs-8 override: default-refuse, with
# an explicit opt-out. --allow-count-mismatch (bug135) is the same design for the
# targeted-run count assertion. Extracted from anywhere in the args.
ALLOW_EMPTY=0; ALLOW_COUNT_MISMATCH=0; KEEP_DB=0; _kept=()
for _a in "$@"; do case "$_a" in
  --allow-empty) ALLOW_EMPTY=1 ;;
  --keep-db) KEEP_DB=1 ;;
  --allow-count-mismatch) ALLOW_COUNT_MISMATCH=1 ;;
  *) _kept+=("$_a") ;;
esac; done
set -- ${_kept[@]+"${_kept[@]}"}

if ! docker image inspect "$GATE_IMAGE" >/dev/null 2>&1; then
  echo "[linux-gate] building $GATE_IMAGE (one-time, from the pinned base)"
  docker build -t "$GATE_IMAGE" - <<EOF
FROM $RUST_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
RUN arch="\$(uname -m)" && case "\$arch" in \
      aarch64) nx_arch="linux-arm" ;; \
      x86_64)  nx_arch="linux" ;; \
      *) echo "unsupported arch \$arch" >&2; exit 1 ;; \
    esac \
    && curl -LsSf "https://get.nexte.st/${NEXTEST_VERSION}/\${nx_arch}" \
       | tar zxf - -C /usr/local/bin \
    && cargo nextest --version
EOF
fi

# Build parallelism default: 2. The binding constraint is the Docker VM's
# memory (7.7 GiB default) against parallel BFD links of the AWS-SDK-heavy
# server test binaries — -j4+ OOM-killed ld on the S111 shakedown. Raise via
# LINUX_GATE_JOBS if the VM has been given more memory.
JOBS="${LINUX_GATE_JOBS:-2}"

# --nextest → CI-repro: the same invocation as ci.yml's Test step, with the
# build-parallelism cap applied to --build-jobs (the OOM constraint is the
# LINKER, not the test scheduler — test threads stay at nextest's default so
# the ci profile's parallel scheduling reproduces faithfully).
NEXTEST_MODE=0
CLIPPY_MODE=0
if [[ "${1:-}" == "--nextest" ]]; then
  shift
  NEXTEST_MODE=1
  # ⚠ fault-inject rides here so the LOCAL gate reproduces CI exactly (bug228). A
  # local gate that builds fewer binaries than CI is a gate that can pass on code CI
  # will reject -- and, worse, one that silently stops exercising a suite.
  RUN_CMD=(cargo nextest run --profile ci --workspace --locked
           --build-jobs "$JOBS"
           --features signet-server/dev-auth,signet-server/fault-inject "$@")
elif [[ "${1:-}" == "--clippy" ]]; then
  # --clippy (Gus, S162 review of #373): ROOTS §5.1/§5.6 require clippy with
  # -D warnings in BOTH feature configs, in the gate container, never native —
  # and until this mode existed NO machinery implemented that. It was
  # conformance-by-memory, which at S162 produced two hand-rolled invocations
  # and one false alarm, and at S163 was hand-rolled three more times. Both
  # configs run in ONE container invocation under set -e, behind the same
  # bug135 freshness preamble as the test modes; the end marker below is the
  # content check that a green exit really means BOTH configs completed
  # (a partial run cannot print it — same doctrine as deploy.sh's sentinel).
  shift
  [ $# -eq 0 ] || { echo "linux-gate: --clippy takes no extra args (both configs are fixed by ROOTS §5.1)" >&2; exit 2; }
  CLIPPY_MODE=1
  RUN_CMD=(bash -c 'set -e
    echo "### clippy 1/2: default features ###"
    cargo clippy --workspace --all-targets --locked -- -D warnings
    echo "### clippy 2/2: signet-server/dev-auth ###"
    cargo clippy --workspace --all-targets --locked --features signet-server/dev-auth -- -D warnings
    echo "### clippy: BOTH CONFIGS CLEAN ###"')
else
  RUN_CMD=(cargo test --workspace --locked -j "$JOBS" --features signet-server/dev-auth "$@")
fi

# bug164 (S169): the copy-style gate rides EVERY linux-gate invocation, host-side —
# pure text, sub-second, before any container spins up. It lives here and not in GH CI
# by Chris's explicit ruling (local gate only; no GH lint chasing writing style). Its
# scope and exclusions print on every run; --self-test proves it can fail (scripts-ci
# runs that arm).
"$REPO_ROOT/infrastructure/scripts/copy-style-check.sh" || {
  echo "linux-gate: copy-style-check FAILED (bug164) — fix the listed strings before the container run" >&2
  exit 3
}

# bug174: env-var truth lived in four places with nothing checking they agree —
# the drift happens at BUILD time (a var added in code, never documented), so
# the check rides the build gate, host-side, same class as copy-style above:
# pure text, sub-second. FAILs on a server var absent from deployment.md;
# --self-test carries the negative control (scripts-ci runs that arm too).
"$REPO_ROOT/infrastructure/scripts/env-var-doc-check.sh" || {
  echo "linux-gate: env-var-doc-check FAILED (bug174) — document the listed vars in deployment.md before the container run" >&2
  exit 3
}

# host.docker.internal reaches the host-published compose services from
# inside the container (Docker Desktop). Same test env as ci.yml otherwise.
# NOTE (C1, S140): was `exec docker run` — now captured (tee) so the 0-tests guard can
# read the executed count after the run. Output still streams to the terminal live.
# bug135 PREVENT: the freshness preamble runs IN the container, before cargo,
# on the artifact clock (see container-freshness.sh). HOST_NOW is captured
# host-side immediately before the run so the skew measurement is honest.
# ⭐ A FRESH DATABASE PER TEST RUN (Gus's proposal, 2026-10-31; --keep-db opts out).
# CI starts from an empty Postgres; a long-lived local one drifts from it. Twice on
# 10-31 a gate database was stale: one held 2870 epoch-1 rows the v1.1.0 code refuses
# to boot on, one held a 0004 checksum from a file nine minutes older than the one
# that shipped (VersionMismatch). And an isolated database leaks whenever a test fails
# before its drop, so a long-lived gate collects them exactly when something is wrong.
# So: drop every signet_iso_* database (all are older than this run) and recreate
# signet_drive_test, with the gate Postgres's own image, before the build. A run
# therefore also exercises first boot, the path v1.1.0 adds.
# Pinned by digest, as the gate's own image is: postgres:17 as the gate Postgres runs it.
GATE_PG_CLIENT_IMAGE="postgres:17@sha256:b8faeff7712663c2773a190181e1246e37e364b887611c04658c28b44e2408fe"
if fresh_db_planned "$CLIPPY_MODE" "$KEEP_DB"; then
  echo "linux-gate: fresh database — dropping signet_iso_* and recreating signet_drive_test (--keep-db to keep it)"
  docker run --rm -i -e PGPASSWORD=signet_dev_password "$GATE_PG_CLIENT_IMAGE" \
    psql -h host.docker.internal -p "$GATE_PG_PORT" -U signet -d template1 -v ON_ERROR_STOP=1 -q -tA <<'SQL' \
    || { echo "linux-gate: could not reset the test database — refusing to run on a stale one (--keep-db to override)" >&2; exit 2; }
SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', datname)
  FROM pg_database WHERE datname LIKE 'signet\_iso\_%' \gexec
DROP DATABASE IF EXISTS signet_drive_test WITH (FORCE);
CREATE DATABASE signet_drive_test;
SELECT 'linux-gate: fresh: signet_drive_test recreated; '
       || (SELECT count(*) FROM pg_database WHERE datname LIKE 'signet\_iso\_%')
       || ' isolated databases left';
SQL
fi

_gate_out="$(mktemp)"
echo "linux-gate: test services at host.docker.internal — Postgres :${GATE_PG_PORT} · MinIO :${GATE_S3_PORT}"
HOST_NOW="$(date +%s)"
set +e
docker run --rm \
  -v "$REPO_ROOT":/build -w /build \
  -v signet-gate-cargo-registry:/usr/local/cargo/registry \
  -v signet-gate-target:/gate-target \
  -e CARGO_TARGET_DIR=/gate-target \
  -e CARGO_TERM_COLOR=always \
  -e DATABASE_URL="postgres://signet:signet_dev_password@host.docker.internal:${GATE_PG_PORT}/signet_drive_test" \
  -e SIGNET_S3_ENDPOINT="http://host.docker.internal:${GATE_S3_PORT}" \
  -e SIGNET_S3_BUCKET="signet-test" \
  -e SIGNET_S3_ACCESS_KEY="minioadmin" \
  -e SIGNET_S3_SECRET_KEY="minioadmin" \
  -e SIGNET_S3_REGION="us-east-1" \
  "$GATE_IMAGE" \
  bash -c 'bash /build/infrastructure/scripts/container-freshness.sh "$1" && shift && exec "$@"' \
  _ "$HOST_NOW" "${RUN_CMD[@]}" 2>&1 | tee "$_gate_out"
_rc="${PIPESTATUS[0]}"
set -e

_executed="$(count_executed < "$_gate_out")"

# --clippy content check: a green exit must carry the end marker, or one config
# (or the whole run) silently didn't happen — the S162 hazard this mode retires.
if [ "$CLIPPY_MODE" -eq 1 ]; then
  if [ "$_rc" -eq 0 ] && ! grep -q "### clippy: BOTH CONFIGS CLEAN ###" "$_gate_out"; then
    echo "[linux-gate] ⚠ clippy exited 0 but the BOTH-CONFIGS end marker is missing — partial/truncated run; refusing to report ok." >&2
    rm -f "$_gate_out"
    exit 5
  fi
fi
rm -f "$_gate_out"

# C1: a run that executed ZERO tests is never what the operator wanted — it is green and
# meaningless. Gated on `_rc -eq 0` (Gus, S140 nit): a FAILED run (compile error, panic) also
# executes zero tests, and there the true exit code + the already-loud red output are the better
# information — mis-labelling a compile failure as "filter matched nothing" would be a false lead.
# The 0-test guard is for the GREEN-but-empty case only.
# (--clippy is exempt: a lint run legitimately executes zero tests; its own
# completeness check is the BOTH-CONFIGS end marker above.)
if [ "$CLIPPY_MODE" -eq 0 ] && [ "$_rc" -eq 0 ] && [ "$ALLOW_EMPTY" -ne 1 ] && [ "$_executed" -eq 0 ]; then
  {
    echo ""
    echo "[linux-gate] ⚠ 0 TESTS EXECUTED (S140 C1) — the filter/target matched nothing."
    echo "  A run that executes zero tests is green while proving nothing. If you passed a"
    echo "  filter it likely needs target scoping (e.g. '-p signet-cli --lib capacity')."
    echo "  If a genuinely-empty run is intended, re-run with --allow-empty."
  } >&2
  exit 3
fi

# bug135 DETECT: for a green targeted `--test <name>` run, assert the executed
# count EQUALS the static test-attribute count in the named file(s). A stale
# binary — whatever made it stale — shows up as a count mismatch, loudly.
# Green runs only: a red run's true exit code is the better information (the
# same reasoning as C1's `_rc -eq 0` gate).
if [ "$_rc" -eq 0 ] && [ "$ALLOW_COUNT_MISMATCH" -ne 1 ] && [ "$NEXTEST_MODE" -eq 0 ]; then
  _targets="$(extract_test_targets "${RUN_CMD[@]}")"
  if [ -n "$_targets" ]; then
    _static=0; _resolved=1
    while IFS= read -r _t; do
      [ -z "$_t" ] && continue
      _matches="$(find "$REPO_ROOT" \( -name target -o -name node_modules -o -name .git \) -prune \
                    -o -type f -path "*/tests/${_t}.rs" -print 2>/dev/null)"
      _n_matches="$(printf '%s\n' "$_matches" | grep -c . || true)"
      if [ "$_n_matches" -ne 1 ]; then
        echo "[linux-gate] note: --test ${_t} resolves to ${_n_matches} files — count assertion skipped for this run." >&2
        _resolved=0; break
      fi
      _static=$(( _static + $(count_test_fns_in "$_matches") ))
    done <<< "$_targets"
    if [ "$_resolved" -eq 1 ]; then
      if [ "$_executed" -ne "$_static" ]; then
        {
          echo ""
          echo "[linux-gate] ⚠ TEST-COUNT MISMATCH (bug135) — executed ${_executed}, but the named"
          echo "  test file(s) carry ${_static} test attribute(s). The binary that ran does NOT match"
          echo "  the code on disk — a stale build (container-clock skew), or the counts have a"
          echo "  legitimate new mismatch source (macro-generated tests?)."
          echo "  A green gate on a stale binary is worse than a red one; refusing to report ok."
          echo "  If the mismatch is legitimate, re-run with --allow-count-mismatch."
        } >&2
        exit 4
      fi
      echo "[linux-gate] test-count: ${_executed} executed == ${_static} declared ✓ (bug135 assertion)"
    fi
  fi
fi
exit "$_rc"
