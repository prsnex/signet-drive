#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PRSN EX Inc.
#
# npm-audit-gate.sh — the npm half of the dependency-advisory gate (S137).
#
# WHY THIS REPLACES A BARE `npm audit --audit-level=high`. The Rust side has had a
# disclosed ignore baseline since S062 (`.cargo/audit.toml`), whose own comment
# states the principle: **the gate's real job is to FAIL on a newly-introduced
# advisory.** The npm side had no equivalent, so it could not tell "new" from
# "known, justified, watched" — and the moment an advisory landed on a transitive
# DEV dependency we cannot move (brace-expansion under eslint, S137), it went
# permanently red and blocked every PR touching a manifest. A permanently red gate
# trains people to ignore it, which is worse than fixing or declaring.
#
# WHAT IT DOES NOT DO: lower the bar. Every high/critical advisory NOT in the
# baseline still fails the build, and every waiver applied is PRINTED — waived,
# never hidden (the same disclosure condition applied to the public repo's leak
# waivers and to exporting `.cargo/audit.toml` itself).
#
# ROOT ADVISORIES, NOT PACKAGE COUNTS. `npm audit`'s human output counts affected
# PACKAGES, and a package inherits its worst transitive severity — so ONE high
# advisory in brace-expansion presents as "5 high" once minimatch, eslint,
# @eslint/config-array and @eslint/eslintrc inherit it. Reading that as five
# advisories is a real trap (it cost S137 a wrong claim that two runtime advisories
# had crossed the threshold when both were still moderate/low). This gate walks the
# `via` graph and keys on the ADVISORY's own severity, which is the honest unit.
#
# Usage:  infrastructure/scripts/npm-audit-gate.sh            # from repo root or web/
#         BASELINE=path/to/baseline.txt  ...                  # override
#
# Exit: 0 = no unwaived high/critical advisory. 1 = at least one (or a parse
# failure — a gate that cannot read its input must never report success).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="${WEB_DIR:-$(cd "$HERE/../../web" && pwd)}"
BASELINE="${BASELINE:-$WEB_DIR/audit-baseline.txt}"

[ -d "$WEB_DIR" ] || { echo "npm-audit-gate: no web/ at $WEB_DIR" >&2; exit 1; }
[ -f "$BASELINE" ] || { echo "npm-audit-gate: no baseline at $BASELINE" >&2; exit 1; }

cd "$WEB_DIR"

# `npm audit` exits non-zero when it finds anything, so `|| true` — the verdict is
# ours to compute, not its exit code. But an EMPTY body means the command genuinely
# failed (no network, bad lockfile) and must not read as "clean".
REPORT_FILE="$(mktemp)"
trap 'rm -f "$REPORT_FILE"' EXIT
npm audit --json >"$REPORT_FILE" 2>/dev/null || true
[ -s "$REPORT_FILE" ] || { echo "npm-audit-gate: npm audit produced no output — treating as FAILURE, not as clean" >&2; exit 1; }

# The report goes in as a FILE argument, not on stdin: a heredoc already occupies
# stdin for the script body, and giving python both makes the second redirect win —
# python then reads the JSON as its own source. (Caught by this gate failing loudly
# on its first run, which is the right failure mode for a gate.)
BASELINE="$BASELINE" python3 - "$REPORT_FILE" <<'PY'
import json, os, sys, re

with open(sys.argv[1]) as fh:
    raw = fh.read()
try:
    report = json.loads(raw)
except json.JSONDecodeError as e:
    print(f"npm-audit-gate: unparseable npm audit JSON ({e}) — FAILING", file=sys.stderr)
    sys.exit(1)

# Baseline: `GHSA-xxxx | rationale`; everything else is a comment.
waived = {}
with open(os.environ["BASELINE"]) as fh:
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        gid, _, why = line.partition("|")
        waived[gid.strip()] = why.strip()

# Walk `via` for ADVISORY objects and key on each advisory's OWN severity — a
# package's severity is inherited from its worst transitive and would over-count.
advisories = {}
for pkg, node in (report.get("vulnerabilities") or {}).items():
    for via in node.get("via") or []:
        if isinstance(via, dict):
            gid = (via.get("url") or "").rstrip("/").rsplit("/", 1)[-1]
            if re.fullmatch(r"GHSA-[0-9a-z-]+", gid or ""):
                advisories[gid] = {
                    "severity": via.get("severity", "unknown"),
                    "package": via.get("name", pkg),
                    "title": (via.get("title") or "").strip(),
                }

blocking = {g: a for g, a in advisories.items() if a["severity"] in ("high", "critical")}
applied = {g: a for g, a in blocking.items() if g in waived}
unwaived = {g: a for g, a in blocking.items() if g not in waived}
below = {g: a for g, a in advisories.items() if g not in blocking}

print(f"npm-audit-gate: {len(advisories)} root advisories "
      f"({len(blocking)} high/critical, {len(below)} below the gate)")

# Waivers are always reported. Silence about an applied waiver is how a baseline
# rots into a blindfold.
for g, a in sorted(applied.items()):
    print(f"  WAIVED   {g}  {a['package']}: {a['title'][:70]}")
    print(f"           rationale: {waived[g]}")
for g, a in sorted(below.items()):
    print(f"  below    {g}  [{a['severity']}] {a['package']}")

# A baseline entry that no longer matches anything is stale — say so, but do not
# fail on it: a dependency bump that removes an advisory is good news.
for g in sorted(set(waived) - set(advisories)):
    print(f"  STALE    {g} is baselined but no longer reported — remove it from the baseline")

if unwaived:
    print()
    for g, a in sorted(unwaived.items()):
        print(f"  ✘ UNWAIVED {a['severity'].upper()}  {g}  {a['package']}: {a['title'][:70]}", file=sys.stderr)
    print(f"\nnpm-audit-gate: FAIL — {len(unwaived)} high/critical advisory(ies) not in the baseline.\n"
          f"Fix it, or add it to web/audit-baseline.txt WITH a rationale and a revisit condition.",
          file=sys.stderr)
    sys.exit(1)

print("npm-audit-gate: PASS — no unwaived high/critical advisory.")
PY
