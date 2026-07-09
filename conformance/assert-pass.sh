#!/usr/bin/env bash
# Harbor — assert the OIDF OP conformance run PASSED (release gate, §1.8 Stage 7).
#
# Consumes the normalized results produced by conformance/run-plan.sh and exits
# NON-ZERO on anything short of a clean pass — a conformance regression is
# release-blocking (§1.7). This is deliberately strict and fail-closed:
#   - missing / empty / invalid results.json        -> FAIL (no evidence = no pass)
#   - runnerExit != 0                                -> FAIL (the suite's own verdict)
#   - any required module not in {PASSED, WARNING}   -> FAIL (list the offenders)
#
# WARNING is treated as acceptable (it is advisory in the OIDF suite); FAILED,
# REVIEW, INTERRUPTED, SKIPPED, or any unknown status fail the gate.
set -euo pipefail

RESULTS="${1:-conformance/out/results.json}"

fail() { printf '==> conformance: FAIL — %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail 'jq not installed (required to parse results.json — nix develop)'
[ -f "$RESULTS" ] || fail "results file not found: $RESULTS (did conformance/run-plan.sh run?)"
jq -e . "$RESULTS" >/dev/null 2>&1 || fail "results file is not valid JSON: $RESULTS"

runner_exit="$(jq -r '.runnerExit // empty' "$RESULTS")"
module_count="$(jq -r '.modules | length' "$RESULTS")"

# No runnerExit = the run is unconfirmed. No evidence = no pass.
[ -n "$runner_exit" ] || fail 'results.json missing runnerExit — cannot confirm the run (no evidence = no pass)'

# The OIDF runner's own exit code is authoritative — honor it first.
if [ "$runner_exit" != "0" ]; then
  printf '  failing modules (status not in PASSED/WARNING):\n' >&2
  jq -r '.modules[]? | select((.status|ascii_upcase) as $s | ($s != "PASSED" and $s != "WARNING")) | "    - \(.testName): \(.status)"' "$RESULTS" >&2 || true
  fail "OIDF runner exited $runner_exit (see conformance/out/run.log)"
fi

# Per-module check when structured export is present.
if [ "$module_count" -gt 0 ]; then
  bad="$(jq -r '[.modules[] | select((.status|ascii_upcase) as $s | ($s != "PASSED" and $s != "WARNING"))] | length' "$RESULTS")"
  if [ "$bad" -gt 0 ]; then
    printf '  failing modules (status not in PASSED/WARNING):\n' >&2
    jq -r '.modules[] | select((.status|ascii_upcase) as $s | ($s != "PASSED" and $s != "WARNING")) | "    - \(.testName): \(.status)"' "$RESULTS" >&2
    fail "$bad of $module_count OIDF modules did not pass"
  fi
  printf '==> conformance: PASS — %s OIDF modules all PASSED/WARNING (%s)\n' "$module_count" "$RESULTS"
  exit 0
fi

# The runner exited 0 but exported NO per-module evidence. A clean exit with zero
# modules is not proof the plan actually ran, so fail closed — no evidence = no pass.
fail "OIDF runner exited 0 but exported no per-module results — no evidence to confirm the run (see conformance/out/run.log)"
