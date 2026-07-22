#!/usr/bin/env bash
# Harbor — WebAuthn / FIDO2 conformance gate (§1.8 Stage 7).
#
# The FIDO Alliance FIDO2 / WebAuthn conformance test tools are GUI / desktop
# applications and do NOT run headlessly in CI. So this gate is intentionally a
# DOCUMENTED MANUAL step, and the AUTOMATED CI coverage for the passkey
# ceremonies is Harbor's own `internal/webauthn` tests (attestation, assertion,
# signCount) — run by `make test` / `make agent-check` on every change.
#
# This script prints the manual pre-release checklist, then RUNS the automated
# substitute — Harbor's `internal/webauthn` ceremony tests — FAIL-CLOSED so a
# broken passkey ceremony blocks the gate. It is NOT a silent skip: the manual
# requirement is stated explicitly, and the automated coverage is actually
# exercised (a PRESENT-but-FAILING internal/webauthn package fails the gate).
set -euo pipefail

GO="${GO:-go}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cat <<'DOC'
==> conformance: WebAuthn / FIDO2 — MANUAL gate (GUI tooling; not headless)
  Automated CI coverage (runs on every change):
    - internal/webauthn passkey ceremony tests (attestation, assertion, signCount)
      via `make test` / `make agent-check`.

  Manual pre-release step (before a release that touches passkeys, §10):
    1. Run the FIDO Alliance FIDO2 / WebAuthn conformance test tools against a
       live harbor-hot passkey registration + authentication flow.
    2. Archive the tool's report alongside conformance/out/ as compliance
       evidence (§12).

  See .agents/oidc-conformance.md (WebAuthn conformance) for the full procedure.
DOC

# Automated substitute: run the passkey ceremony tests fail-closed when present.
# An ABSENT package is an informative skip (greenfield); a PRESENT one that FAILS
# fails the gate (matches the Makefile's absent-harness philosophy).
if [ -d "$REPO_ROOT/internal/webauthn" ]; then
  echo '==> conformance: running internal/webauthn ceremony tests (automated WebAuthn substitute)'
  ( cd "$REPO_ROOT" && "$GO" test ./internal/webauthn/... )
else
  echo '  [skip] internal/webauthn not present yet — automated WebAuthn coverage lands with the package'
fi

exit 0
