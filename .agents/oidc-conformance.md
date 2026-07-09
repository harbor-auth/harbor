---
name: oidc-conformance
description: Run the OIDC OP + WebAuthn conformance suites as a hard release gate (§1.7, §1.8 stage 7).
---

Run Harbor's conformance suites. Per `docs/DESIGN.md` §1.7, **OIDC OP certification and WebAuthn conformance MUST pass to ship — this is a hard gate, not advisory: a build that fails conformance does not release** (§1.8 **Stage 7**). Standards-first (§1.1): we conform to the spec, we don't invent our own auth.

> **Update this skill:** if the conformance tools, test plans, or commands below drift from the code, fix this file as part of your change. Harbor is greenfield — this describes the **intended** workflow per the design and is updated as the code lands. A stale skill is a bug.

## OIDC OP conformance

Use the **OpenID Foundation conformance suite** (`openid-certification/conformance-suite`) — runnable locally via its Docker Compose, or hosted at <https://www.certification.openid.net/>. Point it at a running `harbor-hot` issuer's discovery doc (`/.well-known/openid-configuration`).

Test plans relevant to Harbor:

- **Authorization Code + PKCE** (the profile Harbor targets), **discovery**, and **JWKS**.
- Config MUST reflect Harbor's invariants: **pairwise subjects only** (§3.2) and **asymmetric signing only** (ES256/EdDSA; `alg:none`/HS\* rejected, §7).

## WebAuthn conformance

Use the **FIDO Alliance FIDO2 / WebAuthn conformance test tools** against the passkey registration/authentication flows (the `credentials` table, §10) — attestation, assertion, and `signCount` handling. These tools are **GUI / desktop** and do **not** run headlessly, so `conformance/run-webauthn.sh` is a **documented MANUAL gate** (it prints the procedure and exits 0). The **automated CI coverage** for the passkey ceremonies is Harbor's own `internal/webauthn` tests, run by `make test` / `make agent-check`.

## How to run (intended)

`make conformance` FIRST runs the in-repo **e2e OIDC harness** (Foundation F8: `e2e/docker-compose.yml` + `go test -tags=e2e ./e2e/...`) as a fast composed-flow smoke gate — authorize→token→JWKS plus the **§11.7 negatives** (PKCE mismatch ⇒ `invalid_grant`, unregistered `redirect_uri` rejected) against a **live harbor-hot** — BEFORE the full OIDF OP + WebAuthn suites below. CI runs this via a dedicated Docker-enabled **`e2e`** job (`nix develop -c make conformance`), so the assembled flow is exercised on every PR.

Beyond that smoke gate, `make conformance` runs the **full OIDF OP suite headless** via the `conformance/` harness and asserts **all required modules pass** — non-zero exit on any required failure (honest red). The harness lives in `conformance/` (see `conformance/README.md`):

- **`conformance/docker-compose.yml`** — harbor-hot, the **OP under test** (issuer `http://host.docker.internal:8080` so the Dockerized suite can reach it and its discovery endpoints).
- **`conformance/run-plan.sh`** — brings up harbor-hot + the OIDF suite and runs the OIDC OP plan via the suite's `scripts/run-test-plan.py`, writing normalized results to `conformance/out/results.json`. The **runner exit code is authoritative**. There is **no official prebuilt suite image**, so it prefers `CONFORMANCE_SUITE_IMAGE` and otherwise shallow-clones the suite at a pinned `CONFORMANCE_SUITE_REF`, failing closed at the OIDF Build & Run step (the Java jar build is not scripted).
- **`conformance/assert-pass.sh`** — fail-closed asserter: non-zero unless every required module is `PASSED`/`WARNING`.
- **`conformance/run-webauthn.sh`** — the **documented manual** WebAuthn/FIDO2 gate (see below).

```bash
# The whole gate (e2e smoke -> OIDC OP cert -> assert -> WebAuthn):
make conformance

# Or the OIDF OP suite directly, with a prebuilt suite image (primary path):
CONFORMANCE_SUITE_IMAGE=<registry/suite:tag> bash conformance/run-plan.sh
bash conformance/assert-pass.sh conformance/out/results.json   # honest red on any non-pass
```

## CI placement (§1.8 Stage 7)

Runs **pre-release**, after integration (Stage 5) and security (Stage 6); **blocks the release** on any failure. **Keep the result report as compliance evidence** for the governance trail (§12).

## On failure

**Do NOT waive or config-around a conformance failure — fix the implementation to conform.** A conformance regression is release-blocking.

## Checklist

- [ ] In-repo **e2e OIDC harness** (F8) passes (`make conformance` / `go test -tags=e2e ./e2e/...`)?
- [ ] OIDF suite pointed at Harbor's **live issuer** via `conformance/harbor-op-config.json` (`/.well-known/openid-configuration`)?
- [ ] Config reflects **pairwise-only** subjects and **asymmetric-only** signing?
- [ ] **OIDC OP** plan (Code + PKCE / discovery / JWKS) **all-pass** via `run-plan.sh` → `assert-pass.sh` (honest red until harbor-hot conforms)?
- [ ] **WebAuthn/FIDO2** manual gate run (`run-webauthn.sh`) and `internal/webauthn` ceremony tests green?
- [ ] Run is **headless / scripted** and **exits non-zero** on any required failure (fail-closed)?
- [ ] **`conformance/out/results.json` archived** for compliance evidence (§12)?
