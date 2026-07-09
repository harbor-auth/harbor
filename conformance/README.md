# conformance — OIDC OP + WebAuthn certification gate (§1.8 Stage 7)

The **full certification suites** that `make conformance` runs **after** the fast
F8 e2e smoke gate (`e2e/`). Per `docs/DESIGN.md` §1.7 this is a **hard release
gate**: a build that fails conformance does not ship. **Do not waive or
config-around a failure — fix the implementation to conform.**

## What runs

| Stage | Script | Gate |
|---|---|---|
| OIDC OP certification | `run-plan.sh` → `assert-pass.sh` | **Blocking** — the OpenID Foundation suite drives harbor-hot through the OIDC OP test plan headlessly; `assert-pass.sh` fails on any non-`PASSED`/`WARNING` module (honest red). |
| WebAuthn / FIDO2 | `run-webauthn.sh` | **Manual (GUI) + automated substitute** — the FIDO Alliance FIDO2 tools are GUI-only (manual pre-release step); the automated `internal/webauthn` ceremony tests are run **fail-closed (blocking)** when the package is present. |

## Files

- **`docker-compose.yml`** — harbor-hot, the **OP under test** (issuer
  `http://host.docker.internal:8080`, `/healthz`-gated). The heavy OIDF suite is
  **not** vendored — `run-plan.sh` brings it up.
- **`run-plan.sh`** — brings up harbor-hot + the OIDF suite, runs the OIDC OP
  plan via the suite's `scripts/run-test-plan.py`, and writes normalized results
  to `out/results.json`. The **runner exit code is authoritative**.
- **`assert-pass.sh`** — fail-closed asserter over `out/results.json`.
- **`run-webauthn.sh`** — the documented manual WebAuthn gate.
- **`harbor-op-config.json`** — the OP-under-test config (Authorization Code +
  PKCE S256, pairwise-only, asymmetric-only). `{HARBOR_DISCOVERY_URL}` is
  rendered by `run-plan.sh`.
- **`out/`** — run artifacts + archived results (compliance evidence, §12).
- **`.suite/`** — the pinned OIDF suite checkout (created on demand).

## Obtaining the OIDF suite (no official prebuilt image exists)

`run-plan.sh` prefers a prebuilt image and otherwise clones the suite at a pinned
ref. Because the suite is a large Java build, the clone path **fails closed** at a
clearly-marked manual build step rather than attempting a fragile scripted build:

- **Primary (prebuilt image):**
  ```bash
  CONFORMANCE_SUITE_IMAGE=<registry/suite:tag> make conformance
  ```
- **Secondary (pinned clone):** `run-plan.sh` shallow-clones
  `openid-certification/conformance-suite` at `CONFORMANCE_SUITE_REF` into
  `.suite/`, then prints the OIDF
  [Build & Run](https://gitlab.com/openid/conformance-suite/wikis/Developers/Build-&-Run)
  guide and exits 1 until you supply `CONFORMANCE_SUITE_IMAGE`.

## Networking (the crux)

The suite runs in Docker and must reach harbor-hot **and** see a discovery
document whose endpoints it can also reach. So harbor-hot's `ISSUER` is
`http://host.docker.internal:8080` (not `localhost`): the suite reaches the
host-published `:8080` via `host.docker.internal`, and discovery advertises the
same host. `host.docker.internal` is wired to the host gateway via `extra_hosts`
(and `run-plan.sh` adds the same to the suite container it starts).

## Env knobs

| Var | Default | Purpose |
|---|---|---|
| `CONFORMANCE_SUITE_IMAGE` | *(unset)* | Prebuilt suite image (primary path). |
| `CONFORMANCE_SUITE_REF` | `release-v5.1.45` | Pinned suite ref for the clone path. |
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443` | Suite base URL. |
| `HARBOR_ISSUER` | `http://host.docker.internal:8080` | Issuer the suite drives. |
| `PLAN` | `oidcc-basic-certification-test-plan` | OIDF test plan name. |

## Why it is RED today

harbor-hot is an in-memory scaffold (unsigned placeholder tokens), so the OIDF
OP suite cannot yet PASS. That is intentional: the gate is honest red until
harbor-hot reaches real OIDC compliance (asymmetric-signed tokens, pairwise
subjects). The e2e smoke gate (`e2e/`) still passes.
