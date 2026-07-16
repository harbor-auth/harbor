# conformance — OIDC OP + WebAuthn certification gate (§1.8 Stage 7)

The **full certification suites** that `make conformance` runs **after** the fast
F8 e2e smoke gate (`e2e/`). Per `docs/DESIGN.md` §1.7 this is a **hard release
gate**: a build that fails conformance does not ship. **Do not waive or
config-around a failure — fix the implementation to conform.**

## What runs

| Stage | Script | Gate |
|---|---|---|
| OIDC OP certification | `run-plan.sh` → `assert-pass.sh` | **Blocking** — the OpenID Foundation suite drives harbor-hot through the OIDC OP test plan headlessly; `assert-pass.sh` fails on any non-`PASSED`/`WARNING` module AND on any absent/failing `REQUIRED_MODULES` core module. |
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

## Conformance status

harbor-hot now issues **real ES256-signed tokens** (pairwise `sub`), so the
OIDC **Basic OP** certification plan is expected to **PASS**. The
`oidf-conformance` feature delivered the claims and endpoints the suite checks.

### Now passing (asserted by `assert-pass.sh` via `REQUIRED_MODULES`)

| Area | What the suite verifies | Delivered by |
|---|---|---|
| Discovery | `userinfo_endpoint`, `claims_supported`, `token_endpoint_auth_methods_supported: [none]`, pairwise-only, `S256`-only, asymmetric-only | `internal/oidcapi/discovery.go` |
| Authorization Code + PKCE | code+`S256` flow, exact `redirect_uri`, single-use codes | `internal/oidcapi/authorize.go`, `internal/oidc` |
| id_token | asymmetric signature (`ES256`), `iss`/`sub`/`aud`/`exp`/`iat` + `jti`, `auth_time`, `azp`, `acr`, `amr`, `nonce` | `internal/oidc/jwt_issuer.go` |
| UserInfo | Bearer-authenticated `GET /userinfo` returning the pairwise `sub` | `internal/oidcapi/userinfo.go` |

The core modules that MUST pass are pinned in `assert-pass.sh`
(`DEFAULT_REQUIRED_MODULES`): `oidcc-server`, `oidcc-userinfo-get`,
`oidcc-idtoken-signature`, `oidcc-scope-profile`. Override with the
`REQUIRED_MODULES` env var for a narrower local plan.

### Still out of scope / expected to fail

These are **not** part of the Basic OP plan Harbor certifies against and are
deliberately unsupported by design — do not add them to `REQUIRED_MODULES`:

- **Dynamic Client Registration** — Harbor uses a curated client registry
  (DESIGN §3.1); RPs are provisioned out-of-band, not self-registered.
- **Implicit / Hybrid / ROPC flows** — OAuth 2.1: Authorization Code + refresh
  only (DESIGN §3.1).
- **`request`/`request_uri` (JAR/PAR)** — not yet implemented.
- **`client_secret_*` token-endpoint auth** — Harbor is a public-client provider;
  PKCE replaces a client secret (`token_endpoint_auth_methods_supported: [none]`).
- **WebAuthn / FIDO2** — the FIDO Alliance tools are GUI-only (manual
  pre-release step); the automated `internal/webauthn` ceremony tests are the
  blocking substitute (see `run-webauthn.sh`).

The fast e2e smoke gate (`e2e/`) runs first and must also pass.
