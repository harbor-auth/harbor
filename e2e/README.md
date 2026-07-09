# e2e — agent-runnable OIDC harness (Foundation F8)

An end-to-end harness that drives a **live** `harbor-hot` through the composed
`authorize → token → JWKS` flow, including the **§11.7 security negatives**. It
catches the class of bug where every unit test is green but the *assembled* flow
is broken — and it feeds the conformance gate (§1.8 Stage 7).

## What it checks

- `/healthz` is up.
- The OIDC discovery document (`/.well-known/openid-configuration`) returns
  `issuer` / `authorization_endpoint` / `token_endpoint`.
- **Happy path:** `/authorize` (demo client, PKCE S256) → 302 with a `code` back
  to the *registered* redirect → `/token` exchange → `200` `token_type=Bearer`.
- **§11.7 negatives:**
  - `/token` with the wrong `code_verifier` → `400 invalid_grant`.
  - `/authorize` with an **unregistered** `redirect_uri` → never a 302 to that
    URI (an error is shown locally).

## Run it

```bash
docker compose -f e2e/docker-compose.yml up -d
HARBOR_E2E_BASE_URL=http://localhost:8080 go test -tags e2e ./e2e/...
docker compose -f e2e/docker-compose.yml down
```

`HARBOR_E2E_BASE_URL` defaults to `http://localhost:8080`.

## Why it's excluded from the default test run

The flow test in `flow_test.go` carries a `//go:build e2e` tag, so it is **not**
compiled or run by `go test ./...` (it needs a running server). `doc.go` keeps
the package compilable under the default tags. Only `go test -tags e2e` pulls it
in.
