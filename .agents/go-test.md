---
name: go-test
description: Run Harbor's Go tests — unit, integration, race detector, and coverage.
---

Run Harbor's Go test suites. Our testing philosophy is in `docs/DESIGN.md` §1.7: **test everything independently AND as a system**, with pure logic unit-tested without mocks and integration tests running against **real** dependencies.

> **Update this skill:** if commands, tags, or the integration-test setup drift from the code, fix this file as part of your change. A stale skill is a bug.

## Unit tests (fast, every commit)

```bash
go test ./...                    # all unit tests
go test ./internal/oidc/...      # target a package
go test -run TestDerivePPID ./internal/identity/...      # target a test
```

Core logic — **PPID derivation (§3.2), token minting/validation, crypto envelope logic (§4.4)** — is written as **pure functions separated from I/O**, so it's trivially unit-testable **without mocks**. Deterministic crypto (HMAC/JWT) is a perfect fit for **table-driven tests**: fixed inputs → fixed outputs → exhaustive, fast assertions.

## Race detector (the concurrent hot path)

```bash
go test -race ./...
```

Run `-race` on anything touching the hot path or shared caches (JWKS, client metadata, revocation bloom filter). Data races there are release-blocking.

## Coverage

```bash
go test -cover ./...
go test -coverprofile=cover.out ./... && go tool cover -html=cover.out
```

## Integration tests (per system, real dependencies)

Per §1.7, integration tests use **real Postgres and real Redis** — only *true external* boundaries are stubbed (KMS/HSM, outbound mail).

**Anti-pattern to forbid:** stubbing internal services or authorization inside integration tests. That is security theater — it hides exactly the bugs integration tests exist to catch. **Never stub the thing that would catch a security regression** (a missing authz check, a cross-region leak).

```bash
# Bring up a real test stack (docker-compose or testcontainers), then:
go test -tags=integration ./...
```

Use **testcontainers-go** or a `docker-compose.test.yml` stack for ephemeral Postgres/Redis. Keep external boundaries (KMS, mail) behind interfaces so only *they* are faked.

## Fast subset vs. full suite

- **Inner loop / pre-commit:** unit tests for the changed package(s).
- **PR / pre-merge:** full `go test ./...` + `-race` + integration.

## On failure

Fix it and re-run — do not skip, `t.Skip`, or mark pending to get green. A flaky test is a bug to root-cause, not to retry.
