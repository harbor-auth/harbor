---
title: Collapse to one object graph — remove dev scaffolds, require Postgres + Redis
status: draft
design_refs: [§4.1, §4.4, §10, §1.7]
targets: [cmd/harbor-hot/, cmd/harbor-mgmt/, internal/oidc/, internal/bff/, internal/webauthn/, internal/clients/, internal/arch/, deploy/]
promoted_to: null
openspec: changes/production-wiring-collapse
created: 2026-07-30
---

# Collapse to one object graph (plan)

> **Severity: HIGH — this is the root-cause feature.** Audit findings H1, H8, M1,
> and parts of M5 —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).
> It also unblocks H2, H3, H6, H7 and M3.

## Problem

Both binaries assemble themselves out of **dev scaffolds** while the DB-backed
implementations sit unreferenced. Twelve security-critical constructors exist in
the tree and are called nowhere outside their own tests:

```
NewRedisAuthCodeStore    NewDBClientRegistry       NewJWTVerifier
NewRevocationWorker      NewBloomRevocationFilter  NewDBRevokedJTIStore
NewRevocationSubscriber  NewStepUpGate             RecordTOTPStepUp
DBSessionStore (in hot)  WithEnrollmentSessions    WithClientRegistration
```

Concretely, in production today:

- **`demo-client` is a live registered RP** on every deployment
  (`cmd/harbor-hot/main.go:156-163`), with `http://localhost/callback` registered.
- **No RP can ever be registered.** `WithClientRegistration` is never called →
  `/register` returns 503, and `DBClientRegistry` is never wired → the only
  clients that exist are the hardcoded one.
- **Auth codes are per-process** (`NewInMemoryAuthCodeStore`, `:185`). With
  `hpa.maxReplicas: 20`, `/token` fails whenever the exchange lands on a
  different pod than `/authorize`.
- **Unbounded memory growth.** `InMemoryAuthCodeStore` never evicts
  (`oidc/store.go:160-194`) — `Save` inserts, `Consume` tombstones, nothing
  deletes. Every `/authorize` grows the map permanently.
- **`offline_access` refresh tokens are never issued.** `SessionStore` defaults
  to `noopSessionStore`; the in-memory grant store makes `FindGrant` miss, so
  `issueRefreshToken` bails at `service.go:536`.
- **No passkey can be enrolled (H8).** `cmd/harbor-mgmt/main.go:359` calls
  `webauthn.RegisterRoutes(mux, svc)` — a handler with no enrollment session
  store — so `userIDFromRequest` (`webauthn/handlers.go:152-164`) returns `501`
  for all four ceremony endpoints, and `mgmtServer` never calls
  `WithEnrollmentSessions`. **As wired, there is no working authentication path.**
- **The manifests cannot boot either binary (M1).** See the table below.

**Root cause:** the "optional dependency, degrade gracefully" pattern
(`if pool != nil`, `WithX(nil)` → noop or 503). Each optional dependency forks
the object graph, and the *fake* branch is the one the 45k-LOC test suite covers.
`validateProductionReadiness` (`main.go:406`) exists precisely because the
degradation is dangerous — it is a runtime patch over something construction
should make impossible. `NewService` already **panics** on one bad noop
combination (`oidc/service.go:217-223`); there are ~8 more noop stores without
guards.

## Proposed approach

**Postgres and Redis become required.** They already are, de facto — the startup
guard demands both. Make the dependency real instead of guarding it. Three rules:

### Rule 1 — constructors take dependencies, not `nil`

`New*` returns an `error` when a required collaborator is missing. Delete every
`WithX(nil)` → noop/503 degradation path. A missing dependency is a startup
failure, not a runtime 503.

### Rule 2 — in-memory implementations move where `cmd/` cannot import them

Relocate to `internal/<pkg>/memstore` behind a `//go:build test` tag, or to an
`internal/testsupport` package, and **enforce with `internal/arch`** (which
already does compile-time boundary enforcement).

| Delete outright — these silently *succeed* | Move to test-only |
|---|---|
| `oidc.NewPlaceholderIssuer` / `placeholderIssuer` (unsigned tokens) | `oidc.InMemoryClientRegistry` |
| `oidc.NewStubSessionResolver` | `oidc.InMemoryAuthCodeStore` |
| `noopSessionStore`, `noopGrantStore`, `noopConsentStore` | `oidc.InMemorySessionStore` |
| `noopRevocationSink`, `noopRevocationOutbox`, `noopRevokedJTIChecker` | `oidc.InMemoryGrantStore`, `InMemorySecretLoader` |
| `main.noopSessionRevoker`, `main.noopUserPersister` | `oidc.FixedAuthSource` |
| `clients.MemoryRateLimiter` (redundant — Redis path already fails open) | `bff.InMemoryBFFSessionStore` |
| `mgmtapi.NewInMemoryBYODomainStore` (replace with a DB store) | `webauthn.InMemoryStore`, `InMemorySessionStore` |
| `cmd/harbor-hot/bootstrap.go` — **365 lines, already fully dead** | |

**Do NOT sweep up:** `oidc.RevocationFilter` (in-memory + bloom) is a deliberate
hot-path cache backed by `revoked_jtis`, not a scaffold — keep both.
`crypto.LocalKeyProvider` / `LocalSigner` are the **only** KeyProvider/Signer
that exist; the KMS variants have no backend yet
(`docs/plans/hsm-signing-key.md`). Removing them leaves nothing. Keep, keep the
DEV-ONLY warnings, and leave HSM migration to its own plan.

### Rule 3 — one boot path

Delete `HARBOR_DEV_MODE` and `validateProductionReadiness`; they become
unnecessary once constructors error. Local dev and e2e get real Postgres + Redis
from the existing `e2e/docker-compose.yml`.

### Wire the real stores

| Seam | Today | After |
|---|---|---|
| Client registry (hot) | `InMemoryClientRegistry` + `demo-client` | `clients.NewDBClientRegistry` |
| Auth codes (hot) | `InMemoryAuthCodeStore` | `clients.NewRedisAuthCodeStore` |
| Refresh sessions (hot) | absent → `noopSessionStore` | `clients.NewDBSessionStoreWithPool` |
| Grants (hot) | `InMemoryGrantStore` | the already-built `deps.grantStore` |
| Consents (hot) | absent | `clients.NewDBConsentStore` |
| Dynamic registration (mgmt) | absent → 503 | `WithClientRegistration(store, baseURL)` |
| Enrollment→ceremony (mgmt) | absent → 501 | `WithEnrollmentSessions` on **both** `mgmtServer` and the webauthn `Handler` |
| BYO domains (mgmt) | in-memory | DB-backed store |

### Fix the manifests (M1)

| Manifest sets | Code reads | Fix |
|---|---|---|
| `HARBOR_KEK_SECRET` (k8s secret-mgmt) | `HARBOR_KMS_SECRET` | rename |
| `WEBAUTHN_RP_NAME` (k8s configmap-mgmt) | `WEBAUTHN_RP_DISPLAY_NAME` | rename |
| `WEBAUTHN_ORIGIN` (k8s configmap-mgmt) | `WEBAUTHN_RP_ORIGINS` | rename |
| *(nothing)* | `REGION` | add |
| Helm `secret-hot` lacks `HARBOR_KMS_SECRET`, `LOGIN_URL` | both required | add |
| Helm `deployment-mgmt` has no `REDIS_URL`, comment claims mgmt "does not use Redis" | mgmt uses it for BFF **and** WebAuthn session stores (`main.go:104-139`) | add + fix comment |

Also model the **shared** KEK properly: `KEK_SECRET` (hot, signing keys) and
`HARBOR_KMS_SECRET` (mgmt, user DEKs) are distinct, but hot *also* needs mgmt's
value to unwrap user DEKs for PPID derivation. The chart has one `kekSecret` per
component and no way to express the shared one. Introduce an explicit
`global.userDekKekSecret` consumed by both.

## DESIGN alignment

Serves §4.1 (hot/cold split), §4.4 (regional data plane), §10 (data model),
§1.7 (pure core, IO at the edges — **the interfaces stay**; only the
optional-ness goes). No DESIGN change: this makes the code match the design that
is already written.

## Target code paths

- `cmd/harbor-hot/main.go` — real stores; delete dev-mode branches; **delete `bootstrap.go`**
- `cmd/harbor-mgmt/main.go` — `WithClientRegistration`, `WithEnrollmentSessions`, DB BYO store
- `internal/oidc/{issuer,resolver,service,store,refresh,consent}.go` — delete noops/stubs
- `internal/bff/`, `internal/webauthn/` — relocate in-memory stores
- `internal/clients/ratelimit.go` — delete `MemoryRateLimiter`
- `internal/mgmtapi/byo_domain_store.go` — DB-backed
- `internal/bff/dashboard.go` — nil-check `consents`/`sessions`/`credentials` (M5) — or, better, make them required
- `internal/arch/arch_test.go` — new wiring rules
- `deploy/k8s/`, `deploy/helm/`, `e2e/docker-compose.yml`

## Implementation checklist

- [ ] Wire the real stores per the seam table; delete `demo-client`
- [ ] Convert `New*`/`With*` to error-returning required dependencies
- [ ] Relocate in-memory stores behind a build tag / `testsupport`; add arch rules forbidding `cmd/**` from importing them
- [ ] Delete the noop/stub/placeholder inventory above, and `cmd/harbor-hot/bootstrap.go`
- [ ] Delete `HARBOR_DEV_MODE` and `validateProductionReadiness`
- [ ] Set `pgxpool` `MaxConns` explicitly (HPA scales to 20 replicas)
- [ ] Fix every manifest/env-name mismatch; add the shared user-DEK KEK value
- [ ] Update `e2e/docker-compose.yml` + `README.md` so local dev runs on real Postgres + Redis
- [ ] **Regression guard (the point of the whole feature):** an integration test that builds the real handler graph via `run()` against containerised Postgres/Redis and asserts *which implementations are live* — no in-memory store, no noop, no placeholder issuer reachable from `main`
- [ ] Tests: cross-replica `/authorize` on instance A → `/token` on instance B succeeds
- [ ] Tests: `offline_access` actually returns a refresh token end-to-end
- [ ] Tests: passkey enrollment ceremony completes (no 501)
- [ ] Tests: startup fails cleanly and loudly with a missing dependency
- [ ] Author & verify paired OpenSpec change: `@openspec new production-wiring-collapse` then `openspec validate production-wiring-collapse --strict`
- [ ] Reconcile & promote: `@plan promote production-wiring-collapse`

## Risks & open questions

- **Largest blast radius of the whole set.** Touches both mains and ~20 files.
  Land the three CRITICAL fixes first (this feature is their DAG child).
- **Do not migrate to Postgres-only.** Redis stays: auth-code TTL semantics,
  BFF/WebAuthn session TTLs, sliding-window rate limits, and revocation pub/sub
  are all a genuine fit, and all four implementations already exist and work.
  Collapsing to one datastore would mean rewriting working components to save one
  container — a bad trade. If it is ever wanted, do it as a deliberate follow-up.
- **`/register` becoming live** means anonymous dynamic registration unless
  `WithInitialAccessToken` is also configured. Wire the gate in the same PR.
- **Migrations:** this feature adds none. Harbor has not launched, so its
  sibling features amend existing migrations in place rather than adding new
  ones — there is no number to reserve or collide with. Do not add a migration
  here either.
- **Pre-launch (2026-07-30):** with no users and no production rows, the
  backward-compatibility comments scattered through the wiring — "legacy
  sessions created before the column was added" (`clients/sessions.go:98-105`),
  nullable `grant_id` for the migration window (`0007`), `NOT NULL DEFAULT ''`
  on `sessions.client_id` (`0005`) — describe a constraint that does not exist.
  Delete the dead compatibility branches rather than carrying them; they are
  future confusion for no benefit.
- Retain every `DEV-ONLY` warning on `LocalSigner` / `LocalKeyProvider`; they are
  staying only because there is no HSM backend yet.

## Definition of done

- No in-memory store, noop store, stub resolver, or placeholder issuer is
  reachable from either `main()`, proven by an arch test **and** a live-graph
  integration test.
- Both binaries boot from the shipped Helm chart against real Postgres + Redis.
- A user can enroll a passkey, log in, and receive a refresh token.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check`, and
  `make conformance` green.
