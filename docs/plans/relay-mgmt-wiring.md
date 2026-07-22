---
title: Wire relay service into harbor-mgmt (activate /relay-addresses and /byo-domains)
status: draft
design_refs: [§7.5, §7.5.4]
targets: [cmd/harbor-mgmt/, internal/clients/]
promoted_to: null
openspec: changes/relay-mgmt-wiring
created: 2026-07-22
---

# Wire relay service into harbor-mgmt (plan)

> **Dependency order:** depends on `feat(relay): email relay service` (PR #61)
> being merged — all the relay package code, DB migration, and mgmtapi HTTP
> handlers must be present. Independent of `webauthn-db-wiring`,
> `redis-enrollment-session`, and `bff-flow-wiring` at the code level (all
> touch `cmd/harbor-mgmt/main.go` so land in order to minimise merge friction;
> this plan is the natural follow-up to PR #61).

## Problem

PR #61 landed the complete relay service package (`internal/relay/`) and the
HTTP endpoint layer (`internal/mgmtapi/relay.go` — `GET /relay-addresses`,
`DELETE /relay-addresses/{relay_token}`, `POST /byo-domains`, etc.), but the
`mgmtapi.Server` fields `relays` and `byoDomains` are intentionally `nil` —
`WithRelayStore` and `WithBYODomainStore` have never been called from
`cmd/harbor-mgmt/main.go`. All relay endpoints therefore return
`503 Service Unavailable` (the scaffold 503 guard in each handler).

The relay DB migration (`0016_relay_addresses`) is shipped. `relay.Store`
already satisfies the `mgmtapi.RelayStore` interface. This plan is wiring only.

## Proposed approach

### 1. Wire `RelayStore`

`relay.Store` (from `internal/relay/store.go`) already satisfies
`mgmtapi.RelayStore`:

| `mgmtapi.RelayStore` method | `relay.Store` method | Match |
|---|---|---|
| `ListByUser(ctx, userID string)` | `ListByUser(ctx, userID string)` | ✅ |
| `GetByToken(ctx, token string)` | `GetByToken(ctx, token string)` | ✅ |
| `Deactivate(ctx, addressID string)` | `Deactivate(ctx, addressID string)` | ✅ |

Wire it when `pool != nil`:

```go
var relayStore mgmtapi.RelayStore
if pool != nil {
    relayStore = relay.NewStore(db.New(pool), crypto.NewCipher())
    logger.Info("relay store: using DB-backed store")
} else {
    logger.Warn("DATABASE_URL not set — relay endpoints will return 503 (dev mode)")
}
```

Then call `.WithRelayStore(relayStore)` on `mgmtServer`.

### 2. Wire `BYODomainStore`

The `mgmtapi.BYODomainStore` interface requires `CreateDomain`, `GetDomainByName`,
`ListDomainsByUser`, `UpdateDomainState`, and `DeleteDomain`. No DB-backed
implementation exists yet (BYO-domain data is not yet persisted to Postgres —
that requires a new migration and sqlc queries).

**Initial wiring:** add an `InMemoryBYODomainStore` scaffold in
`internal/mgmtapi/byo_domain_store.go` (similar to `InMemoryEnrollmentSessionStore`)
so the endpoints function in single-process dev/test scenarios. The in-memory
store is acceptable short-term because BYO-domain verification is idempotent
(re-verifying a lost domain is harmless). Leave a `// TODO` for the DB migration
follow-up (`byo-domain-db-persistence` plan).

Wire it unconditionally (both dev and DB-backed modes use the in-memory store
until the DB migration lands):

```go
byoDomainStore := mgmtapi.NewInMemoryBYODomainStore()
```

Then call `.WithBYODomainStore(byoDomainStore, domainVerifier, mtaDomain, relayDomain)`
on `mgmtServer`.

### 3. `DomainVerifier` + env vars

`relay.DomainVerifier` needs to be constructed and passed to `WithBYODomainStore`:

```go
mtaDomain   := getenv("MTA_DOMAIN", "")
relayDomain := getenv("RELAY_DOMAIN", "")
var domainVerifier *relay.DomainVerifier
if mtaDomain != "" && relayDomain != "" {
    domainVerifier = relay.NewDomainVerifier(relay.NewNetResolver(), mtaDomain, relayDomain)
} else {
    logger.Warn("MTA_DOMAIN or RELAY_DOMAIN not set — BYO-domain DNS verification unavailable")
}
```

The `DomainVerifier` may be `nil` when the env vars are absent; `PostBYODomainVerify`
and `GetBYODomainDNSStatus` already guard with a nil check and return 503.

### 4. Helm / env

Add `MTA_DOMAIN` and `RELAY_DOMAIN` to `deploy/helm/templates/configmap-mgmt.yaml`
and `deploy/helm/values.yaml` (under `mgmt.relay`). These are the regional MTA
and relay domains (e.g. `mta.eu.harborauth.com`, `relay.eu.harborauth.com`).

## DESIGN alignment

Realises §7.5 (per-RP Hide-My-Email relay) and §7.5.4 (deactivation independent
of login grant revocation). Does **not** change `DESIGN.md` — §7.5 already
describes this feature; this plan connects the existing, tested components.

## Target code paths

- `cmd/harbor-mgmt/main.go` — wire `relay.NewStore`, `InMemoryBYODomainStore`,
  `DomainVerifier`; call `WithRelayStore`/`WithBYODomainStore` on `mgmtServer`;
  read `MTA_DOMAIN`/`RELAY_DOMAIN` env vars; add `relay` import.
- `internal/mgmtapi/byo_domain_store.go` — new `InMemoryBYODomainStore` (dev
  scaffold satisfying `mgmtapi.BYODomainStore`).
- `deploy/helm/templates/configmap-mgmt.yaml` — add `MTA_DOMAIN`, `RELAY_DOMAIN`.
- `deploy/helm/values.yaml` — add `mgmt.relay.mtaDomain`, `mgmt.relay.relayDomain`.

Explicitly **not** touched by this plan:
- `internal/relay/` — all implementations are complete (PR #61).
- `internal/mgmtapi/relay.go` — HTTP handlers are complete (PR #61).
- DB migrations — `0016_relay_addresses` already shipped (PR #61). BYO-domain
  persistence is a follow-up plan (`byo-domain-db-persistence`).

## Implementation checklist

- [ ] Add `internal/mgmtapi/byo_domain_store.go` — `InMemoryBYODomainStore`
      satisfying `BYODomainStore`; include `var _ BYODomainStore = (*InMemoryBYODomainStore)(nil)`.
- [ ] In `cmd/harbor-mgmt/main.go`:
  - [ ] Add `relay` import (`github.com/harbor-auth/harbor/internal/relay`).
  - [ ] Read `MTA_DOMAIN` / `RELAY_DOMAIN` env vars with `getenv`.
  - [ ] Conditionally construct `relay.NewStore(db.New(pool), crypto.NewCipher())`
        when `pool != nil`; log `Info` / `Warn`.
  - [ ] Construct `InMemoryBYODomainStore` unconditionally.
  - [ ] Construct `DomainVerifier` when both env vars are set; log `Warn` when absent.
  - [ ] Call `.WithRelayStore(relayStore).WithBYODomainStore(byoDomainStore,
        domainVerifier, mtaDomain, relayDomain)` in the `mgmtServer` builder chain.
- [ ] `deploy/helm/templates/configmap-mgmt.yaml` — add `MTA_DOMAIN`, `RELAY_DOMAIN`.
- [ ] `deploy/helm/values.yaml` — add `mgmt.relay.mtaDomain` / `mgmt.relay.relayDomain`
      (empty defaults; must be set in `values-prod.yaml`).
- [ ] `go build ./... && go vet ./...` green.
- [ ] `go test ./internal/mgmtapi/... ./internal/relay/...` green.
- [ ] Author & verify paired OpenSpec change: `openspec validate relay-mgmt-wiring --strict`.
- [ ] Reconcile & promote: `@plan promote relay-mgmt-wiring`.

## Risks & open questions

- **BYO-domain persistence:** the in-memory store loses domain records on restart.
  For a v0 deployment this is acceptable (users re-verify); the DB migration
  follow-up (`byo-domain-db-persistence`) adds durability. Document this clearly
  in the store's doc comment.
- **`relay.Store` + `crypto.NewCipher()` in main:** `relay.Store` uses the cipher
  only for creating new relay addresses (mint path), not for the mgmtapi read/deactivate
  paths. Constructing the store in `main` is correct — the cipher is cheap and
  stateless.
- **MTA boot invariant:** `MTA_DOMAIN`/`RELAY_DOMAIN` are optional; the relay
  store itself is wired when `pool != nil` regardless. A deployment without
  these env vars gets relay address management (list/deactivate) but no BYO-domain
  DNS verification — this is the expected staged rollout.

## Definition of done

`go build/vet/test ./...` green; `GET /relay-addresses` returns the authenticated
user's relay addresses (empty list for new users); `DELETE /relay-addresses/{token}`
deactivates a relay address; `POST /byo-domains` creates a domain challenge in
the in-memory store; `openspec validate relay-mgmt-wiring --strict` passes;
plan promoted from draft. Ready to `@plan promote`.
