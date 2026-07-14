---
title: Bloom-filter revocation (§3.5 — emergency JWT kill)
status: draft
design_refs: [§3.5, §3.5.2, §3.5.4, §7.4]
targets: [internal/oidc/, cmd/harbor-hot/]
promoted_to: null
openspec: changes/bloom-filter-revocation
created: 2026-07-14
---

# Bloom-filter revocation (plan)

> **Dependency order:** depends on **`real-token-issuance`** (JWTs must carry
> a real `jti` claim for the filter to key on) and **`revocation-outbox`**
> (the outbox is the *persistent* kill path; the bloom filter is the
> *near-instant in-process* kill path — they compose, not compete). Can be
> prototyped with stub JTIs, but production deployment requires real JWTs.

## Problem

JWT verification is intentionally stateless: RPs verify the signature offline
against the cached JWKS — no call to Harbor. This is the performance property
that makes the architecture scale. But it creates a revocation gap:

- **Routine revocation** (logout, app removal): delete the refresh token. The
  short-lived JWT expires on its own (≤ 15 min window — acceptable).
- **Emergency revocation** (compromised credential, active attack): the
  15-minute window is too long. A stolen JWT must be killed in **seconds**.

Today Harbor has no emergency kill mechanism. The `revocation-outbox` plan
provides durable DB-side session revocation (prevents *new* tokens from being
minted), but it does nothing to invalidate JWTs already in circulation.

§3.5 of the design specifies the answer: a **bloom filter** checked at every
token verification point, replicated across all `harbor-hot` replicas, with a
management API to add entries and a replication channel (Redis pub/sub or gossip)
to push updates within seconds.

## Proposed approach

### The data structure

A **counting bloom filter** (not a simple bit-array) so entries can be removed
as well as added — useful when a false-positive is confirmed to be genuine (the
token expired, no need to keep its `jti` in the filter forever):

- **Keys:** `jti` values (UUID strings, 36 bytes each).
- **Target false-positive rate:** ≤ 1 in 1,000,000 with up to 10,000 actively
  revoked JTIs (a bloom filter of ~240 KB satisfies this with 23 hash functions).
- **In-process:** one `sync.RWMutex`-protected filter per replica; reads are
  lock-free via the read lock, writes are infrequent (emergency use only).

### Verification pipeline

```
RP's JWT arrives at harbor-hot (or at the RP itself, using the JWKS)
    │
    1. Verify signature vs cached JWKS                 (offline, always)
    2. Check exp                                       (offline, always)
    3. filter.MightContain(jti)                        (in-process, ~100 ns)
       │
       hit (possible revocation)
       │
       4. DB introspection: SELECT FROM revoked_jtis   (rare — false pos. rate ≤ 1/1M)
          │
          confirmed → 401 Unauthorized
          false pos  → 200 OK
       │
       miss → 200 OK (no DB call)
```

Step 3 adds ~100 ns on the fast path (no network, no DB). Step 4 (DB
introspection) only fires on a bloom filter hit, which at a 1-in-1M false
positive rate means roughly 1 introspection per million token checks — negligible.

### Schema

```sql
-- The persistent revoked_jtis table (source of truth for filter rehydration).
-- Also the fallback for RP-side introspection when the filter is unavailable.
CREATE TABLE revoked_jtis (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason     TEXT NOT NULL,         -- 'emergency_kill' | 'key_rotation'
    expires_at TIMESTAMPTZ NOT NULL   -- JWT's original exp; used for GC
);
CREATE INDEX revoked_jtis_exp_idx ON revoked_jtis (expires_at);
-- GC: DELETE FROM revoked_jtis WHERE expires_at < now() (run nightly).
```

### Replication

```
Management API (harbor-mgmt):
    POST /admin/revoke-jwt { jti: "...", reason: "emergency_kill" }
        │
        ├─► INSERT INTO revoked_jtis
        └─► PUBLISH revocation_channel "jti:<value>" (Redis pub/sub)

harbor-hot replicas (all):
    SUBSCRIBE revocation_channel
        │
        message → filter.Add(jti) under write lock
        │
    On startup:
        SELECT jti FROM revoked_jtis WHERE expires_at > now()
        → filter.Add each (rehydrates the filter from the persistent store)
```

### Filter sizing guide

| Active revocations | Optimal filter size | FP rate |
|---|---|---|
| 1,000 | 24 KB | < 1/1M |
| 10,000 | 240 KB | < 1/1M |
| 100,000 | 2.4 MB | < 1/1M |
| 1,000,000 | 24 MB | < 1/1M |

At 10,000 active emergency revocations the in-process footprint is ~240 KB —
trivial relative to any production heap.

### Library choice

Use `github.com/bits-and-blooms/bloom/v3` (MIT, well-maintained, pure Go):
- `bloom.NewWithEstimates(n, fp)` constructs for target cardinality `n` and
  false-positive rate `fp`.
- No CGo, no external dependencies, benchmarks at ~90 ns/lookup.

### The nuclear option: JWKS key rotation

For a **signing key compromise** (all tokens signed by the current key are
suspicious), simply rotate the JWKS `kid`. Old tokens fail signature
verification immediately at step 1 — no bloom filter needed. The bloom filter
is for surgical per-token revocation where the key itself is not compromised.

## DESIGN alignment

Implements §3.5 (bloom-filter kill) and §3.5.2 (the four-level revocation
stack: JWT expiry → refresh revocation → JTI bloom filter → key rotation).
Adds `revoked_jtis` to §10's data model. `harbor-mgmt` gains the emergency
kill management endpoint (§7.4's operational API). Does **not** change
`DESIGN.md` structure — this is pure realization of existing design.

## Target code paths

- `db/migrations/0005_revoked_jtis.{up,down}.sql`
- `db/queries/revoked_jtis.sql`
- `internal/gen/db/revoked_jtis.sql.go` (regenerated)
- `internal/oidc/revocation_filter.go` — `RevocationFilter` interface + bloom impl
- `internal/oidc/token.go` — JTI check in JWT verification path
- `cmd/harbor-hot/main.go` — filter init (rehydrate from DB) + Redis subscriber
- `cmd/harbor-mgmt/main.go` — `POST /admin/revoke-jwt` endpoint
- `internal/oidc/*_test.go` — unit tests for filter; invariant test

## Implementation checklist

- [ ] Add `github.com/bits-and-blooms/bloom/v3` to `go.mod`
- [ ] Write migration `0005_revoked_jtis.{up,down}.sql`
- [ ] Write `db/queries/revoked_jtis.sql` (Insert, ListActive, GCExpired)
- [ ] Run `sqlc generate`
- [ ] Implement `RevocationFilter` interface in `internal/oidc/revocation_filter.go`
- [ ] Wire `filter.MightContain(jti)` into the JWT verification path
- [ ] Add DB introspection fallback on filter hit
- [ ] Add `POST /admin/revoke-jwt` to `harbor-mgmt`
- [ ] Add Redis pub/sub subscriber in `harbor-hot` (or polling fallback)
- [ ] Add filter rehydration on startup
- [ ] Invariant: add `INV-EMERGENCY-REVOCATION` to `invariants/registry.yaml`
- [ ] `go test -race ./...` passes
- [ ] `@validate` passes
