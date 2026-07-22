---
title: Bloom-Filter Revocation (emergency JWT kill)
status: implemented
design_refs: [§3.5, §7.4]
code:  [internal/oidc/, internal/oidcapi/, internal/clients/, cmd/harbor-hot/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/oidc/, internal/oidcapi/, internal/clients/]
depends_on: [real-token-issuance, revocation-outbox]
plan: bloom-filter-revocation
last_reconciled: 2026-07-20
---

# Bloom-Filter Revocation (emergency JWT kill)

## Summary

Harbor can now kill a specific JWT **within seconds** without giving up the
offline-verification performance thesis (docs/DESIGN.md §3.5). An in-process
bloom filter of revoked `jti`s is checked on every token verification (~100 ns,
no network, no DB on the fast path); a filter hit falls back to a DB
introspection to distinguish a true revocation from a bloom false positive.
`POST /admin/revoke-jwt` records the revocation in the source-of-truth
`revoked_jtis` table, adds it to the local filter immediately, and publishes it
to sibling `harbor-hot` replicas over Redis pub/sub. This is level 3 of the
§3.5.2 revocation stack (JWT expiry → refresh revocation → **JTI bloom filter**
→ key rotation) — the surgical per-token kill that complements the durable,
session-level `revocation-outbox` and the whole-key `signing-key-rotation`.

## Behavior (as-built)

**Filter (`oidc.RevocationFilter`)** — a small interface (`MightContain`,
`Add`, `Remove`, `Rehydrate`) with two implementations:

- `BloomRevocationFilter` (production) — wraps
  `github.com/bits-and-blooms/bloom/v3` behind a `sync.RWMutex`. Sized via
  `NewWithEstimates` from `DefaultBloomCapacity` (10,000) and
  `DefaultBloomFPRate` (1 in 1,000,000) — ~240 KB. Standard bloom filters
  can't remove elements, so `Remove` is a documented no-op; stale entries are
  cleared on the next `Rehydrate` (which rebuilds the filter from scratch), and
  a lingering entry only ever costs one extra DB lookup.
- `InMemoryRevocationFilter` (tests) — an exact map with real `Remove`, so
  tests get deterministic membership with no false positives.

**Verification pipeline (`oidc.JWTVerifier.Verify`)** — bound to invariant
`INV-EMERGENCY-REVOCATION`:

```
1. parse compact JWT
2. verify ES256 signature vs the signer's public key
3. reject if exp is past                       → ErrTokenExpired
4. filter.MightContain(jti)?                    (~100 ns, in-process)
     └─ hit → confirmRevocation(jti) via DB introspection
              confirmed → ErrTokenRevoked
              DB error  → fail closed (ErrTokenRevoked)
              not found → false positive, token valid
5. return VerifiedClaims
```

Step 4 fires the DB lookup only on a filter hit — roughly one introspection per
million verifications at the default FP rate. The DB checker is optional: with
no checker wired, a filter hit is treated as **fail-closed** (revoked), so a
misconfiguration errs toward safety.

**Endpoint (`POST /admin/revoke-jwt`)** — `Server.PostAdminRevokeJwt`:

1. Validates the body (`jti` required; `reason` ∈ {`emergency_kill`,
   `key_rotation`, `user_request`}; `expires_at` required). Body capped at 8 KB.
2. **Upserts** the JTI into `revoked_jtis` (the source of truth) — idempotent,
   so a client retry after a publish failure is safe.
3. `filter.Add(jti)` locally first, so the token is dead on this replica before
   the pub/sub round-trip completes.
4. Best-effort `publisher.Publish(revChannel, jti)` to fan the revocation out to
   sibling replicas. A publish failure is logged, not fatal — every replica
   re-derives its filter from `revoked_jtis` on startup, so a dropped message
   delays cross-replica convergence but never loses the revocation.

Returns `503` when revocation isn't configured (`revoked` store nil), so a
discovery-only deployment degrades cleanly.

**Schema (`0010_revoked_jtis`)** — `jti` PK, `revoked_at`, `reason` (CHECK
constrained to the three enum values), `expires_at` (the JWT's original `exp`,
indexed for nightly GC). Deliberately stores **no `user_id`** and **no region
column** — a `jti` is an opaque token identifier, not PII, and Harbor avoids
creating a queryable token→user mapping.

**Startup rehydration (`oidc.RehydrateFilter`)** — loads all non-expired JTIs
via an `ActiveJTILister` and repopulates the filter before the replica serves
traffic, so emergency revocations survive restarts. Fails open on a load error
(empty filter + logged error) rather than crashing — tokens still get checked
against the DB on any subsequent filter hit.

## Interfaces / Endpoints

- `POST /admin/revoke-jwt` → `200` `RevokeJwtResponse` (`Cache-Control:
  no-store`); `400` on invalid body; `401` without admin auth; `503` when
  unconfigured.
- Exported Go surface:
  - `oidc.RevocationFilter` + `BloomRevocationFilter` / `InMemoryRevocationFilter`;
    `DefaultBloomCapacity`, `DefaultBloomFPRate`.
  - `oidc.JWTVerifier` (`Verify`, `VerifyAccessToken`), `oidc.VerifiedClaims`,
    `oidc.JWTVerifierConfig`; errors `ErrTokenRevoked` / `ErrTokenExpired` /
    `ErrTokenInvalid`.
  - `oidc.RevokedJTIChecker` (+ `DBRevokedJTIChecker`, `NewNoopRevokedJTIChecker`).
  - `oidc.ActiveJTILister`, `oidc.RehydrateFilter`.
  - `oidcapi.RevokedJTIStore`, `oidcapi.RevocationPublisher`.
- Contract: `api/openapi/harbor.yaml` defines `/admin/revoke-jwt` +
  `RevokeJwt{Request,Response}` schemas.

## Code map

| Path | Role |
|---|---|
| `internal/oidc/revocation_filter.go` | `RevocationFilter` interface; bloom + in-memory impls; `RehydrateFilter`; `ActiveJTILister`. |
| `internal/oidc/jwt_verifier.go` | `JWTVerifier` — signature + expiry + bloom check with DB fallback; ES256 verify. |
| `internal/oidcapi/revoke_jwt.go` | `POST /admin/revoke-jwt` handler; validation; upsert + local Add + pub/sub. |
| `db/migrations/0010_revoked_jtis.{up,down}.sql` | `revoked_jtis` source-of-truth table + `expires_at` GC index. |
| `db/queries/revoked_jtis.sql` | Insert (upsert), ListActive (rehydrate), GetByJTI (confirm), GCExpired. |
| `internal/clients/revoked_jtis.go` | `DBRevokedJTIStore` — DB-backed store behind the store/checker interfaces. |
| `cmd/harbor-hot/main.go` | Filter init + startup rehydration + Redis subscriber wiring (DB path). |
| `api/openapi/harbor.yaml` | `/admin/revoke-jwt` + `RevokeJwt{Request,Response}` schemas. |

## Security & privacy invariants

- **`INV-EMERGENCY-REVOCATION`** — on `JWTVerifier.Verify`: a revoked `jti`
  (confirmed against the DB after a filter hit) is always rejected with
  `ErrTokenRevoked`.
- **Fail closed on uncertainty** — a DB error during confirmation is treated as
  revoked; a filter hit with no DB checker configured is treated as revoked.
  The system never lets a possibly-revoked token through on an error path.
- **No token→user mapping (§6.5)** — `revoked_jtis` stores no `user_id`; a `jti`
  is opaque, so the emergency-kill table cannot be mined to correlate tokens to
  users.
- **DB is the source of truth** — the filter is a cache; every replica
  rehydrates from `revoked_jtis`, so a lost pub/sub message never loses a
  revocation. Upsert makes the write idempotent under client retry.
- **Bounded admin input (§6.5)** — the revoke body is capped at 8 KB.
- **No PII in error messages** — insert failures return a generic message;
  details go to structured logs only.

## Tests

- `internal/oidc/` — bloom sizing/FP behaviour; `MightContain`/`Add`/`Rehydrate`;
  `JWTVerifier` accepts a valid token, rejects expired (`ErrTokenExpired`),
  tampered/bad-alg (`ErrTokenInvalid`), and revoked (`ErrTokenRevoked`);
  false-positive path (filter hit + DB miss → valid); fail-closed on DB error
  and on nil checker; `RehydrateFilter` restores active JTIs.
- `internal/oidcapi/revoke_jwt_test.go` — handler success (row inserted, filter
  updated, publish invoked), validation errors, `503` when unconfigured,
  single-replica (nil publisher) path.
- `internal/clients/revoked_jtis_test.go` — `Insert` upsert, `GetByJTI` found/
  not-found, `ListActive` excludes expired, `GCExpired` prunes.

## Known gaps / TODOs

- **`Remove` is a no-op on the production filter** — standard bloom filters
  can't delete; stale entries linger until the next `Rehydrate` and only cost an
  extra DB lookup. A counting bloom filter would enable true removal if the
  false-positive-lookup rate ever becomes material.
- **Redis pub/sub is best-effort** — cross-replica convergence within seconds
  depends on the publish landing; the durable guarantee is startup rehydration,
  so a replica that missed a live message only catches up on its next restart
  (or a periodic re-rehydrate, not yet scheduled).
- **GC is manual** — `GCExpired` exists but the nightly job that runs it is not
  yet wired.

## As-built note

Migration landed as `0010_revoked_jtis` (renumbered from the draft's `0005`,
then `0006`, to avoid colliding with `0006_recovery_required`). The
`POST /admin/revoke-jwt` handler lives on the OIDC surface
(`internal/oidcapi/revoke_jwt.go`) rather than a separate `harbor-mgmt` binary
as the draft proposed. Merged to `main` in PR #33.
