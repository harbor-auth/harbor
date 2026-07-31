---
title: Wire the emergency-revocation pipeline into harbor-hot
status: draft
design_refs: [§3.5, §7.4]
targets: [cmd/harbor-hot/, internal/oidc/, internal/clients/, db/queries/]
promoted_to: null
openspec: changes/wire-revocation-pipeline
created: 2026-07-30
---

# Wire the emergency-revocation pipeline (plan)

> **Severity: HIGH.** Audit finding H3 —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).
> DAG child of `production-wiring-collapse`.
>
> **Hard prerequisite:** [`admin-endpoint-auth`](./admin-endpoint-auth.md) must
> be on `main` first. See *Risks* — wiring the filter before the admin endpoint
> is authenticated converts a dead feature into a fleet-wide kill switch.
>
> **Scope boundary:** RP-initiated logout wiring is
> [`end-session-logout`](./end-session-logout.md). This plan is the revocation
> data plane only.

## Problem

[`bloom-filter-revocation`](./bloom-filter-revocation.md) is marked
**`promoted`** — its library landed and a feature doc was written. But the
components are **never instantiated anywhere**:

| Component | File | Wired? |
|---|---|---|
| `BloomRevocationFilter` | `oidc/revocation_filter.go:135` | ❌ never |
| `DBRevokedJTIStore` | `clients/revoked_jtis.go:43` | ❌ never |
| `RevocationWorker` | `oidc/worker.go:47` | ❌ never |
| `RevocationSubscriber` | `clients/revocation_subscriber.go:55` | ❌ never |
| `DBRevocationOutbox` | `clients/revocation_outbox.go:72` | ❌ never |
| `RehydrateFilter` | `oidc/revocation_filter.go:228` | ❌ never |

Consequences in production today:

- `s.revoked == nil` → `POST /admin/revoke-jwt` returns **503**. The emergency
  kill switch does not exist.
- `s.filter == nil` → `Introspect` (`introspect.go:208`) and `JWTVerifier.Verify`
  (`jwt_verifier.go:187`) **skip the revocation check entirely**.
- The transactional outbox that `signalRefreshReuse` and `signalCodeReuse`
  carefully write to (`oidc/service.go:875,948`) is `noopRevocationOutbox` — so
  the refresh-token **theft signal is silently discarded**. The most
  security-critical path in the token lifecycle logs its intent and drops it.

This is also a documentation-integrity finding: a plan marked `promoted` whose
code is unreachable from `main()` is exactly the failure `.agents/plan.md`
documents under *The merged gate*.

## Proposed approach

Wire all five pieces **together**. Partial wiring is worse than none — see Risks.

1. **`RevokedJTIStore`** ← `clients.NewDBRevokedJTIStore(q)`. The `revoked_jtis`
   table (migration 0010) is the source of truth.
2. **`RevocationFilter`** ← `oidc.NewBloomRevocationFilter(capacity, fpRate)`,
   both from config with documented defaults, **rehydrated from `revoked_jtis`
   via `RehydrateFilter` before the listener binds**. A replica that starts
   serving with a cold filter honours no revocations.
3. **`RevokedJTIChecker`** ← the same DB store. **Non-nil is mandatory** — see
   the fail-closed hazard in Risks.
4. **`RevocationPublisher` / `RevocationSubscriber`** ← thin adapters over the
   existing Redis client on `defaultRevocationChannel`, so a revocation reaches
   sibling replicas in one round-trip instead of waiting for the next restart.
   The subscriber needs defined reconnect behaviour on a dropped Redis
   connection — a silently dead subscriber is a silently stale filter.
5. **`RevocationOutbox`** ← `clients.NewDBRevocationOutbox(q, logger)`, and run
   `oidc.NewRevocationWorker` as a goroutine bound to the root context so theft
   signals are durably delivered and retried, and drained on SIGTERM.

**GC.** Migration 0010's own comment calls for
`DELETE FROM revoked_jtis WHERE expires_at < now()` "run nightly"; nothing
implements it. A never-pruned table means a monotonically growing filter, which
means a rising false-positive rate — the fail-closed hazard reached slowly rather
than suddenly. Add the query and a scheduled sweep.

## DESIGN alignment

Serves §3.5 (the revocation model: short TTLs + opaque refresh + an emergency
kill for the exceptional case) and §7.4 (emergency kill switch). No DESIGN
change — this connects a story the design already tells and the library already
implements.

## Target code paths

- `cmd/harbor-hot/main.go` — construct store, filter, checker, publisher, subscriber, outbox; run the worker; rehydrate before bind
- `internal/oidc/worker.go` — confirm shutdown semantics against the root context
- `internal/clients/revocation_subscriber.go` — confirm/​add reconnect behaviour
- `db/queries/revoked_jtis.sql` — GC query (no migration; the `expires_at` index exists)

## Implementation checklist

- [ ] Wire `RevokedJTIStore`, bloom `RevocationFilter`, **non-nil `RevokedJTIChecker`**, publisher, subscriber, outbox
- [ ] `RehydrateFilter` from `revoked_jtis` **before** the HTTP listener binds
- [ ] Run `RevocationWorker` on the root context; drain cleanly on SIGTERM
- [ ] Subscriber reconnects on a dropped Redis connection; failure is logged and metered, never silent
- [ ] Add the `revoked_jtis` GC query and schedule the sweep
- [ ] Remove `noopRevocationOutbox` from the `main` wiring
- [ ] Config: bloom capacity + false-positive rate, with the sizing arithmetic documented in the feature doc
- [ ] Tests: a revoked JTI is rejected at `/introspect` on the same replica
- [ ] Tests: and on a **sibling** replica, via pub/sub
- [ ] Tests: the filter is correctly rehydrated after a restart
- [ ] Tests: **a bloom false positive with a non-nil checker leaves the token valid** — the fail-closed hazard's regression test
- [ ] Tests: the outbox worker retries a revocation whose inline attempt failed
- [ ] Tests: refresh-token reuse actually revokes the (user, client) family end-to-end
- [ ] Author & verify paired OpenSpec change: `@openspec new wire-revocation-pipeline` then `openspec validate wire-revocation-pipeline --strict`
- [ ] Reconcile & promote: `@plan promote wire-revocation-pipeline`

## Risks & open questions

- **Ordering is load-bearing and non-negotiable.** `admin-endpoint-auth` must be
  verifiably on `origin/main` — not on a working branch — before the filter goes
  live. Today `/admin/revoke-jwt` is harmless because it 503s. The moment the
  store is wired it becomes an unauthenticated, fleet-wide token kill switch
  (audit finding C2).
- **The fail-closed amplification hazard.** With a nil `RevokedChecker`,
  `confirmRevocation` returns `true` for *any* bloom hit
  (`introspect.go:263-266`, `jwt_verifier.go:236-239`). An attacker who can
  reach the admin endpoint could then flood arbitrary JTIs, saturate the filter,
  and fail-close the entire fleet. Wiring the checker non-nil is what makes a
  false positive cost one DB lookup instead of an outage. **Do not ship the
  filter without the checker.**
- **Do not change the nil-checker default to fail-open.** With the checker wired
  the branch is unreachable; keep the conservative default and add the test so a
  future nil-wiring regression is caught rather than silently tolerated.
- **Bloom sizing needs a real number**, derived from expected revocations per
  retention window. Document the arithmetic; make both parameters configurable.
- Also correct [`bloom-filter-revocation`](./bloom-filter-revocation.md)'s
  `promoted` status — its code is not reachable from `main()`.

## Definition of done

- A revoked JTI is dead on every replica within one pub/sub round-trip, and stays
  dead across a restart.
- Refresh-token reuse durably revokes the session family via the outbox.
- No noop revocation path is reachable from `main()`.
- `revoked_jtis` is pruned on a schedule.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check` green.
