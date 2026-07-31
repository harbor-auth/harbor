---
title: One token-verification core — kid selection, expiry, issuer coherence
status: draft
design_refs: [§3.3, §3.5, §7.3, §11.7]
targets: [internal/oidc/, internal/oidcapi/]
promoted_to: null
openspec: changes/unify-token-verification
created: 2026-07-30
---

# One token-verification core (plan)

> **Severity: HIGH.** Audit findings H4 and H5 —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).
> DAG child of `production-wiring-collapse`.
>
> **Scope boundary:** *client* authentication (who is calling `/introspect`
> and `/revoke`) belongs to [`client-secret-auth`](./client-secret-auth.md).
> This plan is about *token* verification (is this token valid). The two land
> in adjacent files — coordinate, expect a rebase.

## Problem

Harbor has **three independent JWT verification implementations that disagree**:

| Path | `kid` selection | `exp` | `iss` | Revocation |
|---|---|---|---|---|
| `oidcapi/userinfo.go` `verifyAccessToken` | ✅ `publicKeyByKID` | ❌ **never** | ✅ | ❌ |
| `oidc/introspect.go` `Introspector` | ✅ `publicKeyByKID` | ✅ | ❌ **never** | ✅ |
| `oidc/jwt_verifier.go` `JWTVerifier` | ❌ **single key** | ✅ | ✅ | ✅ |

Each is individually reasonable; collectively they mean a token's validity
depends on which endpoint you ask.

### H4 — `/userinfo` accepts expired access tokens forever

`internal/oidcapi/userinfo.go:95-97` states it outright: *"It does NOT check
expiry — token TTLs are short-lived and the conformance surface exercises
freshly-minted tokens."* There is no `exp` check and no revocation check. A token
leaked from a log line, a proxy cache, or a browser history works at `/userinfo`
for the lifetime of the signing key.

This directly contradicts the design's central revocation claim — that short TTLs
plus opaque refresh tokens *are* the revocation story (§3.5). If one endpoint
ignores TTL, that story does not hold.

### H5 — `JWTVerifier` holds one key and ignores `kid`

`internal/oidc/jwt_verifier.go:98-106` extracts a **single** `pubKey` from
`cfg.Signer`. `Verify` reads `h.Kid` only to check `alg` (`:148`), never to
select a key. So during any rotation overlap — the precise window that the whole
`signing_keys` pending→active→retired state machine (migration 0008,
`crypto/rotator.go`) exists to provide — tokens signed by the non-active key
**fail to verify**.

The other two paths already do this correctly. `JWTVerifier` is the one used for
`id_token_hint` at logout, so the practical effect is that logout breaks for
anyone holding a token from before the last rotation.

### Issuer coherence is enforced in two places out of three

`Introspector.Introspect` never checks `iss`, so a token minted on
`eu.harbor.id` introspects successfully on `us.harbor.id` — the exact
cross-region acceptance that `ErrIssuerMismatch` was written to prevent
(`jwt_verifier.go:28-33`, OpenSpec `regional-data-residency-routing` REQ-001/002).

## Proposed approach

Extract **one** `oidc.TokenVerifier` owning the whole pipeline, and delete the
other two:

```
parse → alg check → kid-selected key → signature → exp → iss → revocation
```

- Config takes `Signers []crypto.Signer` (not one `Signer`) and selects by `kid`,
  adopting the shape `Introspector.publicKeyByKID` already uses.
- Options struct for the one legitimate deviation: `SkipExpiry` for
  `id_token_hint` at `/end_session`, which OIDC RP-Initiated Logout 1.0
  explicitly permits (users must be able to log out with an expired token). That
  is the *only* sanctioned exception, and it should be named as such in the type
  rather than achieved by a separate code path.
- `iss` and revocation are enforced on every path, with no exception.
- Repoint `/userinfo`, `/introspect`, `/revoke`, and `/end_session` at it.

The win is not just correctness: three implementations is why the divergence went
unnoticed, and one implementation is why it will not recur.

### Rejected alternative

*Fix each of the three in place.* Rejected — it preserves the structure that
produced the bug. The next claim added (say, `nbf`, or an audience check) would
again land in one or two of three.

## DESIGN alignment

Serves §3.3 (token format and verification), §3.5 (short-TTL revocation model —
which requires TTL actually to be checked), §7.3 (rotation overlap must verify),
§11.7 (uniform, non-enumerable rejection). No DESIGN change: this makes three
implementations agree with the one design.

## Target code paths

- `internal/oidc/jwt_verifier.go` — becomes the single core; multi-signer + kid selection
- `internal/oidc/introspect.go` — delegates; gains the `iss` check
- `internal/oidcapi/userinfo.go` — delegates; gains `exp` + revocation; `publicKeyByKID` deleted
- `internal/oidcapi/end_session.go` — delegates with `SkipExpiry`
- `internal/oidcapi/revoke.go` — delegates

## Implementation checklist

- [ ] `TokenVerifier` over `[]crypto.Signer` with `kid` selection
- [ ] Single pipeline: alg → key → signature → `exp` → `iss` → revocation
- [ ] `SkipExpiry` option, used **only** by the `id_token_hint` logout path
- [ ] Repoint all four callers; delete the two duplicate implementations
- [ ] Tests: **expired access token is rejected at `/userinfo`** — H4's regression test; it passes today
- [ ] Tests: a token signed by a *pending/overlapping* kid verifies on every path — H5's regression test
- [ ] Tests: a token signed by a *retired* kid is rejected on every path
- [ ] Tests: cross-region `iss` rejected at `/introspect` (currently accepted)
- [ ] Tests: a revoked JTI is rejected at `/userinfo` (currently unchecked)
- [ ] Tests: `/end_session` still accepts an expired `id_token_hint`
- [ ] Tests: a table-driven matrix asserting all four endpoints agree on the same token
- [ ] Author & verify paired OpenSpec change: `@openspec new unify-token-verification` then `openspec validate unify-token-verification --strict`
- [ ] Reconcile & promote: `@plan promote unify-token-verification`

## Risks & open questions

- **`/userinfo` gaining an expiry check is a behaviour change** that will start
  rejecting tokens some RP may be relying on. It is a correction, not a
  regression — call it out in the PR description.
- **Revocation checking depends on the filter being live**
  ([`wire-revocation-pipeline`](./wire-revocation-pipeline.md)). Until that
  lands, the revocation step is a no-op with a nil filter. Build the seam; do
  not block on it.
- Coordinate with [`client-secret-auth`](./client-secret-auth.md) and
  [`end-session-logout`](./end-session-logout.md) — all three touch
  `internal/oidcapi/`. Sequence within the wave if conflicts bite.
- No migration in this feature.

## Definition of done

- Exactly one JWT verification implementation exists.
- All four endpoints agree on `alg`, `kid`, `exp`, `iss` and revocation, proven
  by a shared table-driven test.
- Rotation overlap verifies; retired keys do not.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check` green.
