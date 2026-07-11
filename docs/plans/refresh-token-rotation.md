---
title: Refresh token rotation (§3.5 opaque, rotating, one-time-use)
status: draft
design_refs: [§3.5, §10]
targets: [internal/oidc/, internal/clients/, db/queries/]
promoted_to: null
openspec: changes/refresh-token-rotation
created: 2026-07-10
---

# Refresh token rotation (plan)

> **Dependency order:** depends on **`real-token-issuance`** (a refresh exchange
> mints a fresh access/ID token) and **`session-ppid-seam`** (the session is
> bound to a real user↔RP pairing). Build after both. This is the last piece of
> "The First Honest Token" milestone.

## Problem

The `sessions` table + its sqlc queries (`db/queries/sessions.sql`,
`GetActiveSession`/`CreateSession`/`RevokeSession`) exist and are
rotation-ready — but **nothing issues or rotates a refresh token**. Today
`/token` returns only an access + ID token; there is no long-lived, revocable
credential, so "log out everywhere" / "remove app" (§11.3, §3.5.3) and
theft-detection-by-rotation are impossible. §3.5's universal rule — *the
long-lived credential must be opaque and server-side, never a JWT* — is
unimplemented.

## Proposed approach

Implement §3.5's opaque, rotating, one-time-use refresh tokens over the existing
`sessions` table:

1. **Issue** (on `/token` code exchange, when `offline_access` scope is
   granted): generate an opaque CSPRNG refresh token; store **only its hash**
   (`refresh_token_hash`) in a new `sessions` row (region, user, device label,
   `expires_at`); return the plaintext token once in the token response.
2. **Rotate** (on `grant_type=refresh_token`): hash the presented token,
   `GetActiveSession`; if valid → **`RevokeSession`** (old) + **`CreateSession`**
   (new) in one transaction and mint a fresh access/ID token + new refresh
   token (single-use rotation).
3. **Reuse-detection / theft signal**: if a refresh token that is *already
   revoked* is presented, treat it as theft (§3.5, §11.7) — revoke the whole
   session family for that user↔RP pairing (`RevokeSessionsByUser` or a
   family-scoped revoke) and return `invalid_grant`. This mirrors the
   auth-code-reuse theft signal already in `service.go`.

All stores are per-region (§5), so rotation never crosses a jurisdiction.

## DESIGN alignment

Realizes §3.5 (short-lived JWT + opaque rotating refresh token; reuse-detection;
"revoke the ability to get a new one") and the `sessions` table in §10. Reuses
the theft-signal pattern already established for auth-code reuse (§11.7). Does
**not** change `DESIGN.md`.

## Target code paths

- `internal/oidc/refresh.go` — refresh grant handling + rotation + reuse-detection
- `internal/oidc/token.go` — extend `/token` to route `grant_type=refresh_token`
- `internal/clients/sessions.go` — sqlc-backed `SessionStore` over `sessions.sql`
- `api/openapi/harbor.yaml` — allow `grant_type=refresh_token` + `refresh_token` in the token response (regen)
- `cmd/harbor-hot/main.go` — wire the session store
- `internal/oidc/refresh_test.go`

## Implementation checklist

- [ ] Opaque refresh token: CSPRNG plaintext returned once; only the **hash** stored (never plaintext, §7.4).
- [ ] Issue a refresh token on code exchange when `offline_access` is granted; new `sessions` row (region populated).
- [ ] `grant_type=refresh_token` path: `GetActiveSession` → rotate (revoke old + create new) in a transaction → mint fresh tokens.
- [ ] Reuse-detection: presenting a revoked token fires the theft signal (family revoke) + `invalid_grant`.
- [ ] Extend the OpenAPI token contract; regenerate.
- [ ] Wire `SessionStore` into `cmd/harbor-hot/main.go`.
- [ ] Tests: rotation returns a *new* token and invalidates the old; **replaying the old token ⇒ theft signal + family revoke**; expired/revoked ⇒ `invalid_grant`; hash-at-rest (no plaintext in DB); region populated.
- [ ] Author & verify paired OpenSpec change: `openspec validate refresh-token-rotation --strict`
- [ ] Reconcile & promote: `@plan promote refresh-token-rotation`

## Risks & open questions

- **Rotation atomicity**: revoke-old + create-new must be a single transaction or a crash mid-rotation could lock the user out or leave two live tokens — use one tx and test the race.
- **Family scope** for the theft revoke: revoke per user↔RP session family (not all of the user's sessions) unless policy says otherwise — decide and document.
- Refresh tokens are only issued when `offline_access` is consented — confirm the scope gate matches the grant recorded by `session-ppid-seam`.

## Definition of done

`go build/vet/test ./...` green; `/token` issues an opaque, hashed-at-rest
refresh token on code exchange; `grant_type=refresh_token` rotates it one-time
(revoke old, create new) and mints fresh tokens; replaying a rotated token fires
the theft signal and revokes the family; no plaintext refresh token is ever
stored; `make agent-check` clean. Ready to `@plan promote`.
