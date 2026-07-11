# Proposal: Refresh token rotation (§3.5 opaque, rotating, one-time-use)

## Problem

The `sessions` table + its sqlc queries (`sessions.sql`: `GetActiveSession`,
`CreateSession`, `RevokeSession`) exist and are rotation-ready — but nothing issues
or rotates a refresh token. `/token` returns only an access + ID token; there is no
long-lived, revocable credential, so "log out everywhere" and theft-detection-by-rotation
(§3.5) are impossible. §3.5's universal rule — the long-lived credential must be
opaque and server-side, never a JWT — is unimplemented.

## Proposed Solution

- Issue an opaque CSPRNG refresh token on `/token` code exchange when `offline_access`
  is granted; store only its hash (`refresh_token_hash`) in a new `sessions` row.
- On `grant_type=refresh_token`: hash the presented token, `GetActiveSession` (filters
  revoked/expired), rotate atomically (`RevokeSession` old + `CreateSession` new in
  one transaction), mint fresh tokens.
- Reuse detection: a revoked-but-known token fires the theft signal (revoke the
  session family for that user<>RP) and returns `invalid_grant`, mirroring the
  auth-code-reuse pattern already in `service.go`.

## Non-Goals

- Opaque access tokens + introspection (per-RP opt-in; §3.3 — later).
- Revocation bloom filter (§3.5.2 — later).
- `RevokeSessionsByUser` UI/dashboard endpoint (the sqlc query exists; the handler is a follow-up).

## Success Criteria

- [ ] `/token` issues an opaque, hashed-at-rest refresh token on code exchange (when `offline_access` granted).
- [ ] `grant_type=refresh_token` rotates it one-time and mints fresh tokens.
- [ ] Replaying a rotated token fires the theft signal and revokes the session family.
- [ ] No plaintext refresh token is ever stored; region populated on every sessions row.
- [ ] `make agent-check` clean.
