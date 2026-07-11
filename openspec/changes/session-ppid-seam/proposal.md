# Proposal: Session seam — login → PPID → token subject

## Problem

`internal/oidc/service.go` uses `stubSessionResolver`, which auto-approves a
fixed demo subject (`demo-subject-ppid`). `internal/identity.DerivePPID` is real
and tested but **never called on the hot path**. So `/authorize` issues codes
for a hardcoded fake subject — no real user logs in, and the per-RP pairwise
`sub` guarantee (§3.2) is bypassed entirely.

## Proposed Solution

Replace `stubSessionResolver` with a real `SessionResolver` that:

1. Authenticates the user via `webauthn.FinishLogin` (real `users.id`).
2. Loads + decrypts the user's `pairwise_secret` (via the user DEK).
3. Looks up the RP's `sector_id` from the DB-backed registry.
4. Derives `sub = DerivePPID(pairwise_secret, sector_id, user_id)` (§3.2).
5. Finds-or-creates the consent grant (`GrantStore`), skipping the consent
   screen when scopes are already granted.
6. Returns `(sub, approved)` — flowing the real PPID through the unchanged
   `/authorize` → `/token` path into the token `sub`.

## Non-Goals

- The full hosted login/consent UI (a minimal/programmatic consent step is
  enough for v1; the UI is a follow-up).
- Refresh tokens (owned by `refresh-token-rotation`).

## Success Criteria

- [ ] `/authorize` issues codes bound to a real, per-RP PPID from the authenticated user.
- [ ] Same user + same RP ⇒ stable `sub`; same user + different sector ⇒ different `sub` (unlinkability).
- [ ] Consent persists once via `GrantStore`; rejection ⇒ `access_denied`.
- [ ] `pairwise_secret` never appears in logs or tokens; errors fail closed (never fall back to raw `user_id`).
- [ ] `make agent-check` clean.
