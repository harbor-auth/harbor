# Proposal: User creation & enrollment (§11.1 signup flow)

## Problem

There is no real signup. `internal/webauthn` runs correct passkey ceremonies but
reads `user_id` from an insecure dev-only query param — no `users` row is
created, no home region assigned, no `pairwise_secret`/DEK generated. Without
enrollment there is no user to log in and no `pairwise_secret` for PPID
derivation (§3.2).

## Proposed Solution

Implement the DESIGN §11.1 enrollment sequence in the management plane:

1. Choose a home region; encode it into the user id (§3.4, §5).
2. Create the `users` row with `region`, `status='active'`, a CSPRNG
   `pairwise_secret` (encrypted under a fresh DEK), and `dek_wrapped` (the DEK
   wrapped by the regional KEK via `envelope-encryption-kms`).
3. Register the first passkey via the existing WebAuthn ceremony, keyed off the
   real `users.id`, persisted to the `credentials` table.
4. Record the recovery-setup requirement (≥2 methods; §7.2 — codes now, social
   recovery deferred).
5. Delete the insecure dev-only `user_id` query-param path.

## Non-Goals

- Full account-recovery UX incl. social guardians (§7.2 — later plan).
- The hosted signup UI (programmatic/management endpoint is enough for v1).
- PPID derivation at login (that's `session-ppid-seam`).

## Success Criteria

- [ ] Signup creates exactly one region-encoded `users` row with a wrapped DEK + encrypted `pairwise_secret`.
- [ ] The first passkey persists to the `credentials` table, keyed off the real `users.id`.
- [ ] Enrollment is transactional (no half-enrolled accounts).
- [ ] The insecure dev-only `user_id` path is removed.
- [ ] `make agent-check` clean.
