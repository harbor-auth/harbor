# Design: Refresh token rotation (§3.5)

## Key Decisions

### Decision 1: SHA-256 hash at rest, never plaintext
**Chosen:** Hash the plaintext token with SHA-256; store only the hash.
**Rationale:** §7.4 / §10 — a plaintext credential in the DB is a direct breach
vector; one-way hash means a DB read gives nothing usable. SHA-256 is fine
here (collision resistance not required; second-preimage resistance is).
**Alternatives considered:** Bcrypt/Argon2 (adds latency to the refresh-token
check; unnecessary here since the token is already 256-bit CSPRNG — no
dictionary attack surface, rejected).

### Decision 2: Rotation inside a single DB transaction
**Chosen:** `RevokeSession(old)` + `CreateSession(new)` in one transaction.
**Rationale:** Atomicity removes the window where both old and new are valid
(double-spend) or neither exists (lock-out). The transaction also makes the
race visible: a concurrent identical rotation will see a conflict and surface as
reuse detection.
**Alternatives considered:** Best-effort sequential revoke+create (partial
failure modes, rejected).

### Decision 3: Reuse signal = full-user session revoke (not scoped to RP)
**Chosen:** A revoked token being presented => `RevokeSessionsByUser(userID)` —
revokes ALL sessions for the user, not just the current client.
**Rationale:** §3.5/§11.7 theft model: if a refresh token is replayed, the
user's credential set is considered compromised. Scoping revocation to a single
(user, client) pair would require a `client_id` column on the sessions table
(not present in the current schema). Full-user revocation is the safe,
conservative choice that matches the "sign out everywhere" guarantee a user
expects when their session is stolen. Mirrors the auth-code-reuse signal in
`service.go`.
**Trade-off accepted:** A theft signal from one RP revokes all sessions,
including other RPs. This is intentional — in a theft scenario, we prefer
disrupting the user over leaving the thief with active sessions. The user can
immediately re-authenticate.
**Alternatives considered:** (user, client) scoped revocation — requires adding
`client_id` to the sessions table + a new `RevokeSessionsByUserAndClient` query;
deferred as a follow-up if the UX trade-off is deemed too broad. No revoke
(leaves the thief with an active session — rejected).

### Decision 4: `SessionStore` as a new seam over existing sqlc queries
**Chosen:** Add `oidc.SessionStore` backed by `sessions.sql`; no new queries.
**Rationale:** The queries already exist (`GetActiveSession`, `CreateSession`,
`RevokeSession`, `RevokeSessionsByUser`). Adding a Go seam keeps the flow
package DB-agnostic (same pattern as `ClientRegistry`/`GrantStore`).

### Decision 5: Extend the OpenAPI contract before implementing
**Chosen:** Add `refresh_token` + `refresh_token_expires_in` to the token
response schema and `grant_type=refresh_token` to the token endpoint; regenerate.
**Rationale:** §1.2 — spec is the source of truth; the `ServerInterface`
assertion stops the spec outrunning the server.
