# Design: Token revocation endpoint (RFC 7009 — POST /revoke)

## Key Decisions

### Decision 1: Uniform 200 empty response (anti-enumeration)
**Chosen:** Every well-formed, authenticated request returns `200` with an empty
body — including unknown, expired, already-revoked, and cross-client tokens.
Only malformed requests (`400 invalid_request`) and unauthenticated callers
(`401`) deviate.
**Rationale:** RFC 7009 §2.2 mandates this, and it is a security control: a
distinguishing status/body for known vs unknown tokens would be a
token-enumeration oracle. Uniformity denies the caller any signal.
**Alternatives considered:** `404`/`400` for unknown tokens (violates RFC 7009,
re-introduces the oracle — rejected); `403` for cross-client tokens (leaks that
the token exists under another client — rejected).

### Decision 2: Reuse the shipped revocation stack (don't re-mechanise)
**Chosen:** `/revoke` feeds the existing `revocation-outbox` → `revoked_jtis`
(access tokens) and the session/grant store `revoked_at` via `grant-id-fk`
(refresh tokens); the bloom filter and `/introspect` then enforce.
**Rationale:** The durable, replica-safe revocation path already exists; the
endpoint should be a thin contract over it, not a parallel mechanism. This keeps
recording and enforcement consistent across the internal and external paths.
**Alternatives considered:** Synchronously delete state inline in the handler
(bypasses the durable outbox, risks partial/replica-inconsistent revocation —
rejected).

### Decision 3: Hot-path placement, behind the rate limiter
**Chosen:** `/revoke` lives on `harbor-hot` (`internal/oidcapi/`) next to
`/token` and `/introspect`, registered **behind the rate-limiter middleware**.
**Rationale:** RFC 7009 is a client-facing OAuth endpoint RPs call directly; it
reuses the hot-path client-auth and router middleware. As an abuse-sensitive
write/enumeration surface it must be throttled — hence the hard ordering after
`rate-limiting`.
**Alternatives considered:** Put it on `harbor-mgmt` (wrong SLA/audience,
duplicate client-auth — rejected); leave it unthrottled (enumeration/DoS vector
— rejected).

### Decision 4: `token_type_hint` is advisory
**Chosen:** Treat `token_type_hint` as a hint — try the hinted store first, fall
back to the other on a miss.
**Rationale:** RFC 7009 §2.1 defines the hint as advisory; a wrong hint must
never cause a missed revocation. Trying both guarantees correctness.
**Alternatives considered:** Trust the hint strictly and skip the other store
(a wrong/malicious hint would leave a token live — rejected).

### Decision 5: Access-token revocation is eventually-consistent
**Chosen:** `/revoke` records the JTI durably immediately; hot-path enforcement
(bloom filter / edge caches) converges asynchronously.
**Rationale:** This is the same convergence window `bloom-filter-revocation`
already accepts to keep verification DB-free (§4.1). The endpoint's contract is
"recorded", not "instantly enforced everywhere"; refresh-token revocation is
immediate because it is a store write consulted on refresh.
**Alternatives considered:** Block until global convergence (couples `/revoke`
latency to cache propagation, breaks the stateless hot path — rejected).
