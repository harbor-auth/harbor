# Design: Token introspection (RFC 7662 — POST /introspect)

## Key Decisions

### Decision 1: Serve /introspect on harbor-hot, not harbor-mgmt

**Chosen:** Register `POST /introspect` on the hot-path router
(`cmd/harbor-hot`), alongside `/token`, `/jwks.json`, and `/userinfo`.

**Rationale:** Introspection is a per-request operation for RPs that can't
verify tokens locally — potentially called on *every* API request they serve.
It shares the hot path's latency SLA, its telemetry labeling
(`telemetry.EndpointIntrospect` already exists), and its rate-limiting story
(the `rate-limiting` plan already scopes `/introspect` as a protected hot
endpoint). The management surface has different SLA guarantees and would make
introspection a de-facto availability dependency on mgmt.

**Alternatives considered:** harbor-mgmt (rejected: wrong SLA class; also
couples RP request paths to the admin surface); a dedicated verifier service
(rejected: premature — the stateless JWT path means introspection adds almost
no load to harbor-hot).

### Decision 2: Stateless-first verification with bloom-gated DB confirmation

**Chosen:** For JWT access tokens: verify signature against the configured
signers (same keys published at `/jwks.json`), check `exp`, then consult the
in-process `oidc.RevocationFilter`. Filter miss ⇒ definitely not revoked ⇒
`active: true` with **zero DB hits**. Filter hit ⇒ confirm via
`RevokedJTIChecker` (the `revoked_jtis` table) before deciding.

**Rationale:** This mirrors the existing `internal/oidc/jwt_verifier.go`
pipeline exactly (steps: signature → expiry → filter → DB confirm), reusing
the invariant that bloom filters admit false positives but never false
negatives. Keeping the common case DB-free preserves the hot path's stateless
guarantee, and reusing the verifier pipeline means one revocation semantics,
not two.

**Alternatives considered:** DB lookup on every introspection (rejected: turns
a stateless surface into a per-request DB hit and defeats the point of JWT
access tokens); trusting the filter without DB confirmation (rejected: false
positives would wrongly report valid tokens as inactive — the exact failure
this endpoint exists to prevent).

### Decision 3: Introspection logic lives in internal/oidc.Service; the handler stays thin

**Chosen:** Add `Introspect(ctx, token, clientID string) (IntrospectionResult,
error)` to `internal/oidc.Service`. `internal/oidcapi/introspect.go` only
authenticates the caller, parses the form, delegates, and serializes.

**Rationale:** Matches the existing layering (`PostToken` → `svc.Token`,
`GetAuthorize` → `svc.Authorize`): domain logic in `internal/oidc`, transport
in `internal/oidcapi`. The service already owns the session store, signers,
and revocation seams needed. `IntrospectionResult` carries `Active` plus the
RFC 7662 claims so the handler does no token parsing of its own.

**Alternatives considered:** Implementing verification inline in the handler
(rejected: duplicates `jwt_verifier` logic and violates the package
boundaries); a standalone `Introspector` type (rejected: it would need the
same five dependencies `Service` already holds).

### Decision 4: All negative outcomes collapse to `200 {"active": false}`

**Chosen:** Expired, tampered, revoked, unknown, malformed, and
wrong-audience tokens all return HTTP 200 with `{ "active": false }`. Only
caller-authentication failure gets a distinct status (`401`).

**Rationale:** RFC 7662 §2.2 and §4: distinguishing *why* a token is inactive
leaks information. In particular, cross-client probes (client B introspecting
client A's token) must be indistinguishable from probing a random string —
returning `403` would confirm the token exists and belongs to someone. This
matches Harbor's existing enumeration-resistance posture (e.g. the WebAuthn
handler collapsing `ErrUserNotFound` into `invalid_request`).

**Alternatives considered:** `403` for audience mismatch (rejected: existence
oracle); `400` for malformed tokens (rejected for the token param — RFC 7662
prescribes `active: false`; `400` is reserved for a missing `token`
parameter).

### Decision 5: Caller authentication — Basic client credential or admin Bearer, never anonymous

**Chosen:** The handler accepts (a) `Authorization: Basic` with a registered
`client_id:client_secret`, scoping results to that client's tokens, or (b) an
admin-scoped Bearer token, which may introspect any token. Anything else is
`401` with `WWW-Authenticate: Basic`.

**Rationale:** RFC 7662 §2.1 requires caller authentication to prevent token
scanning/enumeration. The two-tier model gives RPs self-service validation of
their own tokens while keeping an audit/support path (admin) that crosses
client boundaries deliberately and visibly.

**Alternatives considered:** mTLS client auth (deferred — no mTLS
infrastructure yet; the seam allows adding it later); allowing any
authenticated client to introspect any token (rejected: cross-client token
metadata leak, violates the pairwise-sub privacy model).

### Decision 6: Refresh tokens resolved via the session store

**Chosen:** If the token doesn't parse as a JWT (or `token_type_hint=refresh_token`
short-circuits the order), look it up in the session store and derive
`active` from `revoked_at` / `expires_at`, returning the session's client and
expiry metadata.

**Rationale:** Refresh tokens are stateful by design (rotation + theft
detection already live in `Service.Refresh`); the session row *is* the source
of truth. `token_type_hint` is an optimization only — per RFC 7662, a wrong
hint must not change the outcome, so the fallback tries the other type.

**Alternatives considered:** Refusing refresh-token introspection (rejected:
RFC 7662 covers both types and RPs legitimately check refresh token liveness
before long-running jobs).

### Decision 7: No new migrations or schema changes

**Chosen:** Reuse the existing sessions table and `revoked_jtis` table
(`GetRevokedJTI` query already exists for exactly this fallback).

**Rationale:** Every datum introspection needs is already persisted; the
generated querier even documents `GetRevokedJTI` as the "introspection
fallback." Adding tables would duplicate state and create sync bugs.

**Alternatives considered:** An introspection audit table (deferred to
observability work — telemetry counters cover the immediate need).
