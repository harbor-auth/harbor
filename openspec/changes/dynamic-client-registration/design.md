# Design: Dynamic client registration (RFC 7591 / 7592)

## Key Decisions

### Decision 1: A distinct per-client `registration_access_token` for 7592
**Chosen:** Registration mints a dedicated `registration_access_token`, scoped
to exactly one `client_id`, that authorises the 7592 GET/PUT/DELETE management
operations — separate from the client's own `client_secret`.
**Rationale:** RFC 7592 mandates it, and it gives client credentials and
configuration-management credentials **independent blast radii**: leaking one
does not compromise the other. It also lets management authz be a simple
per-client token check.
**Alternatives considered:** Reuse the `client_secret` to authorise management
(rejected — couples the two credentials, non-conformant); use an org-admin
credential for all clients (rejected — one leaked credential manages every
client).

### Decision 2: Secrets and reg-tokens are hashed at rest, shown once
**Chosen:** Store `client_secret` and `registration_access_token` **hashed
only**; return plaintext exactly once at creation (and, if `PUT` rotates,
again once at rotation).
**Rationale:** A registry breach must not yield usable client credentials.
Show-once is the standard secret-issuance discipline; hashed-at-rest with a
constant-time verify closes the offline-cracking and timing surfaces.
**Alternatives considered:** Store plaintext for later retrieval (rejected —
turns the registry into a credential trove); encrypt-at-rest reversibly
(rejected — a verify never needs the plaintext, so a one-way hash is safer).

### Decision 3: Cold-path placement on `harbor-mgmt`
**Chosen:** All four operations live on `harbor-mgmt`, next to enrolment, not on
`harbor-hot`.
**Rationale:** Registration is a rare administrative write; it must not share
the stateless, edge-cacheable hot path or contend with the hot-path router
chain. Sovereignty: registration is regional, with no global client lookup.
**Alternatives considered:** Put `/register` on `harbor-hot` (rejected — pollutes
the hot path with a stateful admin write); a separate microservice (rejected —
unnecessary; harbor-mgmt already owns cold-path admin surfaces).

### Decision 4: Strict metadata validation (redirect-URI is security-critical)
**Chosen:** Validate submitted metadata strictly — exact-match redirect-URI
registration, https-only except loopback, no wildcards; enforce allowed
grant/response types and `token_endpoint_auth_method`.
**Rationale:** Redirect-URI handling is the classic open-redirect / SSRF /
token-exfiltration surface in OAuth; strict, exact-match validation at
registration is the primary defence. Invalid metadata → `400
invalid_client_metadata`.
**Alternatives considered:** Permissive/wildcard redirect URIs (rejected —
open-redirect and token-leak risk); validate lazily at authorize time (rejected
— a bad client should never persist).

### Decision 5: Gated-by-default open registration
**Chosen:** Support an optional, configurable **initial access token**
requirement on `POST /register`; recommend gating by default.
**Rationale:** Anonymous `POST /register` is a spam/DoS vector that would let
anyone mint clients. An initial-access-token gate makes registration deliberate
while still allowing an operator to open it if desired.
**Alternatives considered:** Always-open registration (rejected — anonymous
client-spam); admin-only manual creation (rejected — defeats the self-service
goal this change exists to deliver).
