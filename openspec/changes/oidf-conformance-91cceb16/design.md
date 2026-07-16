# Design: OIDF OP Conformance Suite Compliance

## Key Decisions

### Decision 1: Thread auth_time from Authorize through Token issuance
**Chosen:** Capture `s.now()` at session creation in `Authorize()`, store in
`AuthCode.AuthTime`, propagate through `Token()` and `Refresh()` to `IssueParams`.
**Rationale:** OIDC Core §2 requires `auth_time` to reflect when the user
actually authenticated, not when the token was issued. The value must survive
code exchange and refresh rotation.
**Alternatives considered:** Using token issuance time (incorrect per spec).

### Decision 2: Generate unique jti per token
**Chosen:** Generate a random 256-bit `jti` (via `crypto/rand`) for each id_token
and access_token independently.
**Rationale:** RFC 7519 §4.1.7 — `jti` prevents replay attacks. Each token must
have its own unique identifier; id_token and access_token cannot share one.
**Alternatives considered:** UUID (larger, no security benefit over raw random).

### Decision 3: azp equals client_id when aud is single-valued
**Chosen:** Set `azp` claim equal to `client_id` in all id_tokens.
**Rationale:** OIDC Core §2 — `azp` is optional but checked by OIDF suite. When
`aud` contains a single value, `azp` SHOULD equal `client_id`.

### Decision 4: Hardcode WebAuthn acr/amr values for conformance
**Chosen:** `acr=urn:harbor:ac:webauthn`, `amr=["hwk","user"]` hardcoded at
authorization time until dynamic ceremony detection is wired.
**Rationale:** OIDF suite checks presence/format of acr/amr. Hardcoding WebAuthn
values satisfies conformance while the passkey ceremony is the only auth path.
**Alternatives considered:** Omitting claims (fails OIDF checks).

### Decision 5: /userinfo verifies Bearer token signature inline
**Chosen:** `GetUserInfo` extracts kid from JWT header, looks up signer by kid,
verifies ES256 signature, then returns claims.
**Rationale:** Self-issued tokens can be verified without external call. The
signer list is already available in the Server struct for JWKS publication.
**Alternatives considered:** Token introspection endpoint (not yet implemented).

### Decision 6: token_endpoint_auth_methods_supported: ["none"]
**Chosen:** Advertise `["none"]` in discovery — Harbor is a public-client
provider where PKCE replaces client secrets.
**Rationale:** OIDF suite checks this field. `none` correctly reflects that no
client authentication is required at the token endpoint (PKCE handles it).

## ADDED Requirements

### REQ-OIDF-JTI: id_token and access_token SHALL contain unique jti claims
Each token MUST have a unique `jti` claim (256-bit random, base64url-encoded).
The id_token and access_token jti values MUST be different.

**Scenario:**
- Given: A successful token exchange
- When: id_token and access_token are decoded
- Then: Both contain `jti` claims AND the values are different

### REQ-OIDF-AUTHTIME: id_token SHALL contain auth_time claim
The `auth_time` claim MUST be present and reflect the Unix timestamp when the
user authenticated (at session creation in Authorize).

**Scenario:**
- Given: A user authenticates and completes authorization
- When: The id_token is decoded
- Then: `auth_time` equals the authentication timestamp (not issuance time)

### REQ-OIDF-AZP: id_token SHALL contain azp claim equal to client_id
The `azp` (authorized party) claim MUST equal the `client_id`.

**Scenario:**
- Given: A token issued to client "demo-client"
- When: The id_token is decoded
- Then: `azp` equals "demo-client"

### REQ-OIDF-ACRAMR: id_token SHALL contain acr and amr claims
The `acr` (authentication context class reference) and `amr` (authentication
methods references) claims MUST be present for WebAuthn authentication.

**Scenario:**
- Given: A user authenticates via passkey
- When: The id_token is decoded
- Then: `acr` equals "urn:harbor:ac:webauthn" AND `amr` contains "hwk" and "user"

### REQ-OIDF-USERINFO: GET /userinfo SHALL return verified sub claim
The `/userinfo` endpoint MUST validate the Bearer access token's ES256 signature
and return the pairwise `sub` (PPID) from the verified token.

**Scenario:**
- Given: A valid access token
- When: GET /userinfo with Authorization: Bearer <token>
- Then: Response contains `{"sub": "<ppid>"}` with 200 OK

### REQ-OIDF-USERINFO-UNAUTH: /userinfo SHALL reject invalid tokens
Missing or invalid Bearer tokens MUST return 401 with WWW-Authenticate header.

**Scenario:**
- Given: No Authorization header OR invalid/tampered token
- When: GET /userinfo
- Then: 401 Unauthorized with `WWW-Authenticate: Bearer error="invalid_token"`

### REQ-OIDF-DISCOVERY: Discovery SHALL include OIDF-required fields
The discovery document MUST include `userinfo_endpoint`, `claims_supported`,
and `token_endpoint_auth_methods_supported`.

**Scenario:**
- Given: GET /.well-known/openid-configuration
- When: Response is parsed
- Then: Contains `userinfo_endpoint`, `claims_supported` array, and
  `token_endpoint_auth_methods_supported: ["none"]`
