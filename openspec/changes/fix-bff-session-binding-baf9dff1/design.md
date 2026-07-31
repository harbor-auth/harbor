# Design: BFF login session fixation fix (C3 + M2)

## Key Decisions

### Decision 1: Browser nonce stored as SHA-256 hash server-side
**Chosen:** Store `SHA-256(nonce)` in `BFFSessionRecord.BrowserNonceHash`; place
the raw nonce in the `__Host-harbor-bff-nonce` cookie.
**Rationale:** A store compromise (Redis breach) yields only hashes, not the raw
nonce values needed to forge a live cookie. The hash-at-rest pattern mirrors the
refresh-token design (§3.5). `subtle.ConstantTimeCompare` prevents timing
side-channels on the comparison.
**Alternatives considered:** Storing the raw nonce (rejected: store breach yields
live cookies); signing the nonce with HMAC (rejected: proves Harbor minted it, not
that *this* browser received it — same attack works).

### Decision 2: 256-bit CSPRNG nonce (32 bytes)
**Chosen:** `crypto/rand.Read` into a 32-byte slice; base64url-encoded for cookie transport.
**Rationale:** Same entropy as the `request_id` (also 256-bit). Brute-force is
computationally infeasible. `base64.RawURLEncoding` avoids padding issues and is
safe in cookie values.
**Alternatives considered:** Shorter nonces (rejected: reduces brute-force margin
with no operational benefit).

### Decision 3: Gate at ALL three checkpoints
**Chosen:** Nonce gate enforced at `BeginLogin`, `FinishLoginWithParsedData`, AND
`GetAuthorizeComplete`.
**Rationale:** Defense-in-depth. An attacker who somehow bypasses `BeginLogin`
(e.g., via a network-level replay) is stopped at `FinishLogin`. An attacker who
bypasses both is stopped at `GetAuthorizeComplete` before any code is issued.
Failure at any checkpoint renders the no-redirect error page (§11.7) — never a
redirect to an unproven URI.
**Alternatives considered:** Gate only at `BeginLogin` (rejected: a single
checkpoint is not defense-in-depth; `GetAuthorizeComplete` reads `request_id` from
the query string, so the gate there is independent of the cookie-to-URL binding).

### Decision 4: Single-public-host topology enforced by `__Host-` prefix
**Chosen:** Document that the supported deployment topology is one public hostname
fronting both harbor-hot and harbor-mgmt via path-routing (`/login*` → mgmt,
everything else → hot).
**Rationale:** `__Host-` cookies cannot span two different registrable domains.
Attempting to split hot and mgmt onto separate public hosts would require dropping
the `__Host-` prefix, weakening the cookie security model. The clean answer is to
enforce the topology by design and document it explicitly in `deploy/README.md`.
**Alternatives considered:** Dropping `__Host-` prefix to support split-host
(rejected: `__Host-` is a critical security hardening that prevents subdomain
injection attacks); a signed handoff token in the redirect (deferred: not needed
for the single-host topology, adds complexity).

### Decision 5: AUTHORIZE_COMPLETE_URL env var (M2 fix)
**Chosen:** New env var `AUTHORIZE_COMPLETE_URL` in `cmd/harbor-mgmt`; fail closed
at boot if unset in production configurations.
**Rationale:** A relative redirect `/authorize/complete?...` resolves against the
harbor-mgmt origin, but the endpoint is registered on harbor-hot. An absolute URL
configured at deploy time is the minimal, unambiguous fix. Boot-time validation
ensures the misconfiguration is caught immediately rather than at the end of every
login flow.
**Alternatives considered:** Deriving the URL from the OIDC issuer (rejected:
issuer is the hot origin, but the path might not be `/authorize/complete` in all
deployments; an explicit env var is clearer); hardcoding (rejected: makes the
topology inflexible).

### Decision 6: Clear both nonce and BFF cookies after /authorize/complete
**Chosen:** `ClearBFFCookie` + `ClearBFFNonceCookie` are both called after the
auth code is issued.
**Rationale:** One-time-use semantics. After the code is issued, both cookies
become stale credentials. Clearing them prevents replay attacks using a stale
nonce cookie combined with a new request_id obtained via a second `/authorize`.
