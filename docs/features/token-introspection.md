# token-introspection

**Status:** planned  
**DESIGN §:** §3.4, §11.7  
**Code:** `internal/oidcapi/` (planned)

OAuth 2.0 Token Introspection endpoint (RFC 7662): lets a resource server ask
Harbor whether an access/refresh token is active and, if so, its scopes and
metadata. Keyed and rate-limited per client on the hot path.
