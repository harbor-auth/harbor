# token-revocation-endpoint

**Status:** implemented  
**DESIGN §:** §3.5, §10  
**Code:** `internal/oidcapi/revoke_jwt.go`

OAuth 2.0 Token Revocation endpoint (RFC 7009): lets a client revoke an issued
access/refresh token. Revocations propagate via the revocation outbox so the
hot path rejects the token's jti thereafter.
