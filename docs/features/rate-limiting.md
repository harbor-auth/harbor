# rate-limiting

**Status:** implemented  
**DESIGN §:** §6.5  
**Code:** `internal/clients/ratelimit.go`, `internal/oidcapi/ratelimit.go`

Per-client (client_id) and per-IP sliding-window rate limiting on the
abuse-sensitive hot-path endpoints (/token, /authorize, /introspect).
Redis-backed in production with an in-memory fallback for dev; fails open on
backend errors and never keys on PII.
