# redis-enrollment-session

**Status:** planned  
**DESIGN §:** §11.1  
**Code:** `internal/webauthn/store_redis.go` (planned)

Redis-backed enrollment session store: holds the short-lived, region-pinned
WebAuthn enrollment (B1+B2) ceremony state across replicas so passkey
registration works behind a load balancer without sticky sessions.
