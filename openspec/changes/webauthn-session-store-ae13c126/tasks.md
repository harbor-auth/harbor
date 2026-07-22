# Tasks: WebAuthn session persistence (Redis-backed)

## Prerequisites

- [ ] None — the `SessionStore` interface and `InMemorySessionStore` already exist; this plan swaps in a durable backend.

## Implementation

- [ ] `internal/webauthn/store_redis.go`: `RedisSessionStore` struct wrapping `*redis.Client` + `sessionTTL time.Duration`.
- [ ] `Save(ctx, key, data)`: JSON-marshal `gowebauthn.SessionData`; `SET NX EX <ttl>`. Return error if key exists (NX failed).
- [ ] `Take(ctx, key)`: Lua script (`GET key` → `DEL key` → `return value`). Return `ErrSessionNotFound` when nil.
- [ ] Compile-time assertion: `var _ SessionStore = (*RedisSessionStore)(nil)`.
- [ ] `cmd/harbor-mgmt/main.go`: wire `RedisSessionStore` when `REDIS_URL` is set; keep `InMemorySessionStore` for no-Redis dev.
- [ ] Update `InMemorySessionStore` production-warning comment to reference `webauthn-session-store` plan slug.

## Tests

- [ ] `internal/webauthn/store_redis_test.go`: integration tests (miniredis for unit tests).
- [ ] Docker Compose e2e: run concurrency tests against real Redis to verify Lua atomicity (miniredis may diverge on edge cases).
- [ ] `Save` → `Take` round-trip preserves all `SessionData` fields (Challenge, UserID, AllowedCredentialIDs, UserVerification, RelyingPartyID).
- [ ] Double-`Take` returns `ErrSessionNotFound` on the second call.
- [ ] Expired session (TTL elapsed) returns `ErrSessionNotFound`.
- [ ] `Save` with duplicate key returns `ErrSessionExists` (NX guard).
- [ ] Concurrent `Take` calls: only one succeeds; test with multiple goroutines.
- [ ] Verify no PII in Redis keys or values.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate webauthn-session-store-ae13c126 --strict`
