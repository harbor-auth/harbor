# Specification: Authorization Code Persistence

## Overview

This specification defines the requirements for replacing the in-memory authorization
code store with a Redis-backed implementation that is safe for multi-replica deployments.

## Requirements

### REQ-1: Redis-backed AuthCodeStore Implementation

The system MUST provide a `RedisAuthCodeStore` that implements the existing
`oidc.AuthCodeStore` interface with the following methods:

- `Save(ctx, code AuthCode) error`
- `Peek(ctx, code string) (AuthCode, found bool, consumed bool, error)`
- `Consume(ctx, code string) (ConsumeResult, error)`

### REQ-2: Save Operation

The `Save` method MUST:
- Serialize the `AuthCode` struct to JSON
- Store it in Redis with key pattern `auth_code:<code>`
- Use `SET NX` to prevent overwriting existing codes
- Set TTL based on `code.ExpiresAt - time.Now()`
- Return an error if the code has already expired
- Return an error if a duplicate code exists

### REQ-3: Peek Operation

The `Peek` method MUST:
- Read the code from Redis without mutating state
- Check for the consumed marker at `auth_code_consumed:<code>`
- Return `(AuthCode, true, false, nil)` if code exists and not consumed
- Return `(AuthCode, true, true, nil)` if code exists and is consumed
- Return `(AuthCode{}, false, false, nil)` if code does not exist
- Propagate Redis errors appropriately

### REQ-4: Consume Operation

The `Consume` method MUST:
- Use a Lua script for atomic check-and-mark
- Return `ConsumeNotFound` if the code does not exist
- Return `ConsumeReused` if the consumed marker already exists
- Return `ConsumeFirstUse` and set the consumed marker on first use
- Set consumed marker TTL to 2× the code TTL for reliable reuse detection

### REQ-5: Atomicity

Concurrent `Consume` calls for the same code MUST be serialized such that:
- Exactly one call returns `ConsumeFirstUse`
- All subsequent calls return `ConsumeReused`
- No race conditions can result in two successful first-use results

### REQ-6: Redis Connection

The system MUST provide a `ConnectRedis` function that:
- Reads the `REDIS_URL` environment variable
- Returns `(nil, nil)` when `REDIS_URL` is not set (fallback to in-memory)
- Validates the connection with a PING before returning
- Returns a configured `*redis.Client` on success

### REQ-7: Main Wiring

`cmd/harbor-hot/main.go` MUST:
- Attempt Redis connection via `ConnectRedis`
- Use `RedisAuthCodeStore` when Redis is available
- Fall back to `InMemoryAuthCodeStore` when Redis is not available
- Log appropriately for both cases (info for Redis, warn for in-memory)

### REQ-8: Consumed Marker TTL

The consumed marker MUST have a TTL of 2× the code's remaining TTL to ensure:
- Reuse detection works even when the original code expires
- The marker eventually expires to avoid Redis memory bloat

## Acceptance Scenarios

### Scenario 1: Basic Save-Peek-Consume Flow

```gherkin
Given a Redis-connected auth code store
When I save an auth code with 60s TTL
Then Peek returns (code, found=true, consumed=false)
When I consume the code
Then Consume returns ConsumeFirstUse
And Peek returns (code, found=true, consumed=true)
```

### Scenario 2: Double Consume Detection

```gherkin
Given a saved auth code
When I consume the code twice
Then the first Consume returns ConsumeFirstUse
And the second Consume returns ConsumeReused
```

### Scenario 3: Expired Code

```gherkin
Given a saved auth code with 1s TTL
When I wait 2 seconds
Then Peek returns (code, found=false, consumed=false)
And Consume returns ConsumeNotFound
```

### Scenario 4: Consumed Marker Outlives Code

```gherkin
Given a saved auth code with 1s TTL
When I consume the code immediately
And wait 2 seconds (code expires, marker has 2s remaining)
Then the code key is gone
But the consumed marker still exists
And a re-save + consume of same code value returns ConsumeReused
```

### Scenario 5: Concurrent Consume

```gherkin
Given a saved auth code
When 10 goroutines attempt Consume simultaneously
Then exactly 1 returns ConsumeFirstUse
And the other 9 return ConsumeReused
```

### Scenario 6: Fallback to In-Memory

```gherkin
Given REDIS_URL is not set
When the server starts
Then it uses InMemoryAuthCodeStore
And logs a warning about multi-replica safety
```

## Non-Functional Requirements

### NFR-1: No PII in Redis

The stored `AuthCode` struct MUST NOT contain raw PII. The `Subject` field
contains a PPID (pairwise pseudonymous identifier), not the user's real identity.

### NFR-2: TTL-based Cleanup

All Redis keys MUST have TTLs set. No background cleanup job is required.

### NFR-3: Error Propagation

Redis connection/operation errors MUST be propagated to callers, not silently
swallowed. The service layer decides whether to return 5xx or fall back.
