# Design: Authorization Code Persistence (Redis-backed)

## Architecture

### Key Structure

```
auth_code:<code>          → JSON-serialized AuthCode struct (TTL = code.ExpiresAt - now)
auth_code_consumed:<code> → "1" (TTL = 2× code TTL for reuse detection)
```

### Data Flow

```
/authorize → Save(code) → SET NX EX auth_code:<code>
                        ↓
/token     → Peek(code) → GET auth_code:<code> + EXISTS auth_code_consumed:<code>
                        ↓
           → Consume(code) → Lua script: atomically check+set consumed marker
                        ↓
           → Issue tokens
```

## Implementation Details

### RedisAuthCodeStore

Located in `internal/clients/codes.go`, implementing `oidc.AuthCodeStore`:

```go
type RedisAuthCodeStore struct {
    client      *redis.Client
    consumeScript *redis.Script  // preloaded Lua script
}

func NewRedisAuthCodeStore(client *redis.Client) *RedisAuthCodeStore
func (s *RedisAuthCodeStore) Save(ctx context.Context, code AuthCode) error
func (s *RedisAuthCodeStore) Peek(ctx context.Context, code string) (AuthCode, bool, bool, error)
func (s *RedisAuthCodeStore) Consume(ctx context.Context, code string) (ConsumeResult, error)
```

### Save Implementation

```go
func (s *RedisAuthCodeStore) Save(ctx context.Context, code AuthCode) error {
    data, err := json.Marshal(code)
    if err != nil {
        return fmt.Errorf("codes: marshal: %w", err)
    }
    ttl := time.Until(code.ExpiresAt)
    if ttl <= 0 {
        return fmt.Errorf("codes: code already expired")
    }
    key := "auth_code:" + code.Code
    // SET NX: fail if code already exists (duplicate code collision)
    ok, err := s.client.SetNX(ctx, key, data, ttl).Result()
    if err != nil {
        return fmt.Errorf("codes: redis set: %w", err)
    }
    if !ok {
        return fmt.Errorf("codes: duplicate code")
    }
    return nil
}
```

### Peek Implementation

```go
func (s *RedisAuthCodeStore) Peek(ctx context.Context, code string) (AuthCode, bool, bool, error) {
    key := "auth_code:" + code
    consumedKey := "auth_code_consumed:" + code
    
    // Pipeline: GET code + EXISTS consumed marker
    pipe := s.client.Pipeline()
    getCmd := pipe.Get(ctx, key)
    existsCmd := pipe.Exists(ctx, consumedKey)
    _, err := pipe.Exec(ctx)
    
    data, err := getCmd.Result()
    if err == redis.Nil {
        return AuthCode{}, false, false, nil // not found
    }
    if err != nil {
        return AuthCode{}, false, false, fmt.Errorf("codes: redis get: %w", err)
    }
    
    var ac AuthCode
    if err := json.Unmarshal([]byte(data), &ac); err != nil {
        return AuthCode{}, false, false, fmt.Errorf("codes: unmarshal: %w", err)
    }
    
    consumed := existsCmd.Val() > 0
    return ac, true, consumed, nil
}
```

### Consume Implementation (Lua Script)

```lua
-- KEYS[1] = auth_code:<code>
-- KEYS[2] = auth_code_consumed:<code>
-- ARGV[1] = consumed marker TTL (seconds)

local code = redis.call('GET', KEYS[1])
if not code then
    return {0, ''}  -- ConsumeNotFound
end

local consumed = redis.call('EXISTS', KEYS[2])
if consumed == 1 then
    return {2, code}  -- ConsumeReused
end

-- Mark as consumed with 2× TTL
redis.call('SET', KEYS[2], '1', 'EX', ARGV[1])
return {1, code}  -- ConsumeFirstUse
```

### Redis Connection

`internal/clients/redis.go`:

```go
func ConnectRedis(ctx context.Context, logger *slog.Logger) (*redis.Client, error) {
    url := os.Getenv("REDIS_URL")
    if url == "" {
        return nil, nil  // fallback to in-memory
    }
    opts, err := redis.ParseURL(url)
    if err != nil {
        return nil, fmt.Errorf("redis: parse URL: %w", err)
    }
    client := redis.NewClient(opts)
    if err := client.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("redis: ping: %w", err)
    }
    logger.Info("connected to redis")
    return client, nil
}
```

### Wiring in main.go

```go
// In cmd/harbor-hot/main.go
redisClient, err := clients.ConnectRedis(ctx, logger)
if err != nil {
    logger.Error("redis connection failed", slog.Any("error", err))
    os.Exit(1)
}

var codeStore oidc.AuthCodeStore
if redisClient != nil {
    codeStore = clients.NewRedisAuthCodeStore(redisClient)
    logger.Info("using Redis-backed auth code store")
} else {
    codeStore = oidc.NewInMemoryAuthCodeStore()
    logger.Warn("SCAFFOLD: authorization codes stored in-memory — not suitable for multi-replica deployment")
}
```

## Security Considerations

### PII in Redis

The `AuthCode` struct contains:
- `Code` — opaque random string (not PII)
- `ClientID` — public RP identifier (not PII)
- `RedirectURI` — RP-controlled URL (not PII)
- `Scope` — requested permissions (not PII)
- `Subject` — PPID, not the raw user ID (privacy-preserving)
- `UserID` — internal UUID (not exposed externally)
- `Nonce` — RP-provided random value (not PII)
- `CodeChallenge`/`CodeChallengeMethod` — PKCE values (not PII)

No raw PII (email, name, etc.) is stored. TTL ensures automatic cleanup.

### Atomicity

The Lua script ensures that concurrent `/token` requests cannot both succeed:
- Only one request marks the consumed flag
- The other sees `ConsumeReused` and triggers the theft signal

### Availability

Redis unavailability during:
- `/authorize` → code save fails → login fails (user retries)
- `/token` → code lookup fails → exchange fails (user retries)

Both are recoverable; no permanent data loss.

## Testing Strategy

### Unit Tests (miniredis)

- `TestRedisCodeStore_SavePeekConsume` — round-trip validation
- `TestRedisCodeStore_DoubleConsume` — reuse detection
- `TestRedisCodeStore_Expiry` — TTL-based cleanup
- `TestRedisCodeStore_ConsumedMarkerOutlivesCode` — 2× TTL behavior
- `TestRedisCodeStore_ConcurrentConsume` — Lua atomicity

### Integration Tests (real Redis via Docker Compose)

- `TestRedisCodeStore_RealRedis_LuaScript` — verify Lua behavior matches miniredis

## DESIGN.md Alignment

- §4.1: Hot path stateless across replicas (Redis is region-local shared state)
- §4.4: No PII at rest beyond opaque fields
- §10: Regional stores as consistency boundary
- §11.7: Reuse detection and theft signal

No changes to `DESIGN.md` required.
