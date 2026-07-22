package clients

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/redis/go-redis/v9"
)

// testRedisClient creates a miniredis-backed Redis client for testing.
func testRedisClient(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	return client, mr
}

// testAuthCode creates a test auth code with the given code string.
func testAuthCode(code string, ttl time.Duration) oidc.AuthCode {
	return oidc.AuthCode{
		Code:                code,
		ClientID:            "test-client",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		Subject:             "ppid-123",
		UserID:              "user-456",
		Nonce:               "nonce-789",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(ttl),
	}
}

// TestRedisAuthCodeStore_SavePeekConsume exercises the complete round-trip:
// Save → Peek (found, not consumed) → Consume (first use) → Peek (found, consumed).
func TestRedisAuthCodeStore_SavePeekConsume(t *testing.T) {
	client, _ := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 60*time.Second)
	ctx := context.Background()

	code := testAuthCode("test-code-001", 60*time.Second)

	// Save the code
	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Peek should find the code, not consumed
	stored, found, consumed, err := store.Peek(ctx, code.Code)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if !found {
		t.Fatal("Peek: expected found=true")
	}
	if consumed {
		t.Fatal("Peek: expected consumed=false before Consume")
	}
	if stored.Code != code.Code {
		t.Fatalf("Peek: code mismatch: got %q, want %q", stored.Code, code.Code)
	}
	if stored.ClientID != code.ClientID {
		t.Fatalf("Peek: clientID mismatch: got %q, want %q", stored.ClientID, code.ClientID)
	}

	// Consume should return FirstUse
	result, err := store.Consume(ctx, code.Code)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if result.Status != oidc.ConsumeFirstUse {
		t.Fatalf("Consume: expected ConsumeFirstUse, got %v", result.Status)
	}
	if result.Code.Code != code.Code {
		t.Fatalf("Consume: code mismatch: got %q, want %q", result.Code.Code, code.Code)
	}

	// Peek after Consume should show consumed=true
	_, found, consumed, err = store.Peek(ctx, code.Code)
	if err != nil {
		t.Fatalf("Peek after Consume: %v", err)
	}
	if !found {
		t.Fatal("Peek after Consume: expected found=true")
	}
	if !consumed {
		t.Fatal("Peek after Consume: expected consumed=true")
	}
}

// TestRedisAuthCodeStore_DoubleConsume verifies reuse detection: the second
// Consume returns ConsumeReused (not ConsumeFirstUse or ConsumeNotFound).
func TestRedisAuthCodeStore_DoubleConsume(t *testing.T) {
	client, _ := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 60*time.Second)
	ctx := context.Background()

	code := testAuthCode("test-code-002", 60*time.Second)

	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// First consume
	result1, err := store.Consume(ctx, code.Code)
	if err != nil {
		t.Fatalf("Consume 1: %v", err)
	}
	if result1.Status != oidc.ConsumeFirstUse {
		t.Fatalf("Consume 1: expected ConsumeFirstUse, got %v", result1.Status)
	}

	// Second consume — must be ConsumeReused
	result2, err := store.Consume(ctx, code.Code)
	if err != nil {
		t.Fatalf("Consume 2: %v", err)
	}
	if result2.Status != oidc.ConsumeReused {
		t.Fatalf("Consume 2: expected ConsumeReused, got %v", result2.Status)
	}
	// The code data must still be returned so the caller can act on theft
	if result2.Code.Code != code.Code {
		t.Fatalf("Consume 2: code mismatch: got %q, want %q", result2.Code.Code, code.Code)
	}
}

// TestRedisAuthCodeStore_Expiry verifies that expired codes return NotFound.
func TestRedisAuthCodeStore_Expiry(t *testing.T) {
	client, mr := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 1*time.Second)
	ctx := context.Background()

	code := testAuthCode("test-code-003", 1*time.Second)

	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify code exists before expiry
	_, found, _, err := store.Peek(ctx, code.Code)
	if err != nil {
		t.Fatalf("Peek before expiry: %v", err)
	}
	if !found {
		t.Fatal("Peek before expiry: expected found=true")
	}

	// Fast-forward time past TTL
	mr.FastForward(2 * time.Second)

	// Code should be gone
	_, found, _, err = store.Peek(ctx, code.Code)
	if err != nil {
		t.Fatalf("Peek after expiry: %v", err)
	}
	if found {
		t.Fatal("Peek after expiry: expected found=false")
	}

	// Consume should return NotFound
	result, err := store.Consume(ctx, code.Code)
	if err != nil {
		t.Fatalf("Consume after expiry: %v", err)
	}
	if result.Status != oidc.ConsumeNotFound {
		t.Fatalf("Consume after expiry: expected ConsumeNotFound, got %v", result.Status)
	}
}

// TestRedisAuthCodeStore_ConsumedMarkerOutlivesCode verifies that the consumed
// marker TTL (2x code TTL) allows reuse detection even after the code data
// expires. This is critical for detecting theft attempts that arrive late.
func TestRedisAuthCodeStore_ConsumedMarkerOutlivesCode(t *testing.T) {
	client, mr := testRedisClient(t)
	codeTTL := 2 * time.Second
	store := NewRedisAuthCodeStore(client, codeTTL)
	ctx := context.Background()

	code := testAuthCode("test-code-004", codeTTL)

	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Consume the code
	result, err := store.Consume(ctx, code.Code)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if result.Status != oidc.ConsumeFirstUse {
		t.Fatalf("Consume: expected ConsumeFirstUse, got %v", result.Status)
	}

	// Fast-forward past code TTL but before consumed marker TTL (2x)
	mr.FastForward(codeTTL + 500*time.Millisecond)

	// Code data should be expired
	_, found, _, err := store.Peek(ctx, code.Code)
	if err != nil {
		t.Fatalf("Peek after code expiry: %v", err)
	}
	if found {
		t.Fatal("Peek after code expiry: code data should be gone")
	}

	// But the consumed marker should still exist (checked via EXISTS in Peek)
	// We verify this by checking that if we had the code, it would show consumed
	// Since Peek returns found=false, we check the marker directly
	exists, err := client.Exists(ctx, consumedKey(code.Code)).Result()
	if err != nil {
		t.Fatalf("EXISTS consumed marker: %v", err)
	}
	if exists != 1 {
		t.Fatal("consumed marker should still exist after code expiry")
	}

	// Fast-forward past consumed marker TTL
	mr.FastForward(codeTTL + 1*time.Second)

	// Now the consumed marker should also be gone
	exists, err = client.Exists(ctx, consumedKey(code.Code)).Result()
	if err != nil {
		t.Fatalf("EXISTS consumed marker after full expiry: %v", err)
	}
	if exists != 0 {
		t.Fatal("consumed marker should be gone after 2x code TTL")
	}
}

// TestRedisAuthCodeStore_ConcurrentConsume verifies the Lua script's atomicity:
// exactly one of N concurrent Consume calls returns ConsumeFirstUse; all others
// return ConsumeReused.
func TestRedisAuthCodeStore_ConcurrentConsume(t *testing.T) {
	client, _ := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 60*time.Second)
	ctx := context.Background()

	code := testAuthCode("test-code-005", 60*time.Second)

	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	results := make(chan oidc.ConsumeStatus, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, err := store.Consume(ctx, code.Code)
			if err != nil {
				t.Errorf("Consume error: %v", err)
				return
			}
			results <- result.Status
		}()
	}

	wg.Wait()
	close(results)

	var firstUseCount, reusedCount int
	for status := range results {
		switch status {
		case oidc.ConsumeFirstUse:
			firstUseCount++
		case oidc.ConsumeReused:
			reusedCount++
		default:
			t.Errorf("unexpected status: %v", status)
		}
	}

	if firstUseCount != 1 {
		t.Errorf("expected exactly 1 ConsumeFirstUse, got %d", firstUseCount)
	}
	if reusedCount != goroutines-1 {
		t.Errorf("expected %d ConsumeReused, got %d", goroutines-1, reusedCount)
	}
}

// TestRedisAuthCodeStore_SaveDuplicate verifies that saving a code that already
// exists returns an error (SET NX semantics).
func TestRedisAuthCodeStore_SaveDuplicate(t *testing.T) {
	client, _ := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 60*time.Second)
	ctx := context.Background()

	code := testAuthCode("test-code-006", 60*time.Second)

	// First save should succeed
	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save 1: %v", err)
	}

	// Second save with same code should fail
	err := store.Save(ctx, code)
	if err == nil {
		t.Fatal("Save 2: expected error for duplicate code")
	}
}

// TestRedisAuthCodeStore_ConsumeNotFound verifies that consuming a non-existent
// code returns ConsumeNotFound.
func TestRedisAuthCodeStore_ConsumeNotFound(t *testing.T) {
	client, _ := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 60*time.Second)
	ctx := context.Background()

	result, err := store.Consume(ctx, "nonexistent-code")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if result.Status != oidc.ConsumeNotFound {
		t.Fatalf("Consume: expected ConsumeNotFound, got %v", result.Status)
	}
}

// TestRedisAuthCodeStore_PeekNotFound verifies that peeking a non-existent
// code returns found=false without error.
func TestRedisAuthCodeStore_PeekNotFound(t *testing.T) {
	client, _ := testRedisClient(t)
	store := NewRedisAuthCodeStore(client, 60*time.Second)
	ctx := context.Background()

	_, found, _, err := store.Peek(ctx, "nonexistent-code")
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if found {
		t.Fatal("Peek: expected found=false for non-existent code")
	}
}
