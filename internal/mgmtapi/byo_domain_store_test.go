package mgmtapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/relay"
)

func makeTestBYODomain(userID uuid.UUID, domain string) *relay.BYODomain {
	return &relay.BYODomain{
		ID:             uuid.New(),
		Domain:         domain,
		UserID:         userID,
		ChallengeToken: "test-token-" + domain,
		State:          relay.BYODomainStatePending,
		Region:         region.EU,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(72 * time.Hour),
	}
}

func TestInMemoryBYODomainStore_CreateDomain(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("creates domain successfully", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "mail.example.com")

		err := store.CreateDomain(ctx, domain)
		if err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		// Verify it was stored
		got, err := store.GetDomainByName(ctx, userID.String(), "mail.example.com")
		if err != nil {
			t.Fatalf("GetDomainByName() error = %v", err)
		}
		if got.Domain != "mail.example.com" {
			t.Errorf("got domain = %q, want %q", got.Domain, "mail.example.com")
		}
	})

	t.Run("returns error for duplicate domain", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "dup.example.com")

		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("first CreateDomain() error = %v", err)
		}

		// Try to create same domain again
		domain2 := makeTestBYODomain(userID, "dup.example.com")
		err := store.CreateDomain(ctx, domain2)
		if !errors.Is(err, relay.ErrDomainAlreadyExists) {
			t.Errorf("CreateDomain() error = %v, want ErrDomainAlreadyExists", err)
		}
	})

	t.Run("returns error for duplicate domain different user", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		userA := uuid.New()
		userB := uuid.New()

		domainA := makeTestBYODomain(userA, "shared.example.com")
		if err := store.CreateDomain(ctx, domainA); err != nil {
			t.Fatalf("first CreateDomain() error = %v", err)
		}

		// User B tries to register the same domain
		domainB := makeTestBYODomain(userB, "shared.example.com")
		err := store.CreateDomain(ctx, domainB)
		if !errors.Is(err, relay.ErrDomainAlreadyExists) {
			t.Errorf("CreateDomain() error = %v, want ErrDomainAlreadyExists", err)
		}
	})

	t.Run("stores a copy to prevent external mutation", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "copy.example.com")
		originalToken := domain.ChallengeToken

		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		// Mutate the original
		domain.ChallengeToken = "mutated-token"

		// Retrieve and verify it wasn't affected
		got, err := store.GetDomainByName(ctx, userID.String(), "copy.example.com")
		if err != nil {
			t.Fatalf("GetDomainByName() error = %v", err)
		}
		if got.ChallengeToken != originalToken {
			t.Errorf("stored domain was mutated: got token = %q, want %q", got.ChallengeToken, originalToken)
		}
	})
}

func TestInMemoryBYODomainStore_GetDomainByName(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("returns domain for owner", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "get.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		got, err := store.GetDomainByName(ctx, userID.String(), "get.example.com")
		if err != nil {
			t.Fatalf("GetDomainByName() error = %v", err)
		}
		if got.Domain != "get.example.com" {
			t.Errorf("got domain = %q, want %q", got.Domain, "get.example.com")
		}
		if got.UserID != userID {
			t.Errorf("got userID = %v, want %v", got.UserID, userID)
		}
	})

	t.Run("returns not found for non-existent domain", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()

		_, err := store.GetDomainByName(ctx, userID.String(), "nonexistent.example.com")
		if !errors.Is(err, relay.ErrDomainNotFound) {
			t.Errorf("GetDomainByName() error = %v, want ErrDomainNotFound", err)
		}
	})

	t.Run("returns not found for wrong user (security)", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		userA := uuid.New()
		userB := uuid.New()

		domain := makeTestBYODomain(userA, "usera.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		// User B tries to access user A's domain
		_, err := store.GetDomainByName(ctx, userB.String(), "usera.example.com")
		if !errors.Is(err, relay.ErrDomainNotFound) {
			t.Errorf("SECURITY: GetDomainByName() should return ErrDomainNotFound for wrong user, got %v", err)
		}
	})

	t.Run("returns a copy to prevent external mutation", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "copysafe.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		got, err := store.GetDomainByName(ctx, userID.String(), "copysafe.example.com")
		if err != nil {
			t.Fatalf("GetDomainByName() error = %v", err)
		}

		originalToken := got.ChallengeToken
		got.ChallengeToken = "mutated"

		// Retrieve again and verify it wasn't affected
		got2, err := store.GetDomainByName(ctx, userID.String(), "copysafe.example.com")
		if err != nil {
			t.Fatalf("GetDomainByName() error = %v", err)
		}
		if got2.ChallengeToken != originalToken {
			t.Errorf("stored domain was mutated via returned copy")
		}
	})
}

func TestInMemoryBYODomainStore_ListDomainsByUser(t *testing.T) {
	ctx := context.Background()

	t.Run("returns all domains for user", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		userID := uuid.New()

		domain1 := makeTestBYODomain(userID, "list1.example.com")
		domain2 := makeTestBYODomain(userID, "list2.example.com")

		if err := store.CreateDomain(ctx, domain1); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}
		if err := store.CreateDomain(ctx, domain2); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		got, err := store.ListDomainsByUser(ctx, userID.String())
		if err != nil {
			t.Fatalf("ListDomainsByUser() error = %v", err)
		}
		if len(got) != 2 {
			t.Errorf("got %d domains, want 2", len(got))
		}
	})

	t.Run("returns empty slice for user with no domains", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		userID := uuid.New()

		got, err := store.ListDomainsByUser(ctx, userID.String())
		if err != nil {
			t.Fatalf("ListDomainsByUser() error = %v", err)
		}
		if got == nil {
			t.Error("ListDomainsByUser() returned nil, want empty slice")
		}
		if len(got) != 0 {
			t.Errorf("got %d domains, want 0", len(got))
		}
	})

	t.Run("only returns domains for specified user (security)", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		userA := uuid.New()
		userB := uuid.New()

		domainA := makeTestBYODomain(userA, "usera-list.example.com")
		domainB := makeTestBYODomain(userB, "userb-list.example.com")

		if err := store.CreateDomain(ctx, domainA); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}
		if err := store.CreateDomain(ctx, domainB); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		// User A should only see their domain
		got, err := store.ListDomainsByUser(ctx, userA.String())
		if err != nil {
			t.Fatalf("ListDomainsByUser() error = %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("SECURITY: user A got %d domains, want 1", len(got))
		}
		if got[0].Domain != "usera-list.example.com" {
			t.Errorf("SECURITY: user A got domain %q, want usera-list.example.com", got[0].Domain)
		}
	})

	t.Run("returns copies to prevent external mutation", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		userID := uuid.New()

		domain := makeTestBYODomain(userID, "listcopy.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		got, err := store.ListDomainsByUser(ctx, userID.String())
		if err != nil {
			t.Fatalf("ListDomainsByUser() error = %v", err)
		}

		originalToken := got[0].ChallengeToken
		got[0].ChallengeToken = "mutated"

		// List again and verify it wasn't affected
		got2, err := store.ListDomainsByUser(ctx, userID.String())
		if err != nil {
			t.Fatalf("ListDomainsByUser() error = %v", err)
		}
		if got2[0].ChallengeToken != originalToken {
			t.Errorf("stored domain was mutated via returned list copy")
		}
	})
}

func TestInMemoryBYODomainStore_UpdateDomainState(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("updates state successfully", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "update.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		err := store.UpdateDomainState(ctx, domain.ID.String(), relay.BYODomainStateVerified)
		if err != nil {
			t.Fatalf("UpdateDomainState() error = %v", err)
		}

		// Verify the update
		got, err := store.GetDomainByName(ctx, userID.String(), "update.example.com")
		if err != nil {
			t.Fatalf("GetDomainByName() error = %v", err)
		}
		if got.State != relay.BYODomainStateVerified {
			t.Errorf("got state = %v, want %v", got.State, relay.BYODomainStateVerified)
		}
	})

	t.Run("returns not found for non-existent domain", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()

		err := store.UpdateDomainState(ctx, uuid.New().String(), relay.BYODomainStateVerified)
		if !errors.Is(err, relay.ErrDomainNotFound) {
			t.Errorf("UpdateDomainState() error = %v, want ErrDomainNotFound", err)
		}
	})

	t.Run("transitions through all states", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "states.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		states := []relay.BYODomainState{
			relay.BYODomainStateVerified,
			relay.BYODomainStateActive,
			relay.BYODomainStateFailed,
			relay.BYODomainStatePending,
		}

		for _, state := range states {
			err := store.UpdateDomainState(ctx, domain.ID.String(), state)
			if err != nil {
				t.Fatalf("UpdateDomainState(%v) error = %v", state, err)
			}

			got, err := store.GetDomainByName(ctx, userID.String(), "states.example.com")
			if err != nil {
				t.Fatalf("GetDomainByName() error = %v", err)
			}
			if got.State != state {
				t.Errorf("after update got state = %v, want %v", got.State, state)
			}
		}
	})
}

func TestInMemoryBYODomainStore_DeleteDomain(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("deletes domain successfully", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "delete.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		err := store.DeleteDomain(ctx, domain.ID.String())
		if err != nil {
			t.Fatalf("DeleteDomain() error = %v", err)
		}

		// Verify it was deleted
		_, err = store.GetDomainByName(ctx, userID.String(), "delete.example.com")
		if !errors.Is(err, relay.ErrDomainNotFound) {
			t.Errorf("GetDomainByName() after delete error = %v, want ErrDomainNotFound", err)
		}
	})

	t.Run("returns not found for non-existent domain", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()

		err := store.DeleteDomain(ctx, uuid.New().String())
		if !errors.Is(err, relay.ErrDomainNotFound) {
			t.Errorf("DeleteDomain() error = %v, want ErrDomainNotFound", err)
		}
	})

	t.Run("delete is idempotent returns error on second delete", func(t *testing.T) {
		store := NewInMemoryBYODomainStore()
		domain := makeTestBYODomain(userID, "deleteidempotent.example.com")
		if err := store.CreateDomain(ctx, domain); err != nil {
			t.Fatalf("CreateDomain() error = %v", err)
		}

		// First delete should succeed
		if err := store.DeleteDomain(ctx, domain.ID.String()); err != nil {
			t.Fatalf("first DeleteDomain() error = %v", err)
		}

		// Second delete should return not found
		err := store.DeleteDomain(ctx, domain.ID.String())
		if !errors.Is(err, relay.ErrDomainNotFound) {
			t.Errorf("second DeleteDomain() error = %v, want ErrDomainNotFound", err)
		}
	})
}

func TestInMemoryBYODomainStore_Concurrency(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBYODomainStore()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent creates with different domains
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			userID := uuid.New()
			domain := makeTestBYODomain(userID, "concurrent-"+uuid.New().String()+".example.com")
			if err := store.CreateDomain(ctx, domain); err != nil {
				t.Errorf("concurrent CreateDomain() error = %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Verify we have the expected number of domains (roughly)
	// We can't easily list all domains, but we can verify no panics occurred
}

func TestInMemoryBYODomainStore_ConcurrentReadWrite(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryBYODomainStore()
	userID := uuid.New()

	// Create initial domain
	domain := makeTestBYODomain(userID, "readwrite.example.com")
	if err := store.CreateDomain(ctx, domain); err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.GetDomainByName(ctx, userID.String(), "readwrite.example.com")
			_, _ = store.ListDomainsByUser(ctx, userID.String())
		}()
	}

	// Concurrent writes
	states := []relay.BYODomainState{
		relay.BYODomainStatePending,
		relay.BYODomainStateVerified,
		relay.BYODomainStateActive,
		relay.BYODomainStateFailed,
	}
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			defer wg.Done()
			state := states[n%len(states)]
			_ = store.UpdateDomainState(ctx, domain.ID.String(), state)
		}(i)
	}

	wg.Wait()
}
