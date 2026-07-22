package relay

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/region"
)

// mockQuerier implements relayQuerier for testing.
type mockQuerier struct {
	createFn                 func(ctx context.Context, arg db.CreateRelayAddressParams) (db.RelayAddress, error)
	getByTokenFn             func(ctx context.Context, token string) (db.RelayAddress, error)
	getActiveByTokenFn       func(ctx context.Context, token string) (db.RelayAddress, error)
	getByUserClientFn        func(ctx context.Context, arg db.GetRelayAddressByUserClientParams) (db.RelayAddress, error)
	listByUserFn             func(ctx context.Context, userID pgtype.UUID) ([]db.RelayAddress, error)
	deactivateFn             func(ctx context.Context, id pgtype.UUID) error
	deactivateByUserClientFn func(ctx context.Context, arg db.DeactivateRelayAddressByUserClientParams) error
	reactivateFn             func(ctx context.Context, id pgtype.UUID) error
	setBYODomainFn           func(ctx context.Context, id pgtype.UUID) error
}

func (m *mockQuerier) CreateRelayAddress(ctx context.Context, arg db.CreateRelayAddressParams) (db.RelayAddress, error) {
	if m.createFn != nil {
		return m.createFn(ctx, arg)
	}
	return db.RelayAddress{
		ID:         pgtype.UUID{Bytes: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, Valid: true},
		RelayToken: arg.RelayToken,
		UserID:     arg.UserID,
		ClientID:   arg.ClientID,
		State:      arg.State,
		EncMapping: arg.EncMapping,
		Region:     arg.Region,
	}, nil
}

func (m *mockQuerier) GetRelayAddressByToken(ctx context.Context, token string) (db.RelayAddress, error) {
	if m.getByTokenFn != nil {
		return m.getByTokenFn(ctx, token)
	}
	return db.RelayAddress{}, pgx.ErrNoRows
}

func (m *mockQuerier) GetActiveRelayAddressByToken(ctx context.Context, token string) (db.RelayAddress, error) {
	if m.getActiveByTokenFn != nil {
		return m.getActiveByTokenFn(ctx, token)
	}
	return db.RelayAddress{}, pgx.ErrNoRows
}

func (m *mockQuerier) GetRelayAddressByUserClient(ctx context.Context, arg db.GetRelayAddressByUserClientParams) (db.RelayAddress, error) {
	if m.getByUserClientFn != nil {
		return m.getByUserClientFn(ctx, arg)
	}
	return db.RelayAddress{}, pgx.ErrNoRows
}

func (m *mockQuerier) ListRelayAddressesByUser(ctx context.Context, userID pgtype.UUID) ([]db.RelayAddress, error) {
	if m.listByUserFn != nil {
		return m.listByUserFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockQuerier) DeactivateRelayAddress(ctx context.Context, id pgtype.UUID) error {
	if m.deactivateFn != nil {
		return m.deactivateFn(ctx, id)
	}
	return nil
}

func (m *mockQuerier) DeactivateRelayAddressByUserClient(ctx context.Context, arg db.DeactivateRelayAddressByUserClientParams) error {
	if m.deactivateByUserClientFn != nil {
		return m.deactivateByUserClientFn(ctx, arg)
	}
	return nil
}

func (m *mockQuerier) ReactivateRelayAddress(ctx context.Context, id pgtype.UUID) error {
	if m.reactivateFn != nil {
		return m.reactivateFn(ctx, id)
	}
	return nil
}

func (m *mockQuerier) SetRelayAddressBYODomain(ctx context.Context, id pgtype.UUID) error {
	if m.setBYODomainFn != nil {
		return m.setBYODomainFn(ctx, id)
	}
	return nil
}

func TestStore_Create(t *testing.T) {
	cipher := crypto.NewCipher()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error = %v", err)
	}

	t.Run("creates relay address with encrypted mapping", func(t *testing.T) {
		var capturedParams db.CreateRelayAddressParams
		q := &mockQuerier{
			createFn: func(ctx context.Context, arg db.CreateRelayAddressParams) (db.RelayAddress, error) {
				capturedParams = arg
				return db.RelayAddress{
					ID:         pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
					RelayToken: arg.RelayToken,
					UserID:     arg.UserID,
					ClientID:   arg.ClientID,
					State:      arg.State,
					EncMapping: arg.EncMapping,
					Region:     arg.Region,
				}, nil
			},
		}

		store := NewStore(q, cipher)
		addr, err := store.Create(context.Background(), CreateParams{
			Token:     "test-token-123",
			UserID:    "550e8400-e29b-41d4-a716-446655440000",
			ClientID:  "rp.example.com",
			RealEmail: "user@real.com",
			Region:    region.EU,
			DEK:       dek,
		})

		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if addr == nil {
			t.Fatal("Create() returned nil address")
		}
		if addr.Token != "test-token-123" {
			t.Errorf("addr.Token = %q, want %q", addr.Token, "test-token-123")
		}
		if addr.ClientID != "rp.example.com" {
			t.Errorf("addr.ClientID = %q, want %q", addr.ClientID, "rp.example.com")
		}
		if addr.State != StateActive {
			t.Errorf("addr.State = %v, want %v", addr.State, StateActive)
		}

		// Verify the mapping was encrypted
		if len(capturedParams.EncMapping) == 0 {
			t.Error("EncMapping is empty, expected encrypted data")
		}
		// Verify it's not plaintext
		if string(capturedParams.EncMapping) == "user@real.com" {
			t.Error("EncMapping contains plaintext email, expected encrypted")
		}
	})

	t.Run("returns error on duplicate", func(t *testing.T) {
		q := &mockQuerier{
			createFn: func(ctx context.Context, arg db.CreateRelayAddressParams) (db.RelayAddress, error) {
				return db.RelayAddress{}, errors.New("duplicate key value violates unique constraint")
			},
		}

		store := NewStore(q, cipher)
		_, err := store.Create(context.Background(), CreateParams{
			Token:     "test-token",
			UserID:    "550e8400-e29b-41d4-a716-446655440000",
			ClientID:  "rp.example.com",
			RealEmail: "user@real.com",
			Region:    region.EU,
			DEK:       dek,
		})

		if !errors.Is(err, ErrRelayAddressExists) {
			t.Errorf("Create() error = %v, want ErrRelayAddressExists", err)
		}
	})

	t.Run("returns error on invalid user ID", func(t *testing.T) {
		store := NewStore(&mockQuerier{}, cipher)
		_, err := store.Create(context.Background(), CreateParams{
			Token:     "test-token",
			UserID:    "not-a-uuid",
			ClientID:  "rp.example.com",
			RealEmail: "user@real.com",
			Region:    region.EU,
			DEK:       dek,
		})

		if err == nil {
			t.Error("Create() with invalid userID should return error")
		}
	})
}

func TestStore_GetByToken(t *testing.T) {
	cipher := crypto.NewCipher()

	t.Run("returns address when found", func(t *testing.T) {
		expectedRow := db.RelayAddress{
			ID:         pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
			RelayToken: "test-token",
			UserID:     pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
			ClientID:   "rp.example.com",
			State:      "active",
			EncMapping: []byte("encrypted-data"),
			Region:     "EU",
		}
		q := &mockQuerier{
			getByTokenFn: func(ctx context.Context, token string) (db.RelayAddress, error) {
				if token == "test-token" {
					return expectedRow, nil
				}
				return db.RelayAddress{}, pgx.ErrNoRows
			},
		}

		store := NewStore(q, cipher)
		addr, encMapping, err := store.GetByToken(context.Background(), "test-token")

		if err != nil {
			t.Fatalf("GetByToken() error = %v", err)
		}
		if addr == nil {
			t.Fatal("GetByToken() returned nil address")
		}
		if addr.Token != "test-token" {
			t.Errorf("addr.Token = %q, want %q", addr.Token, "test-token")
		}
		if string(encMapping) != "encrypted-data" {
			t.Errorf("encMapping = %q, want %q", encMapping, "encrypted-data")
		}
	})

	t.Run("returns ErrRelayAddressNotFound when not found", func(t *testing.T) {
		q := &mockQuerier{
			getByTokenFn: func(ctx context.Context, token string) (db.RelayAddress, error) {
				return db.RelayAddress{}, pgx.ErrNoRows
			},
		}

		store := NewStore(q, cipher)
		_, _, err := store.GetByToken(context.Background(), "nonexistent")

		if !errors.Is(err, ErrRelayAddressNotFound) {
			t.Errorf("GetByToken() error = %v, want ErrRelayAddressNotFound", err)
		}
	})
}

func TestStore_GetActiveByToken(t *testing.T) {
	cipher := crypto.NewCipher()

	t.Run("returns active address", func(t *testing.T) {
		q := &mockQuerier{
			getActiveByTokenFn: func(ctx context.Context, token string) (db.RelayAddress, error) {
				return db.RelayAddress{
					ID:         pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
					RelayToken: token,
					State:      "active",
					Region:     "EU",
				}, nil
			},
		}

		store := NewStore(q, cipher)
		addr, _, err := store.GetActiveByToken(context.Background(), "active-token")

		if err != nil {
			t.Fatalf("GetActiveByToken() error = %v", err)
		}
		if addr.State != StateActive {
			t.Errorf("addr.State = %v, want %v", addr.State, StateActive)
		}
	})

	t.Run("returns not found for deactivated", func(t *testing.T) {
		q := &mockQuerier{
			getActiveByTokenFn: func(ctx context.Context, token string) (db.RelayAddress, error) {
				return db.RelayAddress{}, pgx.ErrNoRows
			},
		}

		store := NewStore(q, cipher)
		_, _, err := store.GetActiveByToken(context.Background(), "deactivated-token")

		if !errors.Is(err, ErrRelayAddressNotFound) {
			t.Errorf("GetActiveByToken() error = %v, want ErrRelayAddressNotFound", err)
		}
	})
}

func TestStore_Deactivate(t *testing.T) {
	cipher := crypto.NewCipher()

	t.Run("deactivates address by ID", func(t *testing.T) {
		var capturedID pgtype.UUID
		q := &mockQuerier{
			deactivateFn: func(ctx context.Context, id pgtype.UUID) error {
				capturedID = id
				return nil
			},
		}

		store := NewStore(q, cipher)
		err := store.Deactivate(context.Background(), "550e8400-e29b-41d4-a716-446655440000")

		if err != nil {
			t.Fatalf("Deactivate() error = %v", err)
		}
		if !capturedID.Valid {
			t.Error("Deactivate() did not pass valid UUID")
		}
	})

	t.Run("returns error on invalid ID", func(t *testing.T) {
		store := NewStore(&mockQuerier{}, cipher)
		err := store.Deactivate(context.Background(), "not-a-uuid")

		if err == nil {
			t.Error("Deactivate() with invalid ID should return error")
		}
	})
}

func TestStore_DecryptMapping(t *testing.T) {
	cipher := crypto.NewCipher()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error = %v", err)
	}

	t.Run("round-trip encryption/decryption", func(t *testing.T) {
		store := NewStore(&mockQuerier{}, cipher)
		realEmail := "user@example.com"
		reg := region.EU

		// Encrypt
		aad := []byte("relay-mapping-v1:" + string(reg))
		encrypted, err := cipher.Encrypt(dek, []byte(realEmail), aad)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Decrypt via store
		decrypted, err := store.DecryptMapping(encrypted, reg, dek)
		if err != nil {
			t.Fatalf("DecryptMapping() error = %v", err)
		}
		if decrypted != realEmail {
			t.Errorf("DecryptMapping() = %q, want %q", decrypted, realEmail)
		}
	})

	t.Run("fails with wrong region", func(t *testing.T) {
		store := NewStore(&mockQuerier{}, cipher)
		realEmail := "user@example.com"

		// Encrypt with EU region
		aad := []byte("relay-mapping-v1:" + string(region.EU))
		encrypted, err := cipher.Encrypt(dek, []byte(realEmail), aad)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Try to decrypt with US region (should fail)
		_, err = store.DecryptMapping(encrypted, region.US, dek)
		if err == nil {
			t.Error("DecryptMapping() with wrong region should fail")
		}
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Errorf("DecryptMapping() error = %v, want ErrDecryptionFailed", err)
		}
	})

	t.Run("fails with wrong DEK", func(t *testing.T) {
		store := NewStore(&mockQuerier{}, cipher)
		realEmail := "user@example.com"
		reg := region.EU

		// Encrypt with original DEK
		aad := []byte("relay-mapping-v1:" + string(reg))
		encrypted, err := cipher.Encrypt(dek, []byte(realEmail), aad)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		// Try to decrypt with different DEK (should fail)
		wrongDEK, _ := crypto.GenerateDEK()
		_, err = store.DecryptMapping(encrypted, reg, wrongDEK)
		if err == nil {
			t.Error("DecryptMapping() with wrong DEK should fail")
		}
	})
}

func TestStore_ListByUser(t *testing.T) {
	cipher := crypto.NewCipher()

	t.Run("returns all addresses for user", func(t *testing.T) {
		q := &mockQuerier{
			listByUserFn: func(ctx context.Context, userID pgtype.UUID) ([]db.RelayAddress, error) {
				return []db.RelayAddress{
					{
						ID:         pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
						RelayToken: "token-1",
						ClientID:   "rp1.example.com",
						State:      "active",
						Region:     "EU",
						EncMapping: []byte("enc1"),
					},
					{
						ID:         pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
						RelayToken: "token-2",
						ClientID:   "rp2.example.com",
						State:      "deactivated",
						Region:     "EU",
						EncMapping: []byte("enc2"),
					},
				}, nil
			},
		}

		store := NewStore(q, cipher)
		addresses, mappings, err := store.ListByUser(context.Background(), "550e8400-e29b-41d4-a716-446655440000")

		if err != nil {
			t.Fatalf("ListByUser() error = %v", err)
		}
		if len(addresses) != 2 {
			t.Errorf("len(addresses) = %d, want 2", len(addresses))
		}
		if len(mappings) != 2 {
			t.Errorf("len(mappings) = %d, want 2", len(mappings))
		}
		if addresses[0].Token != "token-1" {
			t.Errorf("addresses[0].Token = %q, want %q", addresses[0].Token, "token-1")
		}
		if addresses[1].State != StateDeactivated {
			t.Errorf("addresses[1].State = %v, want %v", addresses[1].State, StateDeactivated)
		}
	})

	t.Run("returns empty for user with no addresses", func(t *testing.T) {
		q := &mockQuerier{
			listByUserFn: func(ctx context.Context, userID pgtype.UUID) ([]db.RelayAddress, error) {
				return []db.RelayAddress{}, nil
			},
		}

		store := NewStore(q, cipher)
		addresses, mappings, err := store.ListByUser(context.Background(), "550e8400-e29b-41d4-a716-446655440000")

		if err != nil {
			t.Fatalf("ListByUser() error = %v", err)
		}
		if len(addresses) != 0 {
			t.Errorf("len(addresses) = %d, want 0", len(addresses))
		}
		if len(mappings) != 0 {
			t.Errorf("len(mappings) = %d, want 0", len(mappings))
		}
	})
}

func TestIsDuplicateKeyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"random error", errors.New("something went wrong"), false},
		{"23505 code", errors.New("ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)"), true},
		{"unique constraint text", errors.New("unique constraint violation"), true},
		{"duplicate key text", errors.New("duplicate key value"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDuplicateKeyError(tt.err); got != tt.want {
				t.Errorf("isDuplicateKeyError() = %v, want %v", got, tt.want)
			}
		})
	}
}
