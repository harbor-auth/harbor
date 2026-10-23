//go:build integration

package webauthn

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/jackc/pgx/v5"
)

func TestCredentialFlags_SQLGuards(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL is required for credential metadata integration tests")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Errorf("close integration connection: %v", err)
		}
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback integration fixture: %v", err)
		}
	}()
	q := db.New(tx)
	uid := pgUUID(uuid.New())
	if _, err := q.CreateUser(ctx, db.CreateUserParams{ID: uid, Region: "EU", Status: "active", DekWrapped: []byte("integration-fixture"), PairwiseSecret: []byte("integration-fixture")}); err != nil {
		t.Fatal(err)
	}
	credential, err := q.CreateCredential(ctx, db.CreateCredentialParams{ID: pgUUID(uuid.New()), Region: "EU", UserID: uid, Type: "passkey", WebauthnCredID: []byte(uuid.NewString()), WebauthnPubkey: []byte("fixture-key")})
	if err != nil {
		t.Fatal(err)
	}
	if credential.WebauthnFlags != nil {
		t.Fatal("historical flags must remain unknown, not false")
	}
	for _, tc := range []struct {
		name    string
		counter int64
		flags   int16
		rows    int64
	}{
		{"initialize legacy zero counter", 0, 0x1d, 1},
		{"reject conflicting initialization", 0, 0x05, 0},
		{"allow backup state change", 0, 0x0d, 1},
		{"advance counter", 2, 0x0d, 1},
		{"reject regressed counter", 1, 0x0d, 0},
		{"reject repeated nonzero counter", 2, 0x0d, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := q.UpdateCredentialSignCount(ctx, db.UpdateCredentialSignCountParams{ID: credential.ID, SignCount: tc.counter, WebauthnFlags: tc.flags})
			if err != nil || rows != tc.rows {
				t.Fatalf("update = %d, %v; want %d rows", rows, err, tc.rows)
			}
		})
	}
}
