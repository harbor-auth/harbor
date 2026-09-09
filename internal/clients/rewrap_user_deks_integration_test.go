//go:build integration

package clients_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
)

func TestIntegrationUserDEKRewrapPreservesCiphertextAndErasure(t *testing.T) {
	pool := rotationPool(t)
	ctx := context.Background()
	schema, err := os.ReadFile("../../db/migrations/0001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	legacy, err := crypto.NewLocalKeyProvider("legacy-user-dek-secret-with-at-least-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	kms := crypto.NewKMSKeyProvider(crypto.NewFakeKMSClient(), crypto.NewStaticKEKResolver(map[string]string{"EU": "users-eu"}))
	bridge := crypto.NewUserKeyProvider(kms, legacy)
	final := crypto.NewUserKeyProvider(kms, nil)
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	old, err := legacy.WrapDEK(ctx, "EU", dek)
	if err != nil {
		t.Fatal(err)
	}
	cipher := crypto.NewCipher()
	secret := []byte("pairwise-secret-must-remain-identical")
	encrypted, err := cipher.Encrypt(dek, secret, []byte("user"))
	if err != nil {
		t.Fatal(err)
	}
	const active = "00000000-0000-0000-0000-000000000001"
	const erased = "00000000-0000-0000-0000-000000000002"
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,region,status,dek_wrapped,pairwise_secret) VALUES($1,'EU','active',$2,$3),($4,'EU','erased',''::bytea,$3)`, active, old, encrypted, erased); err != nil {
		t.Fatal(err)
	}
	count, err := clients.RewrapUserDEKs(ctx, pool, bridge)
	if err != nil || count != 1 {
		t.Fatalf("rewrap count %d: %v", count, err)
	}
	var wrapped, payload []byte
	if err := pool.QueryRow(ctx, "SELECT dek_wrapped,pairwise_secret FROM users WHERE id=$1", active).Scan(&wrapped, &payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, encrypted) {
		t.Fatal("migration changed user ciphertext")
	}
	got, err := final.UnwrapDEK(ctx, "EU", wrapped)
	if err != nil || got != dek {
		t.Fatal("migration changed DEK", err)
	}
	plain, err := cipher.Decrypt(got, payload, []byte("user"))
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("pairwise secret changed", err)
	}
	if count, err := clients.RewrapUserDEKs(ctx, pool, bridge); err != nil || count != 0 {
		t.Fatal("migration is not idempotent", count, err)
	}
	// Restore a fixture envelope, then hold an erasure transaction open. Rewrap
	// must wait on the row lock instead of overwriting the erased key afterward.
	if _, err := pool.Exec(ctx, "UPDATE users SET dek_wrapped=$1 WHERE id=$2", old, active); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE users SET dek_wrapped=''::bytea,status='erased' WHERE id=$1", active); err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, blockedErr := clients.RewrapUserDEKs(blocked, pool, bridge)
	cancel()
	if blockedErr == nil {
		t.Fatal("rewrap bypassed the erasure row lock")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if count, err := clients.RewrapUserDEKs(ctx, pool, bridge); err != nil || count != 0 {
		t.Fatal("erased keys were restored", count, err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE octet_length(dek_wrapped)>0").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("erased DEK was resurrected")
	}
	// Unknown nonempty envelopes must stop migration, never be reported complete.
	if _, err := pool.Exec(ctx, "UPDATE users SET dek_wrapped=$1 WHERE id=$2", []byte("corrupt"), active); err != nil {
		t.Fatal(err)
	}
	if _, err := clients.RewrapUserDEKs(ctx, pool, bridge); err == nil {
		t.Fatal("corrupt envelope silently skipped")
	}
}
