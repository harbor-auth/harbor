//go:build integration

package clients_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/oidcapi"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type countingKeys struct {
	crypto.KeyProvider
	unwraps atomic.Int32
}

func (k *countingKeys) UnwrapKey(ctx context.Context, region, purpose string, blob []byte) ([]byte, error) {
	k.unwraps.Add(1)
	return k.KeyProvider.UnwrapKey(ctx, region, purpose, blob)
}

func rotationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL required for real PostgreSQL rotation test")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "rotation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close()
	})
	for _, name := range []string{"0008_signing_keys.up.sql", "0022_signing_key_rotation.up.sql"} {
		sql, err := os.ReadFile(filepath.Join("../../db/migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func TestIntegrationLiveSigningKeyRotation(t *testing.T) {
	ctx := context.Background()
	pool := rotationPool(t)
	local, err := crypto.NewLocalKeyProvider("integration-only-key-material-at-least-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	kp := &countingKeys{KeyProvider: local}
	timing := crypto.RotationConfig{GracePeriod: time.Hour, OverlapWindow: time.Hour}
	a := clients.NewLiveSigningKeys(pool, kp, "EU", timing)
	b := clients.NewLiveSigningKeys(pool, kp, "EU", timing)
	// Concurrent first startup must produce exactly one active key, no strays.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, keys := range []*clients.LiveSigningKeys{a, b} {
		wg.Add(1)
		go func(k *clients.LiveSigningKeys) { defer wg.Done(); errs <- k.Initialize(ctx) }(keys)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	initial, err := a.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.AllSigners()) != 1 {
		t.Fatal("concurrent startup left extra keys")
	}
	oldKid := initial.ActiveSigner().KeyID()
	issuer := oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Keys: b})
	verifier, err := oidc.NewJWTVerifier(oidc.JWTVerifierConfig{Keys: a, ExpectedIssuer: "https://rotation.test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := oidcapi.New(oidcapi.Config{Issuer: "https://rotation.test", Keys: a, Rotator: a})
	httpServer := httptest.NewServer(http.HandlerFunc(srv.GetJwks))
	defer httpServer.Close()
	issue := func() oidc.IssuedTokens {
		t.Helper()
		tok, err := issuer.Issue(ctx, oidc.IssueParams{Issuer: "https://rotation.test", ClientID: "rotation", Subject: "synthetic", Scope: "openid", AuthTime: time.Now().Unix()})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	kids := func() map[string]bool {
		t.Helper()
		res, err := http.Get(httpServer.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("JWKS status %d", res.StatusCode)
		}
		var set struct{ Keys []struct{ Kid string } }
		if err = json.NewDecoder(res.Body).Decode(&set); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, k := range set.Keys {
			out[k.Kid] = true
		}
		return out
	}
	tokenKid := func(tok string) string {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		var h struct{ Kid string }
		if err = json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		return h.Kid
	}
	old := issue()
	before := kp.unwraps.Load()
	for i := 0; i < 5; i++ {
		issue()
	}
	if kp.unwraps.Load() != before {
		t.Fatal("steady-state issuance called KMS again")
	}
	scheduled, err := a.Rotate(ctx, crypto.RotateOptions{Region: "EU"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Rotate(ctx, crypto.RotateOptions{Region: "EU"}); err == nil {
		t.Fatal("accepted overlapping pending rotations")
	}
	pending := kids()
	if !pending[oldKid] || !pending[scheduled.NewKid] || len(pending) != 2 {
		t.Fatal("live JWKS did not publish pending key")
	}
	if tokenKid(issue().AccessToken) != oldKid {
		t.Fatal("signed with pending key before grace")
	}
	if err = b.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if tokenKid(issue().AccessToken) != oldKid {
		t.Fatal("scheduler promoted before persisted deadline")
	}
	past := pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
	if err = db.New(pool).ScheduleSigningKey(ctx, db.ScheduleSigningKeyParams{Kid: scheduled.NewKid, PromoteAfter: past}); err != nil {
		t.Fatal(err)
	}
	// A restarted replica recovers the durable deadline, without an in-memory timer.
	restarted := clients.NewLiveSigningKeys(pool, kp, "EU", crypto.RotationConfig{GracePeriod: time.Hour, OverlapWindow: 0})
	if err = restarted.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	fresh := issue()
	if tokenKid(fresh.AccessToken) != scheduled.NewKid || tokenKid(fresh.IDToken) != scheduled.NewKid {
		t.Fatal("issuer did not follow promotion coherently")
	}
	if _, err = verifier.Verify(ctx, old.AccessToken); err != nil {
		t.Fatalf("overlap rejected old token: %v", err)
	}
	if !kids()[oldKid] {
		t.Fatal("overlap lost old JWKS key")
	}
	if err = restarted.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if kids()[oldKid] {
		t.Fatal("retired key still in live JWKS")
	}
	if _, err = verifier.Verify(ctx, old.AccessToken); err == nil {
		t.Fatal("retired token still verifies")
	}
	emergency, err := b.Rotate(ctx, crypto.RotateOptions{Region: "EU", Emergency: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := kids(); len(got) != 1 || !got[emergency.NewKid] {
		t.Fatal("emergency rotation did not replace live JWKS")
	}
	if _, err = verifier.Verify(ctx, fresh.AccessToken); err == nil {
		t.Fatal("emergency-retired token still verifies")
	}
	newest := issue()
	if tokenKid(newest.AccessToken) != emergency.NewKid {
		t.Fatal("issuer retained emergency-retired key")
	}
	if _, err = verifier.Verify(ctx, newest.AccessToken); err != nil {
		t.Fatal(err)
	}

	// Concurrent administrators cannot enqueue multiple pending keys; emergency
	// rotation also cancels the winning pending key without publishing it again.
	rotations := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := a.Rotate(ctx, crypto.RotateOptions{Region: "EU"}); rotations <- err }()
	}
	wg.Wait()
	close(rotations)
	successes := 0
	for err := range rotations {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent scheduled rotations succeeded %d times", successes)
	}
	last, err := b.Rotate(ctx, crypto.RotateOptions{Region: "EU", Emergency: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := kids(); len(got) != 1 || !got[last.NewKid] {
		t.Fatal("emergency retained pending or draining keys")
	}
	newest = issue()
	pool.Close()
	if _, err = issuer.Issue(ctx, oidc.IssueParams{}); err == nil {
		t.Fatal("signed from stale cache after DB loss")
	}
	res, err := http.Get(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 503 || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("JWKS failed open after DB loss")
	}
	if _, err = verifier.Verify(ctx, newest.AccessToken); err == nil {
		t.Fatal("verified from stale cache after DB loss")
	}
}
