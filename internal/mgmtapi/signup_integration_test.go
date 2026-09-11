//go:build integration

package mgmtapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/signup"
	"github.com/harbor-auth/harbor/internal/webauthn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Real SQL migrations, Redis/Lua, crypto, signup, and HTTP handlers. Only the
// external mail delivery boundary is captured; no authorization is stubbed.
type integrationMail struct{ code string }

func (m *integrationMail) SendCode(_ context.Context, _, code string) error {
	m.code = code
	return nil
}
func TestEmailSignupIntegration(t *testing.T) {
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, requiredIntegrationDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "signup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgxpool.ParseConfig(requiredIntegrationDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	paths, err := filepath.Glob("../../db/migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	opts, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		t.Fatal("REDIS_URL required", err)
	}
	rc := redis.NewClient(opts)
	defer func() {
		if err := rc.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err = rc.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	keys, err := crypto.NewLocalKeyProvider(strings.Repeat("z", 32))
	if err != nil {
		t.Fatal(err)
	}
	identifiers := clients.NewDBIdentifierStore(pool, keys, crypto.NewCipher())
	enroller := identity.NewEnroller(keys, crypto.NewCipher(), clients.NewDBUserPersister(q))
	mail := &integrationMail{}
	flow, err := signup.New(signup.NewRedisChallenges(rc), mail, keys, bytes.Repeat([]byte{3}, 32), enroller, identifiers)
	if err != nil {
		t.Fatal(err)
	}
	sessions := NewRedisEnrollmentSessionStore(rc)
	s, err := New(enroller, sessions, &fakeClientReg{}, testRegBaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.WithEmailSignup(flow).WithSignupRegion("EU")
	email := "signup-" + uuid.NewString() + "@example.com"
	body, err := json.Marshal(map[string]string{"email": email, "region": "EU"})
	if err != nil {
		t.Fatal(err)
	}
	start := signupRequest(s, "/enroll", string(body))
	if start.Code != 202 {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil || count != 0 {
		t.Fatal("unverified user persisted", err)
	}
	done := signupRequest(s, "/enroll/verify", `{"code":"`+mail.code+`"}`, start.Result().Cookies()[0])
	if done.Code != 201 {
		t.Fatalf("verify: %d %s", done.Code, done.Body)
	}
	var result enrollResponse
	if err = json.Unmarshal(done.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	uid := pgtype.UUID{Bytes: uuid.MustParse(result.UserID), Valid: true}
	handle := uid.Bytes[:]
	user, err := webauthn.NewDBStore(q).WithAccountLabels(identifiers).GetUser(ctx, handle)
	if err != nil || user.WebAuthnName() != email || !user.RecoveryRequired() {
		t.Fatalf("label/recovery: %+v %v", user, err)
	}
	bundle, err := identity.NewExportBundler(q, q, q, q, keys, crypto.NewCipher()).WithIdentifiers(q).Assemble(ctx, result.UserID)
	if err != nil || len(bundle.Identifiers) != 1 || bundle.Identifiers[0].Value != email {
		t.Fatalf("export: %+v %v", bundle, err)
	}
	// A second verified signup cannot acquire the existing account, even pending.
	start = signupRequest(s, "/enroll", string(body))
	duplicate := signupRequest(s, "/enroll/verify", `{"code":"`+mail.code+`"}`, start.Result().Cookies()[0])
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", duplicate.Code, duplicate.Body)
	}
	for _, c := range duplicate.Result().Cookies() {
		if c.Name == EnrollmentSessionCookieName {
			t.Fatal("duplicate minted authority")
		}
	}
	// Expired credential-free accounts can be safely replaced.
	if _, err = pool.Exec(ctx, "UPDATE users SET created_at=now()-interval '21 minutes' WHERE id=$1", uid); err != nil {
		t.Fatal(err)
	}
	next, err := enroller.EnrollIdentified(ctx, "EU", "email", email, flow.Lookup("EU", email), identifiers)
	if err != nil || next.UserID == result.UserID {
		t.Fatal("expired enrollment was not replaced", err)
	}
	// Active accounts are never replaced, regardless of age.
	if _, err = pool.Exec(ctx, "UPDATE users SET status='active',created_at=now()-interval '1 day' WHERE id=$1", next.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = enroller.EnrollIdentified(ctx, "EU", "email", email, flow.Lookup("EU", email), identifiers); !errors.Is(err, identity.ErrIdentifierExists) {
		t.Fatal("active account replaced", err)
	}
	// Concurrent verified requests for a fresh destination commit one user only.
	concurrentEmail := uuid.NewString() + "@example.com"
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := enroller.EnrollIdentified(ctx, "EU", "email", concurrentEmail, flow.Lookup("EU", concurrentEmail), identifiers)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, identity.ErrIdentifierExists) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent accounts: %d", successes)
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil || count != 2 {
		t.Fatalf("partial transaction: users=%d %v", count, err)
	}
	// The normal erasure SQL also destroys lookup material, releasing the email.
	if err = q.EraseUserDEK(ctx, pgtype.UUID{Bytes: uuid.MustParse(next.UserID), Valid: true}); err != nil {
		t.Fatal(err)
	}
	rows, err := q.ListAccountIdentifiers(ctx, pgtype.UUID{Bytes: uuid.MustParse(next.UserID), Valid: true})
	if err != nil || len(rows) != 0 {
		t.Fatal("erasure retained identifier", err)
	}
	if _, err = enroller.EnrollIdentified(ctx, "EU", "email", email, flow.Lookup("EU", email), identifiers); err != nil {
		t.Fatal("erased identifier not released", err)
	}

	// Cleanup must preserve even an expired pending account if a credential exists.
	credentialEmail := uuid.NewString() + "@example.com"
	pending, err := enroller.EnrollIdentified(ctx, "EU", "email", credentialEmail, flow.Lookup("EU", credentialEmail), identifiers)
	if err != nil {
		t.Fatal(err)
	}
	pendingID := uuid.MustParse(pending.UserID)
	credentialStore := webauthn.NewDBStore(q).WithPool(pool)
	if err = credentialStore.AddCredential(ctx, pendingID[:], gowebauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET created_at=now()-interval '1 day' WHERE id=$1", pending.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = enroller.EnrollIdentified(ctx, "EU", "email", credentialEmail, flow.Lookup("EU", credentialEmail), identifiers); !errors.Is(err, identity.ErrIdentifierExists) {
		t.Fatal("credential-bearing pending account replaced", err)
	}
	// Race first-passkey activation against cleanup. Exactly one ownership wins;
	// activation must never leave a credential attached to a deleted account.
	for range 8 {
		email := uuid.NewString() + "@example.com"
		old, err := enroller.EnrollIdentified(ctx, "EU", "email", email, flow.Lookup("EU", email), identifiers)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, "UPDATE users SET created_at=now()-interval '1 day' WHERE id=$1", old.UserID); err != nil {
			t.Fatal(err)
		}
		id := uuid.MustParse(old.UserID)
		startRace := make(chan struct{})
		activated := make(chan error, 1)
		go func() {
			<-startRace
			activated <- credentialStore.AddCredentialAndActivateUser(ctx, id[:], gowebauthn.Credential{ID: []byte(uuid.NewString()), PublicKey: []byte{1}})
		}()
		close(startRace)
		replacement, replaceErr := enroller.EnrollIdentified(ctx, "EU", "email", email, flow.Lookup("EU", email), identifiers)
		activationErr := <-activated
		if activationErr == nil {
			if !errors.Is(replaceErr, identity.ErrIdentifierExists) {
				t.Fatalf("activated account replaced: %v", replaceErr)
			}
			row, err := q.GetUser(ctx, pgtype.UUID{Bytes: id, Valid: true})
			if err != nil || row.Status != "active" {
				t.Fatal("active account lost", err)
			}
		} else if replaceErr != nil || replacement.UserID == old.UserID {
			t.Fatalf("neither race contender won: activation=%v replacement=%v", activationErr, replaceErr)
		}
	}
	// Rollback is executable after the application has stopped using identifiers.
	down, err := os.ReadFile("../../db/migrations/0022_account_identifiers.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(down)); err != nil {
		t.Fatal("rollback", err)
	}
}
