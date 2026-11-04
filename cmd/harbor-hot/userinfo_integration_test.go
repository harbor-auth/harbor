//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the external AWS KMS HTTP boundary is simulated. Startup, middleware,
// signing, user encryption, PostgreSQL, Redis, token exchange and UserInfo are
// production implementations. Fixtures begin at completed consent/code issuance.
func TestProductionUserInfoHTTPChain(t *testing.T) {
	pool, dsn := userInfoDatabase(t)
	if os.Getenv("REDIS_URL") == "" {
		t.Skip("REDIS_URL is required")
	}
	kms := userInfoKMS(t)
	for key, value := range map[string]string{
		"DATABASE_URL": dsn, "KMS_PROVIDER": "aws", "KMS_KEY_MAP": "EU=signing-key",
		"AWS_ENDPOINT_URL": kms.URL, "AWS_ENDPOINT_URL_KMS": kms.URL,
		"AWS_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
		"AWS_EC2_METADATA_DISABLED": "true", "USER_DEK_PROVIDER": "local",
		"HARBOR_KMS_SECRET": "separate-user-envelope-root-at-least-32-bytes",
		"ISSUER":            "https://eu.harbor.id", "LOGIN_URL": "https://eu.harbor.id/login",
		"ADMIN_API_TOKEN": "integration-admin-token-at-least-32-bytes", "ADDR": "127.0.0.1:0",
		"REGION": "EU", "RATE_LIMIT_DISABLED": "false", "INTERNAL_SERVICE_HOST": "harbor-hot.harbor.svc.cluster.local",
	} {
		t.Setenv(key, value)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(t.Context())
	observed := make(chan http.Handler, 1)
	stopped := make(chan error, 1)
	go func() {
		stopped <- runWithGraphObserver(ctx, logger, func(_ hotGraph, h http.Handler) { observed <- h })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-stopped:
			if err != nil {
				t.Errorf("production shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("production server did not stop")
		}
	})
	var handler http.Handler
	select {
	case handler = <-observed:
	case err := <-stopped:
		t.Fatalf("production startup: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("production startup timed out")
	}

	keys, err := crypto.NewUserKeyProviderFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ids := clients.NewDBIdentifierStore(pool, keys, crypto.NewCipher())
	enroll := identity.NewEnroller(keys, crypto.NewCipher(), clients.NewDBUserPersister(db.New(pool)))
	hash := sha256.Sum256([]byte("region-smoke@example.test"))
	user, err := enroll.EnrollIdentified(region.WithRegion(t.Context(), region.EU), "EU", "email", "region-smoke@example.test", hash[:], ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), "UPDATE users SET status='active' WHERE id=$1", user.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO relying_parties(client_id,name,token_format,token_endpoint_auth_method,sector_id,redirect_uris,scopes_allowed) VALUES ('region-client','Region client','jwt','none','site.example',ARRAY['https://site.example/cb'],ARRAY['openid','email'])`); err != nil {
		t.Fatal(err)
	}
	grant, err := clients.NewDBGrantStore(db.New(pool)).CreateGrant(t.Context(), oidc.NewGrant{Region: "EU", UserID: user.UserID, ClientID: "region-client", PairwiseSub: "region-subject", Scopes: []string{"openid", "email"}, EmailConsent: true})
	if err != nil {
		t.Fatal(err)
	}
	rdb, err := clients.ConnectRedis(t.Context(), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Error(err)
		}
	})
	codes := oidc.NewRedisAuthCodeStore(rdb, time.Minute)
	verifier := strings.Repeat("v", 43)
	challenge := sha256.Sum256([]byte(verifier))
	var sharedToken string
	for _, scope := range []string{"openid", "openid email"} {
		code := uuid.NewString()
		if err = codes.Save(t.Context(), oidc.AuthCode{Code: code, ClientID: "region-client", RedirectURI: "https://site.example/cb", Scope: scope, Subject: grant.PairwiseSub, UserID: user.UserID, GrantID: grant.ID, Nonce: "nonce", CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute), AuthTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := rdb.Del(context.Background(), "authcode:"+code, "authcode:consumed:"+code).Err(); err != nil {
				t.Error(err)
			}
		})
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"region-client"}, "redirect_uri": {"https://site.example/cb"}, "code_verifier": {verifier}}
		req := httptest.NewRequest(http.MethodPost, "https://eu.harbor.id/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("production token exchange: %d", w.Code)
		}
		var tokens struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil || tokens.AccessToken == "" {
			t.Fatal("missing access token")
		}
		// No region is placed on this request by the test: production middleware must do it.
		req = httptest.NewRequest(http.MethodGet, "https://eu.harbor.id/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("production UserInfo (%s): %d %s", scope, w.Code, w.Body.String())
		}
		var info map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		if info["sub"] != grant.PairwiseSub {
			t.Fatal("wrong UserInfo subject")
		}
		if scope == "openid" && info["email"] != nil {
			t.Fatal("email disclosed without scope")
		}
		if scope == "openid email" {
			if info["email"] != "region-smoke@example.test" || info["email_verified"] != true {
				t.Fatal("verified user email missing")
			}
			sharedToken = tokens.AccessToken
		}
	}
	for _, tc := range []struct {
		url    string
		status int
	}{
		{"https://us.harbor.id/userinfo", http.StatusUnauthorized},
		{"https://unknown.example/userinfo", http.StatusBadRequest},
		{"http://localhost/healthz", http.StatusOK},
		{"http://localhost/.well-known/openid-configuration", http.StatusOK},
		{"http://localhost/jwks.json", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		req.Header.Set("Authorization", "Bearer "+sharedToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d", tc.url, w.Code, tc.status)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "http://harbor-hot.harbor.svc.cluster.local/admin/keys/rotate", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("internal admin host must require authentication, got %d", w.Code)
	}

}

func userInfoDatabase(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "hot_userinfo_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	pool, err := pgxpool.New(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	files, err := filepath.Glob("../../db/migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("migration files missing")
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(t.Context(), string(raw)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	return pool, u.String()
}

func userInfoKMS(t *testing.T) *httptest.Server {
	t.Helper()
	backend := crypto.NewFakeKMSClient()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			KeyID          string `json:"KeyId"`
			Plaintext      []byte
			CiphertextBlob []byte
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		var body map[string]any
		var err error
		switch {
		case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".Encrypt"):
			var value []byte
			value, err = backend.Encrypt(r.Context(), in.KeyID, in.Plaintext)
			body = map[string]any{"KeyId": in.KeyID, "CiphertextBlob": value}
		case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".Decrypt"):
			var value []byte
			value, err = backend.Decrypt(r.Context(), in.KeyID, in.CiphertextBlob)
			body = map[string]any{"KeyId": in.KeyID, "Plaintext": value}
		default:
			http.Error(w, "unsupported operation", 400)
			return
		}
		if err != nil {
			http.Error(w, "KMS operation failed", 400)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode KMS response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}
