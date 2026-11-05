//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/web"
)

// localhost and 127.0.0.1 are distinct browser sites. An actual RP document
// initiates navigation, so Chrome evaluates SameSite over the redirect chain.
// The hot startup, authorization validation, Redis transactions and sign-in
// handler are real; only the external signing KMS HTTP service is simulated.
func TestCrossSiteAuthorizationReachesBoundSignin(t *testing.T) {
	pool, dsn := userInfoDatabase(t)
	if os.Getenv("REDIS_URL") == "" {
		t.Fatal("REDIS_URL is required")
	}
	kms := userInfoKMS(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rdb, err := clients.ConnectRedis(t.Context(), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Error(err)
		}
	})
	sessions := bff.NewRedisBFFSessionStore(rdb, 5*time.Minute)
	templates, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatal(err)
	}
	signin, err := bff.NewSigninHandler(sessions, templates, 5*time.Minute, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	type arrival struct {
		id, site string
		hasNonce bool
	}
	arrivals := make(chan arrival, 4)
	var hot http.Handler
	var authorizationURL string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /rp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		target, err := json.Marshal(authorizationURL)
		if err != nil {
			t.Error(err)
			http.Error(w, "cannot encode authorization URL", http.StatusInternalServerError)
			return
		}
		if _, err := io.WriteString(w, "<!doctype html><title>External RP</title><script>location.assign("+string(target)+")</script>"); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("GET /signin", func(w http.ResponseWriter, r *http.Request) {
		_, nonceErr := bff.ReadBFFNonceCookie(r)
		arrivals <- arrival{r.URL.Query().Get("request_id"), r.Header.Get("Sec-Fetch-Site"), nonceErr == nil}
		signin.ServeSignin(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { hot.ServeHTTP(w, r) })
	server := httptest.NewUnstartedServer(mux)
	t.Cleanup(server.Close)
	rpBase := "http://" + server.Listener.Addr().String()
	issuer := strings.Replace(rpBase, "127.0.0.1", "localhost", 1)
	callback := rpBase + "/callback"
	for key, value := range map[string]string{
		"DATABASE_URL": dsn, "KMS_PROVIDER": "aws", "KMS_KEY_MAP": "EU=browser-signing-key",
		"AWS_ENDPOINT_URL": kms.URL, "AWS_ENDPOINT_URL_KMS": kms.URL,
		"AWS_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
		"AWS_EC2_METADATA_DISABLED": "true", "USER_DEK_PROVIDER": "local",
		"HARBOR_KMS_SECRET": "browser-user-envelope-root-at-least-32-bytes",
		"ISSUER":            issuer, "LOGIN_URL": issuer + "/signin", "ADMIN_API_TOKEN": "browser-admin-token-at-least-32-bytes",
		"ADDR": "127.0.0.1:0", "REGION": "EU", "RATE_LIMIT_DISABLED": "false",
		"INTERNAL_SERVICE_HOST": "harbor-hot.harbor.svc.cluster.local",
	} {
		t.Setenv(key, value)
	}
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
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("hot server did not stop")
		}
	})
	select {
	case hot = <-observed:
	case err := <-stopped:
		t.Fatalf("startup: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("startup timeout")
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO relying_parties(client_id,name,token_format,token_endpoint_auth_method,sector_id,redirect_uris,scopes_allowed) VALUES ('external-rp','External RP','jwt','none','127.0.0.1',ARRAY[$1],ARRAY['openid'])`, callback); err != nil {
		t.Fatal(err)
	}
	params := url.Values{"client_id": {"external-rp"}, "response_type": {"code"}, "redirect_uri": {callback}, "scope": {"openid"}, "state": {"rp-state"}, "nonce": {"rp-nonce"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	authorizationURL = issuer + "/authorize?" + params.Encode()
	server.Start()
	dom := chromeDocument(t, rpBase+"/rp")
	var got arrival
	select {
	case got = <-arrivals:
	default:
		t.Fatal("browser did not reach sign-in")
	}
	if got.site != "cross-site" {
		t.Fatalf("navigation site=%q, want cross-site", got.site)
	}
	if !got.hasNonce || strings.Contains(dom, "invalid or expired sign-in request") || !strings.Contains(dom, "Sign in — Harbor") {
		t.Fatal("fresh cross-site authorization did not reach its browser-bound sign-in page")
	}
	record, err := sessions.Get(t.Context(), got.id)
	if err != nil {
		t.Fatal(err)
	}
	if record.ClientID != "external-rp" || record.RedirectURI != callback || record.State != "rp-state" || record.Nonce != "rp-nonce" || record.CodeChallenge != params.Get("code_challenge") || record.CodeChallengeMethod != "S256" || record.UserID != "" {
		t.Fatal("authorization transaction replaced or modified")
	}
	t.Cleanup(func() {
		if err := sessions.Delete(context.Background(), got.id); err != nil {
			t.Error(err)
		}
	})
	// A fresh browser cannot use the transaction URL without its matching nonce.
	missing := chromeDocument(t, issuer+"/signin?request_id="+url.QueryEscape(got.id))
	if !strings.Contains(missing, "invalid or expired sign-in request") {
		t.Fatal("another browser resumed the transaction without its nonce")
	}
	req := httptest.NewRequest(http.MethodGet, issuer+"/signin?request_id="+url.QueryEscape(got.id), nil)
	req.AddCookie(&http.Cookie{Name: bff.NonceCookieName, Value: strings.Repeat("A", 43)})
	w := httptest.NewRecorder()
	signin.ServeSignin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong nonce: status %d", w.Code)
	}
}

func chromeDocument(t *testing.T, target string) string {
	t.Helper()
	binary := os.Getenv("CHROME_BIN")
	if binary == "" {
		for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
			if path, err := exec.LookPath(name); err == nil {
				binary = path
				break
			}
		}
	}
	if binary == "" && runtime.GOOS == "darwin" {
		binary = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if binary == "" {
		t.Fatal("Chrome is required for the cross-site cookie integration test (set CHROME_BIN)")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--headless", "--no-first-run", "--no-default-browser-check", "--disable-sync", "--disable-background-networking", "--user-data-dir="+t.TempDir(), "--dump-dom", "--timeout=15000", "--virtual-time-budget=1000", target)
	var output, stderr bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Chrome document probe: %v", err)
	}
	return output.String()
}
