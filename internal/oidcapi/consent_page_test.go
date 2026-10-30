package oidcapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/bff"
	bfftest "github.com/harbor-auth/harbor/internal/testsupport/bff"
)

func TestConsentPageUsesBoundSessionAndStyledTemplate(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		missing, wrong, notPending bool
		want                       int
	}{
		{name: "business consent", want: 200},
		{name: "missing nonce", missing: true, want: 400},
		{name: "foreign browser", wrong: true, want: 400},
		{name: "not awaiting consent", notPending: true, want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := bfftest.NewInMemoryBFFSessionStore()
			nonce, err := bff.NewBrowserNonce()
			if err != nil {
				t.Fatal(err)
			}
			record := bff.BFFSessionRecord{RequestID: "request", UserID: "user", ClientID: "business", RedirectURI: "https://portal.example/callback", Scope: "openid email profile", ConsentPending: !tc.notPending, BrowserNonceHash: bff.HashNonce(nonce), ExpiresAt: time.Now().Add(time.Minute)}
			if err := store.Create(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			server := &Server{bffSessions: store}
			request := httptest.NewRequest("GET", "/consent?request_id=request&client_name=untrusted.example", nil)
			if !tc.missing {
				value := nonce
				if tc.wrong {
					value = make([]byte, 32)
				}
				request.AddCookie(&http.Cookie{Name: bff.NonceCookieName, Value: base64.RawURLEncoding.EncodeToString(value)})
			}
			response := httptest.NewRecorder()
			server.GetConsent(response, request)
			if response.Code != tc.want {
				t.Fatalf("status %d want %d", response.Code, tc.want)
			}
			if tc.want != 200 {
				return
			}
			body := response.Body.String()
			for _, text := range []string{"<style>", "<main", "portal.example", "Your private relay email address", "Your account ID for this app", "Approve and continue", `value="approve"`, `value="deny"`, `value="request"`} {
				if !strings.Contains(body, text) {
					t.Errorf("missing %q", text)
				}
			}
			if strings.Contains(body, "untrusted.example") {
				t.Fatal("untrusted client name reached consent page")
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("consent response must not be cached")
			}
		})
	}
}
