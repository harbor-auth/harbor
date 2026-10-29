package bff

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestSigninResumesBrowserBoundAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		missing, wrong, expired, personal bool
		want                              int
	}{
		{name: "bound business authorization", want: 200},
		{name: "missing nonce", missing: true, want: 400},
		{name: "wrong browser", wrong: true, want: 400},
		{name: "expired transaction", expired: true, want: 400},
		{name: "personal session cannot be used as authorization", personal: true, want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewInMemoryBFFSessionStore()
			nonce, err := NewBrowserNonce()
			if err != nil {
				t.Fatal(err)
			}
			id, err := NewRequestID()
			if err != nil {
				t.Fatal(err)
			}
			record := BFFSessionRecord{RequestID: id, ClientID: "business-portal", RedirectURI: "https://portal.example/callback", State: "original-state", Nonce: "original-nonce", CodeChallenge: "original-pkce", CodeChallengeMethod: "S256", BrowserNonceHash: HashNonce(nonce), ExpiresAt: time.Now().Add(time.Minute)}
			if tc.expired {
				record.ExpiresAt = time.Now().Add(-time.Minute)
			}
			if tc.personal {
				record.ClientID = ""
				record.RedirectURI = ""
			}
			if err := store.Create(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			h, err := NewSigninHandler(store, testSigninTemplates(t), time.Minute, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/signin?request_id="+id+"&return_to=https://untrusted.example", nil)
			if !tc.missing {
				value := nonce
				if tc.wrong {
					value = make([]byte, 32)
				}
				req.AddCookie(&http.Cookie{Name: NonceCookieName, Value: base64.RawURLEncoding.EncodeToString(value)})
			}
			response := httptest.NewRecorder()
			h.ServeSignin(response, req)
			if response.Code != tc.want {
				t.Fatalf("status=%d want %d", response.Code, tc.want)
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("resuming authorization must not replace nonce/session cookies")
			}
			if len(store.sessions) > 1 {
				t.Fatal("sign-in replaced the original authorization transaction")
			}
			if tc.want == 200 {
				body := response.Body.String()
				match := regexp.MustCompile(`returnTo: ("(?:\\.|[^"\\])*")`).FindStringSubmatch(body)
				var continuation string
				if len(match) != 2 {
					t.Fatal("missing continuation")
				}
				if err := json.Unmarshal([]byte(match[1]), &continuation); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(body, id) || continuation != "/authorize/complete?request_id="+id {
					t.Fatal("page does not resume the original authorization completion")
				}
				if strings.Contains(body, "untrusted.example") {
					t.Fatal("client return_to overrode authorization continuation")
				}
				got, err := store.Get(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				if got.ClientID != record.ClientID || got.State != record.State || got.Nonce != record.Nonce || got.CodeChallenge != record.CodeChallenge || got.RedirectURI != record.RedirectURI {
					t.Fatal("authorization transaction fields changed")
				}
			}
		})
	}
}
