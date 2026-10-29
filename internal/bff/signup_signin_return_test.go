package bff

import (
	"html"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
)

func TestSignupExistingAccountLinkPreservesBusinessAuthorization(t *testing.T) {
	authorization := "/authorize?client_id=business-portal&redirect_uri=https%3A%2F%2Fportal.example%2Fcallback&scope=openid+email&state=opaque-state&nonce=opaque-nonce&code_challenge=pkce-challenge&code_challenge_method=S256"
	for _, tc := range []struct{ name, destination, want string }{
		{"business transaction", authorization, authorization},
		{"default", "", ""},
		{"foreign host", "https://untrusted.example/steal", ""},
		{"protocol relative", "//untrusted.example/steal", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestSignupHandler(t)
			request := httptest.NewRequest("GET", "/signup?"+url.Values{"return_to": {tc.destination}}.Encode(), nil)
			response := httptest.NewRecorder()
			h.GetSignup(response, request)
			match := regexp.MustCompile(`class="signin-link" href="([^"]+)"`).FindStringSubmatch(response.Body.String())
			if len(match) != 2 {
				t.Fatal("missing existing-account sign-in link")
			}
			link, err := url.Parse(html.UnescapeString(match[1]))
			if err != nil {
				t.Fatal(err)
			}
			if link.IsAbs() || link.Path != "/signin" {
				t.Fatalf("unexpected sign-in destination %q", link)
			}
			if got := link.Query().Get("return_to"); got != tc.want {
				t.Fatalf("sign-in return destination = %q, want %q", got, tc.want)
			}
		})
	}
}
