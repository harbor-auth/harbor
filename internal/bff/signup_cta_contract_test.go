package bff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/web"
)

// TestSignupCTAContract_PublishedURLsReturn200HTML is the executable
// verification referenced by docs/design/product/signup-cta-contract.md. It
// wires SignupHandler and SigninHandler onto a mux the same way
// cmd/harbor-mgmt/main.go does (Routes / HandleFunc) and proves each of the
// three published CTA URLs returns 200 text/html — the "done when" bar the
// contract doc holds itself to. If any of these regress, the contract doc is
// now describing behavior that no longer exists and must be updated in the
// same change.
func TestSignupCTAContract_PublishedURLsReturn200HTML(t *testing.T) {
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}

	signupHandler, err := NewSignupHandler(tmpl, nil, nil, []string{"marketing.example.com"}, nil)
	if err != nil {
		t.Fatalf("NewSignupHandler: %v", err)
	}
	signinHandler, err := NewSigninHandler(NewInMemoryBFFSessionStore(), tmpl, 5*time.Minute, []string{"marketing.example.com"}, nil)
	if err != nil {
		t.Fatalf("NewSigninHandler: %v", err)
	}

	mux := http.NewServeMux()
	signupHandler.Routes(mux)
	mux.HandleFunc("GET /signin", signinHandler.ServeSignin)

	tests := []struct {
		name           string
		target         string
		wantBodyHasAny []string
	}{
		{
			name:           "GET /signup",
			target:         "/signup",
			wantBodyHasAny: []string{"Choose your region"},
		},
		{
			name:           "GET /signup?return_to=&region= (inert, still 200)",
			target:         "/signup?return_to=" + "https%3A%2F%2Fmarketing.example.com%2Fwelcome" + "&region=EU",
			wantBodyHasAny: []string{"Choose your region"},
		},
		{
			name:           "GET /signin?return_to=",
			target:         "/signin?return_to=" + "https%3A%2F%2Fmarketing.example.com%2Fwelcome",
			wantBodyHasAny: []string{"navigator.credentials.get"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.target, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200", tt.target, w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("%s Content-Type = %q, want text/html", tt.target, ct)
			}
			body := w.Body.String()
			for _, want := range tt.wantBodyHasAny {
				if !strings.Contains(body, want) {
					t.Errorf("%s body missing %q", tt.target, want)
				}
			}
		})
	}
}

// Rejected destinations and the inert region parameter cannot alter the page.
// Accepted destinations are covered by the signup-to-signin handoff tests.
func TestSignupCTAContract_RejectedQueryParamsAreInert(t *testing.T) {
	h := newTestSignupHandler(t)

	plain := httptest.NewRequest(http.MethodGet, "/signup", nil)
	plainRec := httptest.NewRecorder()
	h.GetSignup(plainRec, plain)

	withParams := httptest.NewRequest(http.MethodGet, "/signup?return_to=https%3A%2F%2Fmarketing.example.com%2Fwelcome&region=US", nil)
	withParamsRec := httptest.NewRecorder()
	h.GetSignup(withParamsRec, withParams)

	if plainRec.Body.String() != withParamsRec.Body.String() {
		t.Error("rejected return_to or region changed the signup page")
	}
	if strings.Contains(withParamsRec.Body.String(), "marketing.example.com") {
		t.Error("signup echoed a rejected return_to")
	}
}
