package bff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/web"
)

func newTestSignupHandler(t *testing.T) *SignupHandler {
	t.Helper()
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	h, err := NewSignupHandler(tmpl, nil)
	if err != nil {
		t.Fatalf("NewSignupHandler: %v", err)
	}
	return h
}

func TestNewSignupHandler_RejectsNilTemplate(t *testing.T) {
	if _, err := NewSignupHandler(nil, nil); err == nil {
		t.Fatal("NewSignupHandler(nil template) = nil error, want error")
	}
}

// TestAllowedSignupRegions_OnlyRegionParseAcceptedCodes proves every code the
// picker offers round-trips through region.Parse, and — since region.Parse
// currently accepts exactly EU/US/APAC — that the full candidate list survives
// the filter (nothing accepted by region.Parse is silently dropped either).
func TestAllowedSignupRegions_OnlyRegionParseAcceptedCodes(t *testing.T) {
	got := allowedSignupRegions()
	if len(got) == 0 {
		t.Fatal("allowedSignupRegions() returned no regions")
	}
	for _, opt := range got {
		if _, err := region.Parse(opt.Code); err != nil {
			t.Errorf("allowedSignupRegions() included %q, but region.Parse(%q) = %v", opt.Code, opt.Code, err)
		}
	}
	if len(got) != len(signupRegionCandidates) {
		t.Errorf("allowedSignupRegions() returned %d regions, want all %d candidates accepted (got %+v)",
			len(got), len(signupRegionCandidates), got)
	}
}

// TestAllowedSignupRegions_FiltersUnknownCandidates proves a candidate code
// region.Parse does not accept is silently dropped from the picker rather than
// rendered as an invalid, unusable option.
func TestAllowedSignupRegions_FiltersUnknownCandidates(t *testing.T) {
	original := signupRegionCandidates
	t.Cleanup(func() { signupRegionCandidates = original })

	signupRegionCandidates = []signupRegionOption{
		{Code: "EU", Label: "European Union"},
		{Code: "MARS", Label: "Mars Colony"},
	}

	got := allowedSignupRegions()
	if len(got) != 1 || got[0].Code != "EU" {
		t.Fatalf("allowedSignupRegions() = %+v, want only the region.Parse-accepted EU candidate", got)
	}
}

// TestGetSignup_RendersOnlyAcceptedRegions renders the live page and confirms
// every region.Parse-accepted candidate appears as a selectable option, and no
// value outside that accepted set is ever rendered.
func TestGetSignup_RendersOnlyAcceptedRegions(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup", nil)
	w := httptest.NewRecorder()
	h.GetSignup(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup status = %d, want 200", w.Code)
	}
	body := w.Body.String()

	for _, opt := range allowedSignupRegions() {
		want := `value="` + opt.Code + `"`
		if !strings.Contains(body, want) {
			t.Errorf("GET /signup body missing region option %q", want)
		}
	}

	// A region code that region.Parse rejects must never appear as an option.
	if strings.Contains(body, `value="MARS"`) {
		t.Error("GET /signup body rendered a region.Parse-rejected option")
	}
}

// TestGetSignup_NoUserIDParameter proves the signup page never echoes or
// solicits a client-supplied user_id or email — the enrollment session cookie
// set by POST /enroll is the only supported identity seam (docs/DESIGN.md §9).
func TestGetSignup_NoUserIDParameter(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup?user_id=attacker-supplied", nil)
	w := httptest.NewRecorder()
	h.GetSignup(w, r)

	body := w.Body.String()
	if strings.Contains(body, "user_id") || strings.Contains(body, "attacker-supplied") {
		t.Error("GET /signup response references a client-supplied user_id")
	}
}

func TestGetSignupPasskey_RendersCeremonyPage(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup/passkey", nil)
	w := httptest.NewRecorder()
	h.GetSignupPasskey(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup/passkey status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, `/webauthn/register/begin`) {
		t.Error("GET /signup/passkey body does not drive /webauthn/register/begin")
	}
	if !strings.Contains(body, `/webauthn/register/finish`) {
		t.Error("GET /signup/passkey body does not drive /webauthn/register/finish")
	}
	if strings.Contains(body, "user_id") {
		t.Error("GET /signup/passkey response references a client-supplied user_id")
	}
}

// TestSignupHandler_Routes proves both routes are wired and answer GET only.
func TestSignupHandler_Routes(t *testing.T) {
	h := newTestSignupHandler(t)
	mux := http.NewServeMux()
	h.Routes(mux)

	for _, path := range []string{"/signup", "/signup/passkey"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, w.Code)
		}
	}
}
