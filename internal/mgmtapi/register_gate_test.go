package mgmtapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	// gateTestToken is the operator-configured initial access token used by the
	// gate tests.
	gateTestToken = "super-secret-initial-access-token"
	// gateTestBody is a minimal valid registration request body.
	gateTestBody = `{"redirect_uris":["https://rp.example.com/cb"]}`
)

// newGatedRegServer returns a registration server gated behind token.
func newGatedRegServer(store ClientRegistrationStore, token string) *Server {
	return New(nil, nil).
		WithClientRegistration(store, testRegBaseURL).
		WithInitialAccessToken(token)
}

// doRegisterWithAuth POSTs body to /register with the given Authorization
// header (omitted when authHeader is empty).
func doRegisterWithAuth(t *testing.T, s *Server, body, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	s.PostRegister(rec, req)
	return rec
}

func TestPostRegisterGateDisabledAllowsAnonymous(t *testing.T) {
	// No initial access token configured: registration is open, so a request
	// with no Authorization header still succeeds.
	fake := &fakeClientReg{}
	s := newGatedRegServer(fake, "") // empty token → gate disabled

	rec := doRegisterWithAuth(t, s, gateTestBody, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Error("expected Create to be called when the gate is disabled")
	}
}

func TestPostRegisterGateValidToken(t *testing.T) {
	fake := &fakeClientReg{}
	s := newGatedRegServer(fake, gateTestToken)

	rec := doRegisterWithAuth(t, s, gateTestBody, "Bearer "+gateTestToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Error("expected Create to be called with a valid initial access token")
	}
}

func TestPostRegisterGateCaseInsensitiveScheme(t *testing.T) {
	// RFC 7235 §2.1: the auth scheme is case-insensitive.
	fake := &fakeClientReg{}
	s := newGatedRegServer(fake, gateTestToken)

	rec := doRegisterWithAuth(t, s, gateTestBody, "bearer "+gateTestToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPostRegisterGateMissingToken(t *testing.T) {
	fake := &fakeClientReg{}
	s := newGatedRegServer(fake, gateTestToken)

	rec := doRegisterWithAuth(t, s, gateTestBody, "") // no Authorization header
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if fake.called {
		t.Error("Create must NOT be called when the initial access token is missing")
	}
	if er := decodeRegisterError(t, rec); er.Error != "invalid_token" {
		t.Errorf("error = %q, want %q", er.Error, "invalid_token")
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want it to contain %q", got, "Bearer")
	}
}

func TestPostRegisterGateWrongToken(t *testing.T) {
	fake := &fakeClientReg{}
	s := newGatedRegServer(fake, gateTestToken)

	rec := doRegisterWithAuth(t, s, gateTestBody, "Bearer not-the-right-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if fake.called {
		t.Error("Create must NOT be called when the initial access token is wrong")
	}
	if er := decodeRegisterError(t, rec); er.Error != "invalid_token" {
		t.Errorf("error = %q, want %q", er.Error, "invalid_token")
	}
}

func TestPostRegisterGateMalformedAuthHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "not bearer scheme", header: "Basic " + gateTestToken},
		{name: "bearer with empty token", header: "Bearer "},
		{name: "raw token no scheme", header: gateTestToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeClientReg{}
			s := newGatedRegServer(fake, gateTestToken)

			rec := doRegisterWithAuth(t, s, gateTestBody, tt.header)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
			}
			if fake.called {
				t.Error("Create must NOT be called for a malformed Authorization header")
			}
		})
	}
}

func TestPostRegisterGateRejectsBeforeBodyParse(t *testing.T) {
	// A malformed body with a missing token must still fail with 401 (the gate
	// runs before body parsing), and nothing is persisted.
	fake := &fakeClientReg{}
	s := newGatedRegServer(fake, gateTestToken)

	rec := doRegisterWithAuth(t, s, `{not json`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if fake.called {
		t.Error("Create must NOT be called when the gate rejects the request")
	}
}
