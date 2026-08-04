package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// TestLoginHandler_FinishLogin_Discoverable_RecoveryRequiredStaysFenced proves
// the task 19 fix (FinishLoginWithParsedData now calls SetUserWithRecoveryStatus
// instead of SetUser, see login.go) does not overcorrect: a returning user who
// still has recovery_required=true (e.g. they registered a first passkey but
// never completed the mandatory recovery-setup step, then came back later and
// signed in directly via GET /signin instead of resuming that flow) must NOT
// be handed SessionScopeFull just because they hold a working passkey.
// FinishDiscoverableLogin's recoveryRequired return value must drive the
// session scope down to SessionScopeEnrollmentOnly, exactly like every other
// session-issuing path in this package (recoverySessionIssuer,
// bffSessionScopeRefresher).
func TestLoginHandler_FinishLogin_Discoverable_RecoveryRequiredStaysFenced(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "valid-session",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	nonceCookie := browserNonceCookieFor(&record)
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	webauthn := &mockWebAuthnService{
		finishDiscoverableFunc: func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, bool, error) {
			return "recovery-pending-user", true, nil
		},
	}
	handler := NewLoginHandler(store, webauthn, DiscoverableUserResolver{}, "http://localhost:8080/authorize/complete")

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "discoverable-session-key"})
	req.AddCookie(nonceCookie)
	rec := httptest.NewRecorder()

	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	updatedSession, err := store.Get(ctx, "valid-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if updatedSession.SessionScope != SessionScopeEnrollmentOnly {
		t.Errorf("session.SessionScope = %q, want %q", updatedSession.SessionScope, SessionScopeEnrollmentOnly)
	}
	if !updatedSession.RecoveryRequired {
		t.Error("session.RecoveryRequired = false, want true")
	}
}
