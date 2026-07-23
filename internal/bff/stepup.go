package bff

import (
	"context"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// DefaultStepUpTTL is how long a step-up (MFA) verification stays valid before
// the gate re-challenges the user. A short window keeps a stolen or long-lived
// browser session from silently reusing an old verification for a fresh
// sensitive action (docs/DESIGN.md §3.1, §7.3).
const DefaultStepUpTTL = 5 * time.Minute

// StepUpGate guards sensitive actions behind a recent MFA (step-up)
// verification. A request passes only when its BFF session carries an
// MFAVerifiedAt within the gate's TTL; otherwise the gate responds 403 with a
// step_up_required hint so the client can drive the user through an MFA
// challenge and retry.
//
// The gate is self-contained: it reads the __Host-harbor-bff cookie and looks
// the session up itself, so it does not depend on Middleware having run first
// or on any particular context injection ordering.
type StepUpGate struct {
	store BFFSessionStore
	ttl   time.Duration
	now   func() time.Time
}

// NewStepUpGate returns a StepUpGate backed by store. A non-positive ttl falls
// back to DefaultStepUpTTL.
func NewStepUpGate(store BFFSessionStore, ttl time.Duration) *StepUpGate {
	if ttl <= 0 {
		ttl = DefaultStepUpTTL
	}
	return &StepUpGate{store: store, ttl: ttl, now: time.Now}
}

// Require wraps next, allowing the request through only when the caller's BFF
// session has a fresh step-up verification. Every failure mode — no cookie,
// unknown/expired session, no authenticated user, or a stale/absent MFA
// verification — collapses to the SAME 403 step_up_required response so the gate
// never discloses which check failed (docs/DESIGN.md §6.5).
func (g *StepUpGate) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := ReadBFFCookie(r)
		if requestID == "" {
			g.deny(w)
			return
		}
		session, err := g.store.Get(r.Context(), requestID)
		if err != nil {
			g.deny(w)
			return
		}
		// A session with no authenticated user cannot have completed a step-up.
		if session.UserID == "" || !g.verified(session) {
			g.deny(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// verified reports whether session's most recent step-up verification is still
// within the TTL window. A zero MFAVerifiedAt (never verified) is never fresh.
func (g *StepUpGate) verified(session BFFSessionRecord) bool {
	if session.MFAVerifiedAt.IsZero() {
		return false
	}
	return g.now().Sub(session.MFAVerifiedAt) < g.ttl
}

// RecordTOTPStepUp records a successful TOTP step-up in the BFF session in two
// steps: SetMFAVerified (stamps the gate TTL window) then SetAuthMethod (upgrades
// the ACR/AMR to webauthn+totp). Both writes are required for the step-up to be
// reflected in the issued tokens; if SetAuthMethod fails the session retains the
// MFA stamp but reverts to WebAuthn-only ACR/AMR (fail-closed on claims).
//
// This is the intended call site for the deferred BFF TOTP step-up HTTP handler.
// Until that handler is wired, this helper documents the contract and provides a
// testable unit for the ACR/AMR integration tests.
func RecordTOTPStepUp(ctx context.Context, store BFFSessionStore, requestID string, verifiedAt time.Time) error {
	if err := store.SetMFAVerified(ctx, requestID, verifiedAt); err != nil {
		return err
	}
	return store.SetAuthMethod(ctx, requestID, oidc.AuthMethodTOTP)
}

// deny writes the uniform step-up-required response. The distinct error code
// tells the client to run an MFA challenge and retry, without revealing which
// precondition was missing.
func (g *StepUpGate) deny(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `MFA realm="harbor", error="step_up_required"`)
	http.Error(w, "step-up MFA verification required", http.StatusForbidden)
}
