package bff

import (
	"context"
	"errors"
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
		if g == nil || g.store == nil {
			if g == nil {
				w.Header().Set("WWW-Authenticate", `MFA realm="harbor", error="step_up_required"`)
				http.Error(w, "step-up MFA verification required", http.StatusForbidden)
				return
			}
			g.deny(w)
			return
		}
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
	age := g.now().Sub(session.MFAVerifiedAt)
	return age >= 0 && age < g.ttl
}

type atomicTOTPStepUpStore interface {
	RecordTOTPStepUp(ctx context.Context, requestID, userID string, verifiedAt time.Time) error
}

// ErrStepUpNotPermittedForSession is returned by RecordTOTPStepUp when the
// session presenting a TOTP/recovery code is one this browser never proved
// ownership of via the /authorize nonce cookie (M3). Today that is exactly
// the corporate-SSO handoff's federated session (cmd/harbor-mgmt/sso.go's
// wireSSOLoginRoute, deliberately minted with AuthMethod=federated and a nil
// BrowserNonceHash). Without this check, a federated session could
// self-enroll a TOTP factor, verify it, and have THIS function stamp
// MFAVerifiedAt — after which StepUpGate.Require (which only checks
// UserID+MFAVerifiedAt, not how the session was authenticated) would pass it
// straight through to /compliance/export, /compliance/erase, /audit-events,
// /consent-grants, and /relay-addresses. That every one of those routes
// currently also happens to be un-routed to harbor-mgmt at the ingress is an
// accident of deploy/helm/templates/ingress.yaml's path list, not an
// application-level guarantee — this is the actual boundary.
var ErrStepUpNotPermittedForSession = errors.New("bff: this session is not permitted to record a step-up verification")

// SessionEligibleForMFAStepUp reports whether session is one RecordTOTPStepUp
// is willing to record a step-up verification for (M3). Exported so
// cmd/harbor-mgmt can apply the SAME predicate earlier, at MFA enrollment
// time (internal/mgmtapi.MFAEnrollmentGuard) — a defense-in-depth check, not
// a substitute for RecordTOTPStepUp's own (load-bearing) enforcement below.
//
// Both conditions are checked independently (not just AuthMethod) because
// BrowserNonceHash — the property every other nonce gate in this package
// (login.go) actually keys off — is the more fundamental one; AuthMethod is
// the more legible one to read in an audit log or test failure. NOTE: this
// also excludes the lost-device account-recovery track (its BFF session is
// promoted to full scope in place via SetUserWithRecoveryStatus without ever
// acquiring a browser nonce — see cmd/harbor-mgmt/caller.go's
// recoverySessionIssuer) — a deliberate, accepted trade-off: that session is
// short-lived, and a fresh, ordinary sign-in restores step-up eligibility
// immediately.
func SessionEligibleForMFAStepUp(session BFFSessionRecord) bool {
	return session.AuthMethod != oidc.AuthMethodFederated && len(session.BrowserNonceHash) != 0
}

// RecordTOTPStepUp records a successful TOTP step-up as one ownership-checked
// store mutation. Stores without this atomic capability fail closed.
func RecordTOTPStepUp(ctx context.Context, store BFFSessionStore, requestID string, verifiedAt time.Time) error {
	session, err := store.Get(ctx, requestID)
	if err != nil || session.UserID == "" {
		if err != nil {
			return err
		}
		return ErrBFFSessionNotFound
	}
	// M3: refuse to manufacture a step-up verification for a session this
	// browser never proved ownership of via the /authorize nonce cookie.
	if !SessionEligibleForMFAStepUp(session) {
		return ErrStepUpNotPermittedForSession
	}
	atomicStore, ok := store.(atomicTOTPStepUpStore)
	if !ok {
		return errors.New("bff: session store does not support atomic step-up")
	}
	if err := atomicStore.RecordTOTPStepUp(ctx, requestID, session.UserID, verifiedAt); err != nil {
		return err
	}
	return nil
}

// deny writes the uniform step-up-required response. The distinct error code
// tells the client to run an MFA challenge and retry, without revealing which
// precondition was missing.
func (g *StepUpGate) deny(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `MFA realm="harbor", error="step_up_required"`)
	http.Error(w, "step-up MFA verification required", http.StatusForbidden)
}
