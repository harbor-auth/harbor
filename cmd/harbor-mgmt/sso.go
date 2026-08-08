// This file wires GET /login/sso — the public consumer end of the
// corporate-SSO handoff whose minting side is internal/cloudapi's POST
// /admin/v1/user-sessions. It redeems a one-time login code for a real BFF
// session, deliberately WITHOUT a browser nonce: see wireSSOLoginRoute's doc
// comment for why that omission is the security property, not a bug.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// defaultSSODashboardPath is SSO_DASHBOARD_PATH's default — the fixed,
// same-origin redirect target GET /login/sso lands a caller on after a
// successful redemption. Never a caller-supplied return_to: the whole point
// of a fixed target is that this route has no open-redirect surface.
const defaultSSODashboardPath = "/dashboard"

// maxSSOLoginCodeLength bounds the `code` query parameter. A minted code is
// 256 bits of base64url (43 chars); this is a generous ceiling, not a tight
// fit, so a malformed/oversized value is rejected fast without ever reaching
// the login-code store.
const maxSSOLoginCodeLength = 512

// validateSSODashboardPath validates SSO_DASHBOARD_PATH at boot: it must be
// an absolute path only — no scheme, no host, no "//" (which some HTTP
// clients interpret as a protocol-relative, i.e. cross-origin, redirect
// target). Fail-fast so a misconfigured deployment never ships an
// open-redirect instead of a fixed target.
func validateSSODashboardPath(raw string) (string, error) {
	if raw == "" {
		return defaultSSODashboardPath, nil
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("SSO_DASHBOARD_PATH must be an absolute same-origin path (e.g. \"/dashboard\"), not a full URL")
	}
	return raw, nil
}

// ssoAuditRecorder is the narrow RecordAsync surface wireSSOLoginRoute needs.
// Satisfied directly by *identity.AuditRecorder (main.go's auditRecorder).
type ssoAuditRecorder interface {
	RecordAsync(ctx context.Context, userID string, et identity.EventType, clientID *string, detail any)
}

// ssoActiveUserChecker re-checks a resolved user's status immediately before
// redemption, independent of whatever ResolveOrCreateFederatedUser saw at
// mint time (which may have been minutes earlier, per loginCodeTTL) —
// closing the (small, but real) window where a user is erased between mint
// and redemption.
type ssoActiveUserChecker interface {
	UserActive(ctx context.Context, userID string) (bool, error)
}

// dbActiveUserChecker implements ssoActiveUserChecker directly over
// *db.Queries — the same production querier cmd/harbor-mgmt already
// constructs in main.go.
type dbActiveUserChecker struct {
	q *db.Queries
}

func (c dbActiveUserChecker) UserActive(ctx context.Context, userID string) (bool, error) {
	var id pgtype.UUID
	if err := id.Scan(userID); err != nil {
		return false, err
	}
	u, err := c.q.GetUser(ctx, id)
	if err != nil {
		return false, err
	}
	return u.Status == "active", nil
}

// ssoLoginSessionTTL bounds both the BFF cookie's Max-Age and (implicitly,
// via the shared bffStore's own configured TTL) the minted session record —
// matching bff.DefaultCookieMaxAge, the same value BeginLogin's own
// SetBFFCookie call uses for a passkey-completed session.
const ssoLoginSessionTTL = bff.DefaultCookieMaxAge

// wireSSOLoginRoute builds the GET /login/sso?code= handler: it redeems a
// one-time login code (minted by POST /admin/v1/user-sessions) into a real,
// full-scope BFF session.
//
// Security property (the reason this design is safe): the minted session's
// BrowserNonceHash is left nil. internal/oidcapi.GetAuthorizeComplete and
// bff.LoginHandler.BeginLogin/FinishLoginWithParsedData all refuse
// len(session.BrowserNonceHash) == 0 — that gate exists specifically so an
// out-of-band session (one this browser never proved ownership of via the
// nonce cookie minted at /authorize or /signin) can never complete an OIDC
// authorization. A nonce-less session CAN drive the dashboard
// (bff.Middleware never checks the nonce) but CANNOT mint an RP-facing
// authorization code. So even a fully compromised harbor-cloud — one that
// could mint arbitrary login codes for arbitrary users — can land a browser
// on the Harbor dashboard, but cannot forge an OIDC login to any relying
// party. This is deliberate, not an oversight: do not "fix" it by minting a
// nonce here.
func wireSSOLoginRoute(
	codes cloudapi.LoginCodeStore,
	bffSessions bff.BFFSessionStore,
	users ssoActiveUserChecker,
	audit ssoAuditRecorder,
	limiter clients.RateLimiter,
	dashboardPath string,
	logger *slog.Logger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set on EVERY response from this handler, success or failure, and
		// before any other work: no-store keeps the one-time code out of any
		// cache; no-referrer stops it leaking to whatever the browser
		// navigates to next via the Referer header.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")

		code := r.URL.Query().Get("code")
		if code == "" || len(code) > maxSSOLoginCodeLength {
			writeSSOLoginError(w)
			return
		}

		allowed, retryAfter, err := limiter.Allow(r.Context(), clients.RateLimitKey("sso_login", ssoSourceKey(r)))
		if err != nil || !allowed {
			// Fail closed: a rate-limiter backend error is treated exactly
			// like an over-limit request, never an implicit pass (mirrors
			// cmd/harbor-mgmt/cloudapi.go's cloudRateLimited).
			if retryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
			}
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		claim, err := codes.Consume(r.Context(), code)
		if err != nil {
			// Never distinguish expired / unknown / already-consumed — all
			// three collapse to ErrLoginCodeNotFound at the store layer
			// (logincode.go), and this handler preserves that by using the
			// SAME generic error page for every failure from here on.
			writeSSOLoginError(w)
			return
		}

		active, err := users.UserActive(r.Context(), claim.UserID)
		if err != nil || !active {
			if err != nil {
				logger.ErrorContext(r.Context(), "sso login: re-check user active failed", "error", err)
			}
			writeSSOLoginError(w)
			return
		}

		requestID, err := bff.NewRequestID()
		if err != nil {
			logger.ErrorContext(r.Context(), "sso login: generate request id failed", "error", err)
			writeSSOLoginError(w)
			return
		}

		record := bff.BFFSessionRecord{
			RequestID: requestID,
			UserID:    claim.UserID,
			// Full scope, never enrollment-only: an SSO user has no passkey
			// enrollment ceremony to complete (identity.EnrollFederated sets
			// RecoveryRequired=false at user-creation time already).
			SessionScope:     bff.SessionScopeFull,
			RecoveryRequired: false,
			AuthMethod:       oidc.AuthMethodFederated,
			// Deliberately nil — see wireSSOLoginRoute's doc comment above.
			BrowserNonceHash: nil,
			ExpiresAt:        time.Now().Add(ssoLoginSessionTTL),
		}
		if err := bffSessions.Create(r.Context(), record); err != nil {
			logger.ErrorContext(r.Context(), "sso login: create bff session failed", "error", err)
			writeSSOLoginError(w)
			return
		}

		// M1: SetSSOBFFCookie (SameSite=Lax), not SetBFFCookie (Strict) — the
		// browser reaches this handler via a cross-site redirect chain (the
		// SAML bridge), and the 303 below to dashboardPath is itself part of
		// that chain, so a Strict cookie set here would very likely never
		// reach the dashboard request. See SetSSOBFFCookie's doc comment for
		// the full RFC 6265bis §5.2 reasoning.
		bff.SetSSOBFFCookie(w, requestID, ssoLoginSessionTTL)
		// Deliberately no enrollment cookie (mgmtapi.EnrollmentSessionCookieName /
		// RecoveryScopedSessionCookieName): this is not an enrollment
		// session and must not unlock the WebAuthn ceremony endpoints.

		audit.RecordAsync(r.Context(), claim.UserID, identity.EventAuthLogin, nil, map[string]string{
			"method":       "federated",
			"namespace_id": claim.NamespaceID,
		})

		http.Redirect(w, r, dashboardPath, http.StatusSeeOther)
	}
}

// ssoSourceKey derives a rate-limit key from the caller's IP without storing
// the IP itself (mirrors cmd/harbor-mgmt/main.go's remoteAddrKey).
func ssoSourceKey(r *http.Request) string {
	return remoteAddrKey(r)
}

// writeSSOLoginError renders a generic, PII-free error page. It carries NO
// Location header (never a redirect on failure) and never distinguishes
// WHY redemption failed — expired, unknown, already-consumed, or the user
// having gone inactive all look identical to the caller.
func writeSSOLoginError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("<!doctype html><html><head><title>Sign-in error</title></head>" +
		"<body><h1>Sign-in error</h1>" +
		"<p>This sign-in link is invalid or has expired. Please try signing in again.</p></body></html>"))
}
