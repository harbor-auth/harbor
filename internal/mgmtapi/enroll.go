package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/signup"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// parseUUIDToBytes converts a UUID string to its 16-byte binary representation
// for use as a WebAuthn user handle.
func parseUUIDToBytes(s string) ([]byte, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return id[:], nil
}

// maxEnrollBody caps the enrollment request body. The body carries only a
// email, region or verification code, so a few KB is far beyond any legitimate request and stops a
// flooded /enroll from exhausting memory (docs/DESIGN.md §6.5).
const maxEnrollBody = 4 * 1024

// statusPending is the enrollment lifecycle status returned to the caller. It
// is distinct from the users.status DB column (which is "active" on insert):
// the account is not usable until passkey registration completes (§11.1), so
// the enrollment API reports "pending" until that second step lands.
const statusPending = "pending"

// checkPreSessionOrigin applies the Origin/Sec-Fetch-Site decision tree to
// POST /enroll, the first pre-session write in the public signup journey
// (docs/DESIGN.md §9). It duplicates internal/bff's checkDashboardCSRF /
// PreSessionCSRF logic rather than importing it: internal/bff already imports
// internal/mgmtapi (for the dashboard handler), so mgmtapi cannot import bff
// without a cycle — the same constraint that makes internal/webauthn
// duplicate enrollmentCookieName instead of importing mgmtapi. Keep this in
// sync with bff.checkDashboardCSRF if that check ever changes.
func checkPreSessionOrigin(r *http.Request) error {
	sfs := r.Header.Get("Sec-Fetch-Site")
	if sfs != "" {
		if sfs == "cross-site" {
			return errors.New("csrf: Sec-Fetch-Site: cross-site")
		}
		return nil
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	if origin == "null" {
		return errors.New("csrf: opaque origin")
	}

	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return errors.New("csrf: malformed Origin header")
	}

	requestHost := r.Host
	if requestHost == "" {
		requestHost = r.URL.Host
	}
	if parsed.Host != requestHost {
		return errors.New("csrf: Origin/Host mismatch")
	}
	return nil
}

// signupReturnToFromCookie reads the return_to value GET /signup already
// validated and stashed in SignupReturnToCookieName, so it can be folded into
// the new enrollment session as real server-side state (design.md Decision 5
// / REQ-004). An absent or empty cookie (POST /enroll called without ever
// visiting GET /signup) simply yields no return_to, matching today's
// behavior; the destination falls back to the fixed same-origin default at
// GET /signup/success.
func signupReturnToFromCookie(r *http.Request) string {
	c, err := r.Cookie(SignupReturnToCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// EmailSignup is the only public enrollment authority. Finish must consume a
// browser-bound verification code before atomically creating a new account.
type EmailSignup interface {
	Start(context.Context, string, string, string) (string, error)
	Finish(context.Context, string, string) (identity.EnrollResult, string, error)
}

const SignupVerificationCookieName = "harbor_signup_verification"

type enrollRequest struct {
	Region string `json:"region"`
	Email  string `json:"email"`
}
type enrollResponse struct {
	UserID string `json:"user_id"`
	Region string `json:"region"`
	Status string `json:"status"`
}

func (s *Server) WithEmailSignup(flow EmailSignup) *Server {
	s.emailSignup = flow
	return s
}

func (s *Server) signupAllowed(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if err := checkPreSessionOrigin(r); err != nil {
		s.writeError(w, http.StatusForbidden, "forbidden", "cross-site request rejected")
		return false
	}
	if s.abuseGate != nil && !s.abuseGate.Check(r.Context(), "enroll", abuseSource(r)) {
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return false
	}
	if s.emailSignup == nil {
		s.writeError(w, http.StatusServiceUnavailable, "unavailable", "email signup is not configured")
		return false
	}
	return true
}
func decodeSignup(w http.ResponseWriter, r *http.Request, into any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

// PostEnroll sends a code. It never creates a user or a WebAuthn enrollment session.
func (s *Server) PostEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.signupAllowed(w, r) {
		return
	}
	var req enrollRequest
	if err := decodeSignup(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "provide an email and region")
		return
	}
	reg, err := region.Parse(req.Region)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_region", "unknown or unsupported region")
		return
	}
	// A regional deployment must never accept PII into another region's store.
	if s.signupRegion != "" && string(reg) != s.signupRegion {
		s.writeError(w, http.StatusBadRequest, "invalid_region", "use this deployment's region")
		return
	}
	if _, err := signup.NormalizeEmail(req.Email); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_email", "enter a valid email address")
		return
	}
	key, err := s.emailSignup.Start(r.Context(), req.Email, string(reg), signupReturnToFromCookie(r))
	if err != nil {
		if errors.Is(err, signup.ErrRateLimited) {
			s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many verification requests")
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, "unavailable", "could not send verification email; try again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SignupVerificationCookieName, Value: key, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(signup.TTL.Seconds())})
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "verification_required"})
}

// PostEnrollVerify consumes the email code, creates the identified account,
// and only then issues the browser's first-passkey enrollment session.
func (s *Server) PostEnrollVerify(w http.ResponseWriter, r *http.Request) {
	if !s.signupAllowed(w, r) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeSignup(w, r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "provide the verification code")
		return
	}
	cookie, err := r.Cookie(SignupVerificationCookieName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_code", "verification expired; start signup again")
		return
	}
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointEnroll, outcome, start) }()
	res, returnTo, err := s.emailSignup.Finish(r.Context(), cookie.Value, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, signup.ErrInvalidCode):
			s.writeError(w, http.StatusBadRequest, "invalid_code", "code is incorrect or expired")
		case errors.Is(err, identity.ErrIdentifierExists):
			http.SetCookie(w, &http.Cookie{Name: SignupVerificationCookieName, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
			s.writeError(w, http.StatusConflict, "account_exists", "an account already uses this email; sign in with your passkey")
		default:
			s.writeError(w, http.StatusInternalServerError, "server_error", "could not complete signup; start again")
		}
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SignupVerificationCookieName, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})

	// When an enrollment session store is wired, save the new user's handle and
	// set an HttpOnly cookie so the passkey registration ceremony can bind to
	// this user WITHOUT a client-supplied user_id (docs/DESIGN.md §9, §11.1).
	if s.sessions != nil {
		key, err := NewEnrollmentSessionKey()
		if err != nil {
			s.logger.ErrorContext(r.Context(), "generate enrollment session key failed", "error", err)
			recordError(telemetry.EndpointEnroll, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
			return
		}
		// The user handle for WebAuthn is the raw UUID bytes. Parse the UUID string
		// returned by Enroll and use its byte representation.
		userHandle, err := parseUUIDToBytes(res.UserID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "parse user ID failed", "error", err)
			recordError(telemetry.EndpointEnroll, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
			return
		}
		if err := s.sessions.Save(r.Context(), key, userHandle, false, returnTo); err != nil {
			s.logger.ErrorContext(r.Context(), "save enrollment session failed", "error", err)
			recordError(telemetry.EndpointEnroll, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     EnrollmentSessionCookieName,
			Value:    key,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   600, // 10 min — matches the session store TTL.
		})
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusCreated, enrollResponse{
		UserID: res.UserID,
		Region: res.Region,
		Status: statusPending,
	})
}
