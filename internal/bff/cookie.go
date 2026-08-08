package bff

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"
)

// CookieName is the name of the BFF session cookie. The __Host- prefix enforces
// Secure, Path=/, and no Domain attribute (hardened against subdomain attacks).
const CookieName = "__Host-harbor-bff"

// DefaultCookieMaxAge is the default max-age for BFF session cookies (5 min).
// This matches the BFF session TTL in the store.
const DefaultCookieMaxAge = 5 * time.Minute

// SetBFFCookie writes the BFF session cookie to the response. The cookie carries
// the opaque request_id for CSRF binding between the browser and the BFF session.
//
// Security properties (docs/plans/bff-session-middleware.md):
//   - __Host- prefix: forces Secure, Path=/, no Domain
//   - HttpOnly: not accessible to JavaScript
//   - SameSite=Strict: CSRF protection
//   - Short TTL (5 min): limits exposure if stolen
func SetBFFCookie(w http.ResponseWriter, requestID string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    requestID,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// SetSSOBFFCookie writes the BFF session cookie with SameSite=Lax instead of
// SetBFFCookie's Strict, for the corporate-SSO landing route ONLY
// (cmd/harbor-mgmt/sso.go's GET /login/sso).
//
// Why (M1): the browser reaches /login/sso via a cross-site redirect chain
// (Harbor Cloud's SAML bridge -> ... -> here). RFC 6265bis §5.2 computes a
// request's "site for cookies" over the WHOLE redirect chain, not just the
// immediately preceding hop — one cross-site hop ANYWHERE in that chain
// nulls it for every subsequent hop, including same-origin ones. The 303
// this handler issues to SSO_DASHBOARD_PATH is one of those subsequent hops,
// so a SameSite=Strict cookie set here would very likely be withheld on
// that follow-up request: the user lands on the dashboard unauthenticated,
// and only a manual reload (a fresh top-level navigation, genuinely
// same-site this time) recovers the session.
//
// SameSite=Lax is the standard remedy: it IS sent on top-level GET
// navigations regardless of the referring site — exactly this handoff's
// shape — while still refusing the cookie on cross-site POSTs, XHR, and
// subresource requests, which is Lax's actual CSRF protection and the
// reason it's an acceptable relaxation here. The alternative (a same-site
// self-submitting interstitial page) would also work but is more moving
// parts for the same outcome; prefer this smaller change.
//
// Every other BFF cookie write (SetBFFCookie: passkey/WebAuthn login and
// enrollment) MUST stay SameSite=Strict — those flows are same-site,
// top-level navigations start to finish (no cross-site hop ever precedes
// them), so Strict costs nothing there and is the tighter default. Do not
// widen SetBFFCookie itself to Lax; if a future flow needs this same
// treatment, add another SSO-shaped call site here instead.
func SetSSOBFFCookie(w http.ResponseWriter, requestID string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    requestID,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ReadBFFCookie extracts the request_id from the BFF session cookie. Returns an
// empty string if the cookie is absent or invalid.
func ReadBFFCookie(r *http.Request) string {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ClearBFFCookie deletes the BFF session cookie by setting MaxAge=-1. This is
// called after the auth code is issued (one-time use) so replay is impossible.
func ClearBFFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// NonceCookieName is the name of the browser nonce cookie. It carries the raw
// 32-byte CSPRNG nonce (base64url-encoded) that binds a BFF session to the
// specific browser that initiated the flow, preventing session fixation attacks.
// The __Host- prefix enforces Secure, Path=/, and no Domain attribute.
const NonceCookieName = "__Host-harbor-bff-nonce"

// NewBrowserNonce generates a 32-byte cryptographically random nonce. The raw
// nonce is placed in the browser cookie; its SHA-256 hash is stored server-side
// (BFFSessionRecord.BrowserNonceHash) so a store compromise does not yield live
// cookies (docs/plans/fix-bff-session-binding.md).
func NewBrowserNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// HashNonce returns the SHA-256 digest of nonce. Store the output, not the
// raw nonce, so that a session-store breach cannot be replayed as a live cookie.
func HashNonce(nonce []byte) []byte {
	h := sha256.Sum256(nonce)
	return h[:]
}

// SetBFFNonceCookie writes the browser nonce cookie to the response. The nonce
// is base64url-encoded for safe cookie transport. This must be called at
// /authorize before redirecting to the login page so the binding is established
// before any user-visible URL is delivered (fix-bff-session-binding.md step 1).
func SetBFFNonceCookie(w http.ResponseWriter, nonce []byte, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     NonceCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(nonce),
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ReadBFFNonceCookie extracts and base64url-decodes the browser nonce from the
// request. Returns an error if the cookie is absent, malformed, or cannot be
// decoded — callers must treat any error as a hard refusal (no fallback).
func ReadBFFNonceCookie(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(NonceCookieName)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(cookie.Value)
}

// ClearBFFNonceCookie deletes the browser nonce cookie by setting MaxAge=-1.
// Call this alongside ClearBFFCookie when the session is consumed or aborted.
func ClearBFFNonceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     NonceCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// NonceMatches returns true iff HashNonce(nonce) equals storedHash using a
// constant-time comparison to prevent timing side-channels. Both the hash step
// and the compare step run in constant time relative to the input length.
// Returns false if either argument is nil or if the lengths differ.
func NonceMatches(nonce []byte, storedHash []byte) bool {
	if len(nonce) == 0 || len(storedHash) == 0 {
		return false
	}
	computed := HashNonce(nonce)
	return subtle.ConstantTimeCompare(computed, storedHash) == 1
}
