package bff

import (
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
