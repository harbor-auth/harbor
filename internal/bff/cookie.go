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
