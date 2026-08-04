package bff

import (
	"errors"
	"net/http"
	"net/url"
)

// DashboardCSRF is an HTTP middleware that adds a second CSRF defence layer to
// mutating dashboard POST routes. The __Host-harbor-bff cookie carries
// SameSite=Strict as the primary layer; this middleware adds a Sec-Fetch-Site
// check (with Origin header as fallback for browsers that do not send Fetch
// Metadata) as a second independent layer, returning 403 Forbidden on
// cross-site requests.
//
// Only POST requests are checked — browsers may legitimately omit Origin on
// same-origin GETs, and all state-changing dashboard operations are POST-only.
//
// Decision tree for POST requests:
//  1. Sec-Fetch-Site present → allow same-origin / same-site / none; deny cross-site.
//  2. Sec-Fetch-Site absent, Origin present → compare origin host to request host;
//     deny on mismatch or opaque ("null") origin.
//  3. Both absent → pass through; SameSite=Strict remains the active guard.
func DashboardCSRF(next http.Handler) http.Handler {
	return requireSameOriginPOST(next)
}

// PreSessionCSRF applies the identical Origin/Sec-Fetch-Site decision tree as
// DashboardCSRF (see checkDashboardCSRF) to POST routes that run before any
// session cookie exists — enrollment, signup, and WebAuthn ceremony
// begin/finish endpoints. Unlike DashboardCSRF, this is not a *second* defence
// layer: these routes have no SameSite=Strict cookie yet, so this check is
// their only CSRF defence.
func PreSessionCSRF(next http.Handler) http.Handler {
	return requireSameOriginPOST(next)
}

// requireSameOriginPOST is the shared middleware wrapper behind both
// DashboardCSRF and PreSessionCSRF; only the doc comment (and therefore the
// caller's intent) differs between the two.
func requireSameOriginPOST(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := checkDashboardCSRF(r); err != nil {
				http.Error(w, "forbidden: cross-site request rejected", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// checkDashboardCSRF returns a non-nil error when the request should be
// rejected as a cross-site POST. It is extracted so it can be unit-tested
// independently of the middleware wrapper.
func checkDashboardCSRF(r *http.Request) error {
	// --- Primary: Sec-Fetch-Site (Fetch Metadata, RFC 8942) ---
	// Sent by all modern browsers (Chrome 76+, Firefox 90+, Safari 16.4+).
	// Possible values: "same-origin", "same-site", "cross-site", "none".
	// "none" is used for navigations with no referrer (bookmarks, address bar);
	// it cannot originate from a cross-site attacker-controlled page.
	sfs := r.Header.Get("Sec-Fetch-Site")
	if sfs != "" {
		if sfs == "cross-site" {
			return errors.New("csrf: Sec-Fetch-Site: cross-site")
		}
		// same-origin, same-site, or none — permit.
		return nil
	}

	// --- Fallback: Origin header (RFC 6454) ---
	// Sent by browsers on cross-origin fetches and by most browsers on
	// same-origin form submissions. Not universally sent, so absence alone
	// is not a rejection signal — SameSite=Strict is still active.
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Neither header present; pass through.
		return nil
	}
	if origin == "null" {
		// Opaque origin: sandboxed <iframe>, data: URI, etc. Deny conservatively.
		return errors.New("csrf: opaque origin")
	}

	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return errors.New("csrf: malformed Origin header")
	}

	// Determine the expected host from the incoming request.
	requestHost := r.Host
	if requestHost == "" {
		requestHost = r.URL.Host
	}

	if parsed.Host != requestHost {
		return errors.New("csrf: Origin/Host mismatch")
	}
	return nil
}
