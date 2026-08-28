package bff

import (
	"net/url"
	"strings"
)

// defaultReturnTo is the fixed same-origin path ValidateReturnTo falls back to
// whenever raw is absent, malformed, or targets a host outside allowlist. It
// is deliberately a bare path (no host), so it is always same-origin by
// construction and needs no allowlist entry of its own.
const defaultReturnTo = "/"

// ValidateReturnTo validates a caller-supplied return_to value against a
// configured host allowlist (e.g. the Harbor Cloud marketing site and demo),
// returning the safe destination to use.
//
// Callers MUST validate raw exactly once — at the point it is first read from
// the client (a query parameter or form field) — and then carry the returned
// string as opaque server-side session state for the remainder of the flow
// (e.g. bound into the enrollment or BFF session record), rather than
// re-reading and re-validating a client-echoed value at each subsequent hop.
// A value round-tripped through the URL at every step reproduces the exact
// query-string trust problem already closed for request_id.
//
// raw is accepted unmodified only when it is either:
//   - a same-origin relative reference beginning with "/" (and not "//",
//     which browsers treat as protocol-relative to a foreign host); or
//   - an absolute "https://" (or scheme-less "//host/...") URL whose host
//     exactly matches an entry in allowlist.
//
// Anything else — an empty value, a malformed URL, an opaque scheme
// (javascript:, data:, mailto:, ...), an insecure scheme, a foreign host,
// embedded control characters, or a backslash-obfuscated host — falls back to
// defaultReturnTo. The second return value reports whether raw was accepted
// as given; it is false whenever the default was substituted.
func ValidateReturnTo(raw string, allowlist []string) (string, bool) {
	if raw == "" {
		return defaultReturnTo, false
	}
	// Reject embedded control characters up front: they have no legitimate use
	// in a redirect target and could otherwise smuggle a header/response split
	// into a caller that later writes this value into a Location header.
	if strings.ContainsAny(raw, "\r\n\x00") {
		return defaultReturnTo, false
	}
	// Backslashes are not URL delimiters per RFC 3986, but browsers and some
	// intermediaries normalize them to forward slashes — turning a path like
	// "/\evil.com" into the protocol-relative "//evil.com" by the time it is
	// actually navigated. Reject before any such normalization could apply.
	if strings.Contains(raw, "\\") {
		return defaultReturnTo, false
	}

	u, err := url.Parse(raw)
	if err != nil {
		return defaultReturnTo, false
	}

	if u.Host == "" {
		// No authority component: a same-origin relative reference. Require a
		// leading "/" so it resolves against our own root rather than the
		// current path, and reject scheme-only oddities like "javascript:...",
		// which url.Parse reports with an empty Host but a non-empty Opaque.
		//
		// The scheme and "//" path guards close a PARSER DIFFERENTIAL. Go's
		// net/url follows RFC 3986: it only treats "//" as introducing an
		// authority immediately after the scheme delimiter, so "///evil.com"
		// and "https:///evil.com" both parse with an EMPTY Host and land here
		// looking like innocent relative paths. Browsers use the WHATWG URL
		// parser, which collapses the leading slashes and reads the next token
		// as the HOST — so both navigate to https://evil.com/. Accepting them
		// here would hand an attacker an off-origin redirect out of the
		// post-login navigation, which is exactly what this function exists to
		// prevent. A genuine same-origin reference never carries a scheme and
		// never begins "//".
		if u.Scheme != "" || u.Opaque != "" ||
			!strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
			return defaultReturnTo, false
		}
		return raw, true
	}

	// Absolute (or protocol-relative "//host/...") reference: the host must be
	// on the allowlist, and the scheme (when present) must be https.
	if u.Scheme != "" && u.Scheme != "https" {
		return defaultReturnTo, false
	}
	for _, allowed := range allowlist {
		if strings.EqualFold(u.Host, allowed) {
			return raw, true
		}
	}
	return defaultReturnTo, false
}
