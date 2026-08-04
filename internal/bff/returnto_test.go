package bff

import "testing"

func TestValidateReturnTo(t *testing.T) {
	allowlist := []string{"harborcloud.example.com", "demo.harborcloud.example.com"}

	cases := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{"empty falls back to default", "", defaultReturnTo, false},
		{"same-origin relative path accepted", "/dashboard", "/dashboard", true},
		{"same-origin path with query accepted", "/dashboard?tab=apps", "/dashboard?tab=apps", true},
		{"relative path without leading slash rejected", "dashboard", defaultReturnTo, false},
		{"allowlisted absolute https accepted", "https://harborcloud.example.com/welcome", "https://harborcloud.example.com/welcome", true},
		{"allowlisted absolute https, case-insensitive host", "https://HarborCloud.Example.com/welcome", "https://HarborCloud.Example.com/welcome", true},
		{"second allowlisted host accepted", "https://demo.harborcloud.example.com/", "https://demo.harborcloud.example.com/", true},
		{"protocol-relative allowlisted host accepted", "//harborcloud.example.com/welcome", "//harborcloud.example.com/welcome", true},
		{"non-allowlisted absolute https rejected", "https://evil.example.com/phish", defaultReturnTo, false},
		{"protocol-relative non-allowlisted host rejected", "//evil.example.com/phish", defaultReturnTo, false},
		{"insecure http scheme to allowlisted host rejected", "http://harborcloud.example.com/", defaultReturnTo, false},
		{"javascript scheme rejected", "javascript:alert(1)", defaultReturnTo, false},
		{"data scheme rejected", "data:text/html,<script>alert(1)</script>", defaultReturnTo, false},
		{"opaque null-ish origin rejected", "mailto:foo@example.com", defaultReturnTo, false},
		{"userinfo host-confusion rejected", "https://harborcloud.example.com@evil.example.com/", defaultReturnTo, false},
		{"backslash-obfuscated host rejected", "/\\evil.example.com", defaultReturnTo, false},
		{"double-backslash host rejected", "\\\\evil.example.com", defaultReturnTo, false},
		{"embedded CRLF rejected", "/x\r\nSet-Cookie: evil=1", defaultReturnTo, false},
		{"embedded NUL rejected", "/x\x00evil", defaultReturnTo, false},
		{"query-only value rejected", "?next=evil", defaultReturnTo, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ValidateReturnTo(tc.raw, allowlist)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("ValidateReturnTo(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestValidateReturnTo_EmptyAllowlistStillAllowsSameOrigin verifies a relative
// path is validated independently of the allowlist — it never needs an entry
// of its own since it can only resolve against our own origin.
func TestValidateReturnTo_EmptyAllowlistStillAllowsSameOrigin(t *testing.T) {
	got, ok := ValidateReturnTo("/signup/success", nil)
	if got != "/signup/success" || !ok {
		t.Errorf("ValidateReturnTo(relative, nil allowlist) = (%q, %v), want (%q, true)", got, ok, "/signup/success")
	}
}

// TestValidateReturnTo_UnrecognizedNeverEchoed is a focused regression test for
// the "an unrecognized return_to value never appears in a Location header"
// requirement: whatever a caller does with ValidateReturnTo's first return
// value (e.g. writing it into a redirect), the rejected raw value must never
// be the thing returned.
func TestValidateReturnTo_UnrecognizedNeverEchoed(t *testing.T) {
	malicious := []string{
		"https://evil.example.com/phish",
		"//evil.example.com/phish",
		"javascript:alert(document.cookie)",
		"/\\evil.example.com",
	}
	allowlist := []string{"harborcloud.example.com"}
	for _, raw := range malicious {
		got, ok := ValidateReturnTo(raw, allowlist)
		if ok {
			t.Errorf("ValidateReturnTo(%q) unexpectedly accepted", raw)
		}
		if got == raw {
			t.Errorf("ValidateReturnTo(%q) echoed the unrecognized value verbatim", raw)
		}
	}
}
