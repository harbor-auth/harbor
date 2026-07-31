package main

import "testing"

// TestParseEnforceAuth pins the fail-closed contract of the RELAY_ENFORCE_AUTH
// switch, which decides whether inbound mail failing SPF/DKIM/DMARC is rejected
// or merely logged.
//
// The regression this guards: the original code was
//
//	enforceAuth, _ := strconv.ParseBool(os.Getenv("RELAY_ENFORCE_AUTH"))
//
// which silently yields FALSE for any spelling strconv.ParseBool does not
// accept. An operator setting RELAY_ENFORCE_AUTH=yes would get authentication
// enforcement switched OFF while believing it was on — a fail-OPEN on a
// security control caused by a swallowed error. Unparseable input must now be a
// startup error, and the human spellings must mean what the operator intended.
func TestParseEnforceAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    bool
		wantErr bool
	}{
		// Unset is the documented default: evaluate SPF/DKIM/DMARC, log only.
		{name: "empty is off", raw: "", want: false},
		{name: "whitespace only is off", raw: "   ", want: false},

		// strconv.ParseBool spellings.
		{name: "true", raw: "true", want: true},
		{name: "t", raw: "t", want: true},
		{name: "1", raw: "1", want: true},
		{name: "false", raw: "false", want: false},
		{name: "f", raw: "f", want: false},
		{name: "0", raw: "0", want: false},

		// The spellings strconv.ParseBool rejects but operators actually write.
		// These are the exact inputs that used to silently disable enforcement.
		{name: "yes enables (was silently off)", raw: "yes", want: true},
		{name: "on enables (was silently off)", raw: "on", want: true},
		{name: "no disables", raw: "no", want: false},
		{name: "off disables", raw: "off", want: false},

		// Case and surrounding whitespace must not change the meaning.
		{name: "TRUE uppercase", raw: "TRUE", want: true},
		{name: "Yes mixed case", raw: "Yes", want: true},
		{name: "padded true", raw: "  true  ", want: true},

		// Anything we cannot interpret is fatal — never a silent false.
		{name: "typo is an error not a silent off", raw: "ture", wantErr: true},
		{name: "enabled is an error", raw: "enabled", wantErr: true},
		{name: "numeric 2 is an error", raw: "2", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseEnforceAuth(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseEnforceAuth(%q): want error, got nil (value %v) — "+
						"an uninterpretable value must fail startup, never default to "+
						"enforcement-off", tc.raw, got)
				}
				if got {
					t.Errorf("parseEnforceAuth(%q): on error the bool must be false, got true", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseEnforceAuth(%q): unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("parseEnforceAuth(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestParseEnforceAuthErrorNamesTheVariable checks that the startup error is
// actionable: it must name RELAY_ENFORCE_AUTH so an operator reading a crash
// log knows which setting to fix, and it must echo the offending value.
func TestParseEnforceAuthErrorNamesTheVariable(t *testing.T) {
	t.Parallel()

	_, err := parseEnforceAuth("ture")
	if err == nil {
		t.Fatal("want an error for an unparseable value")
	}
	msg := err.Error()
	for _, want := range []string{"RELAY_ENFORCE_AUTH", "ture"} {
		if !contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}()
}
