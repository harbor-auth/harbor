package region

import (
	"errors"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		want    Region
		wantErr bool
	}{
		{"eu bare host", "eu.harbor.id", EU, false},
		{"us bare host", "us.harbor.id", US, false},
		{"apac bare host", "apac.harbor.id", APAC, false},
		{"eu issuer url", "https://eu.harbor.id", EU, false},
		{"eu issuer url trailing slash", "https://eu.harbor.id/", EU, false},
		{"eu issuer url with path", "https://eu.harbor.id/token", EU, false},
		{"us host with port", "us.harbor.id:443", US, false},
		{"eu issuer url with port", "https://eu.harbor.id:8443/token", EU, false},
		{"mixed case host", "EU.Harbor.ID", EU, false},
		{"whitespace padded", "  us.harbor.id  ", US, false},
		{"unknown host", "unknown.example", "", true},
		{"unknown issuer url", "https://unknown.example", "", true},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.host)
			if tc.wantErr {
				if !errors.Is(err, ErrUnknownHost) {
					t.Fatalf("Resolve(%q) error = %v, want ErrUnknownHost", tc.host, err)
				}
				if got != "" {
					t.Fatalf("Resolve(%q) returned region %q on error; must not default", tc.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", tc.host, err)
			}
			if got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

// TestResolveNeverDefaults asserts the resolver is total: an unrecognised host
// is rejected, never mapped to a fallback region (OpenSpec REQ-001).
func TestResolveNeverDefaults(t *testing.T) {
	for _, host := range []string{"", "example.com", "harbor.id", "eu.evil.example"} {
		if got, err := Resolve(host); err == nil {
			t.Fatalf("Resolve(%q) = %q, nil; want ErrUnknownHost (must not default)", host, got)
		}
	}
}

func TestValidateHostMap(t *testing.T) {
	cases := []struct {
		name    string
		in      map[string]Region
		wantErr bool
	}{
		{
			name: "valid",
			in:   map[string]Region{"eu.harbor.id": EU, "us.harbor.id": US},
		},
		{
			name:    "empty",
			in:      map[string]Region{},
			wantErr: true,
		},
		{
			name:    "nil",
			in:      nil,
			wantErr: true,
		},
		{
			name:    "unknown region value",
			in:      map[string]Region{"eu.harbor.id": Region("MARS")},
			wantErr: true,
		},
		{
			name:    "empty host key",
			in:      map[string]Region{"   ": EU},
			wantErr: true,
		},
		{
			name:    "ambiguous after normalisation",
			in:      map[string]Region{"eu.harbor.id": EU, "EU.harbor.id:443": US},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHostMap(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidHostMap) {
					t.Fatalf("ValidateHostMap(%v) error = %v, want ErrInvalidHostMap", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateHostMap(%v) unexpected error: %v", tc.in, err)
			}
		})
	}
}

// TestDefaultHostMapValid guards the package's own authoritative map so a bad
// edit is caught by tests as well as by the init-time boot check.
func TestDefaultHostMapValid(t *testing.T) {
	if err := ValidateHostMap(hostMap); err != nil {
		t.Fatalf("default hostMap invalid: %v", err)
	}
}
