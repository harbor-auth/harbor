package region

import (
	"errors"
	"testing"
)

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
