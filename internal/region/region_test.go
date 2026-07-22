package region

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    Region
		wantErr bool
	}{
		{"eu exact", "EU", EU, false},
		{"us exact", "US", US, false},
		{"apac exact", "APAC", APAC, false},
		{"lowercase", "eu", EU, false},
		{"mixed case", "ApAc", APAC, false},
		{"whitespace padded", "  us  ", US, false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"unknown", "MARS", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.raw)
			if tc.wantErr {
				if !errors.Is(err, ErrUnknownRegion) {
					t.Fatalf("Parse(%q) error = %v, want ErrUnknownRegion", tc.raw, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
