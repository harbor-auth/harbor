package crypto

import (
	"errors"
	"os"
	"testing"
)

func TestParseKMSKeyMap(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "single region",
			input: "us-east-1=arn:aws:kms:us-east-1:123456789012:key/abc123",
			want: map[string]string{
				"us-east-1": "arn:aws:kms:us-east-1:123456789012:key/abc123",
			},
		},
		{
			name:  "multiple regions",
			input: "us-east-1=arn:aws:kms:us-east-1:123:key/a,eu-west-1=arn:aws:kms:eu-west-1:123:key/b",
			want: map[string]string{
				"us-east-1": "arn:aws:kms:us-east-1:123:key/a",
				"eu-west-1": "arn:aws:kms:eu-west-1:123:key/b",
			},
		},
		{
			name:  "with whitespace",
			input: " us-east-1 = arn:aws:kms:us-east-1:123:key/a , eu-west-1 = arn:aws:kms:eu-west-1:123:key/b ",
			want: map[string]string{
				"us-east-1": "arn:aws:kms:us-east-1:123:key/a",
				"eu-west-1": "arn:aws:kms:eu-west-1:123:key/b",
			},
		},
		{
			name:  "key alias",
			input: "us-east-1=alias/my-key",
			want: map[string]string{
				"us-east-1": "alias/my-key",
			},
		},
		{
			name:    "empty value",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing equals",
			input:   "us-east-1",
			wantErr: true,
		},
		{
			name:    "empty region",
			input:   "=arn:aws:kms:us-east-1:123:key/a",
			wantErr: true,
		},
		{
			name:    "empty key",
			input:   "us-east-1=",
			wantErr: true,
		},
		{
			name:    "duplicate region",
			input:   "us-east-1=key1,us-east-1=key2",
			wantErr: true,
		},
		{
			name:  "trailing comma",
			input: "us-east-1=key1,",
			want: map[string]string{
				"us-east-1": "key1",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKMSKeyMap(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got.KeyMap) != len(tc.want) {
				t.Errorf("KeyMap length = %d, want %d", len(got.KeyMap), len(tc.want))
			}
			for k, v := range tc.want {
				if got.KeyMap[k] != v {
					t.Errorf("KeyMap[%q] = %q, want %q", k, got.KeyMap[k], v)
				}
			}
		})
	}
}

func TestEnvKEKResolver(t *testing.T) {
	cfg := KMSConfig{
		KeyMap: map[string]string{
			"us-east-1": "arn:aws:kms:us-east-1:123:key/a",
			"eu-west-1": "arn:aws:kms:eu-west-1:123:key/b",
		},
	}

	resolver, err := NewEnvKEKResolver(cfg)
	if err != nil {
		t.Fatalf("NewEnvKEKResolver: %v", err)
	}

	// Test known regions.
	keyID, err := resolver.ResolveKEK("us-east-1")
	if err != nil {
		t.Errorf("ResolveKEK(us-east-1): %v", err)
	}
	if keyID != "arn:aws:kms:us-east-1:123:key/a" {
		t.Errorf("keyID = %q, want arn:aws:kms:us-east-1:123:key/a", keyID)
	}

	keyID, err = resolver.ResolveKEK("eu-west-1")
	if err != nil {
		t.Errorf("ResolveKEK(eu-west-1): %v", err)
	}
	if keyID != "arn:aws:kms:eu-west-1:123:key/b" {
		t.Errorf("keyID = %q, want arn:aws:kms:eu-west-1:123:key/b", keyID)
	}

	// Test unknown region (fail-closed).
	_, err = resolver.ResolveKEK("ap-northeast-1")
	if err == nil {
		t.Error("expected error for unknown region")
	}
	if !errors.Is(err, ErrUnknownRegion) {
		t.Errorf("error = %v, want ErrUnknownRegion", err)
	}

	// Test Regions().
	regions := resolver.Regions()
	if len(regions) != 2 {
		t.Errorf("Regions() = %v, want 2 regions", regions)
	}
}

func TestEnvKEKResolverValidation(t *testing.T) {
	// Empty key map.
	_, err := NewEnvKEKResolver(KMSConfig{})
	if err == nil {
		t.Error("expected error for empty key map")
	}

	// Empty region in map.
	_, err = NewEnvKEKResolver(KMSConfig{
		KeyMap: map[string]string{"": "key"},
	})
	if err == nil {
		t.Error("expected error for empty region")
	}

	// Empty key ID in map.
	_, err = NewEnvKEKResolver(KMSConfig{
		KeyMap: map[string]string{"us-east-1": ""},
	})
	if err == nil {
		t.Error("expected error for empty key ID")
	}
}

func TestLoadKMSConfigFromEnv(t *testing.T) {
	// Save and restore original env var.
	orig := os.Getenv(KMSKeyMapEnvVar)
	defer os.Setenv(KMSKeyMapEnvVar, orig) //nolint:errcheck

	// Test with valid env var.
	os.Setenv(KMSKeyMapEnvVar, "us-east-1=arn:aws:kms:us-east-1:123:key/a") //nolint:errcheck
	cfg, err := LoadKMSConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadKMSConfigFromEnv: %v", err)
	}
	if cfg.KeyMap["us-east-1"] != "arn:aws:kms:us-east-1:123:key/a" {
		t.Errorf("unexpected key map: %v", cfg.KeyMap)
	}

	// Test with unset env var.
	os.Unsetenv(KMSKeyMapEnvVar) //nolint:errcheck
	_, err = LoadKMSConfigFromEnv()
	if err == nil {
		t.Error("expected error for unset env var")
	}
}

func TestNewKEKResolverFromEnv(t *testing.T) {
	// Save and restore original env var.
	orig := os.Getenv(KMSKeyMapEnvVar)
	defer os.Setenv(KMSKeyMapEnvVar, orig) //nolint:errcheck

	// Test with valid env var.
	os.Setenv(KMSKeyMapEnvVar, "us-east-1=arn:aws:kms:us-east-1:123:key/a,eu-west-1=arn:aws:kms:eu-west-1:123:key/b") //nolint:errcheck
	resolver, err := NewKEKResolverFromEnv()
	if err != nil {
		t.Fatalf("NewKEKResolverFromEnv: %v", err)
	}

	keyID, err := resolver.ResolveKEK("us-east-1")
	if err != nil {
		t.Errorf("ResolveKEK: %v", err)
	}
	if keyID != "arn:aws:kms:us-east-1:123:key/a" {
		t.Errorf("keyID = %q, want arn:aws:kms:us-east-1:123:key/a", keyID)
	}

	// Test fail-closed on unknown region.
	_, err = resolver.ResolveKEK("unknown-region")
	if err == nil {
		t.Error("expected error for unknown region (fail-closed)")
	}
	if !errors.Is(err, ErrUnknownRegion) {
		t.Errorf("error = %v, want ErrUnknownRegion", err)
	}
}

func TestEnvKEKResolverDefensiveCopy(t *testing.T) {
	keyMap := map[string]string{
		"us-east-1": "key1",
	}
	cfg := KMSConfig{KeyMap: keyMap}

	resolver, err := NewEnvKEKResolver(cfg)
	if err != nil {
		t.Fatalf("NewEnvKEKResolver: %v", err)
	}

	// Modify original map.
	keyMap["us-east-1"] = "modified"
	keyMap["eu-west-1"] = "new"

	// Resolver should not be affected.
	keyID, err := resolver.ResolveKEK("us-east-1")
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if keyID != "key1" {
		t.Errorf("keyID = %q, want key1 (defensive copy failed)", keyID)
	}

	_, err = resolver.ResolveKEK("eu-west-1")
	if err == nil {
		t.Error("expected error for eu-west-1 (defensive copy failed)")
	}
}
