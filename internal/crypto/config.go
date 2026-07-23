package crypto

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// KMSConfig holds configuration for KMS-based key encryption.
type KMSConfig struct {
	// KeyMap maps region names to KMS key ARNs or aliases.
	// Example: {"us-east-1": "arn:aws:kms:us-east-1:123456789012:key/abc123"}
	KeyMap map[string]string
}

// ErrUnknownRegion is returned when a region has no configured KEK.
// This error is intentionally fail-closed: unknown regions are rejected,
// never falling back to another region's KEK.
var ErrUnknownRegion = errors.New("crypto: unknown region")

// EnvKEKResolver resolves regions to KEK key IDs using environment configuration.
// It fails closed on unknown regions — never falls back to another region's KEK.
//
// EnvKEKResolver is safe for concurrent use (the map is read-only after construction).
type EnvKEKResolver struct {
	keys map[string]string // region → KEK key ID (immutable after construction)
}

// Compile-time proof that EnvKEKResolver implements KEKResolver.
var _ KEKResolver = (*EnvKEKResolver)(nil)

// NewEnvKEKResolver creates a KEKResolver from a KMSConfig.
// Returns an error if the config is invalid (e.g., empty key map).
func NewEnvKEKResolver(cfg KMSConfig) (*EnvKEKResolver, error) {
	if len(cfg.KeyMap) == 0 {
		return nil, fmt.Errorf("crypto: NewEnvKEKResolver: empty key map")
	}

	// Validate all entries.
	for region, keyID := range cfg.KeyMap {
		if region == "" {
			return nil, fmt.Errorf("crypto: NewEnvKEKResolver: empty region in key map")
		}
		if keyID == "" {
			return nil, fmt.Errorf("crypto: NewEnvKEKResolver: empty key ID for region %q", region)
		}
	}

	// Make a defensive copy.
	keys := make(map[string]string, len(cfg.KeyMap))
	for k, v := range cfg.KeyMap {
		keys[k] = v
	}

	return &EnvKEKResolver{keys: keys}, nil
}

// ResolveKEK implements KEKResolver. It returns the KMS key ID for the given
// region, or ErrUnknownRegion if the region is not configured.
//
// This method fails closed: unknown regions are rejected, never falling back
// to another region's KEK. This prevents data sovereignty violations where
// data intended for one region could be encrypted with another region's key.
func (r *EnvKEKResolver) ResolveKEK(region string) (string, error) {
	keyID, ok := r.keys[region]
	if !ok {
		return "", fmt.Errorf("%w: %q has no configured KEK", ErrUnknownRegion, region)
	}
	return keyID, nil
}

// Regions returns all configured regions. Useful for operational visibility.
func (r *EnvKEKResolver) Regions() []string {
	regions := make([]string, 0, len(r.keys))
	for region := range r.keys {
		regions = append(regions, region)
	}
	return regions
}

// ParseKMSKeyMap parses a KMS_KEY_MAP environment variable value into a KMSConfig.
//
// Format: "region1=key1,region2=key2,..."
// Example: "us-east-1=arn:aws:kms:us-east-1:123456789012:key/abc,eu-west-1=arn:aws:kms:eu-west-1:123456789012:key/def"
//
// Returns an error if the format is invalid or if there are duplicate regions.
func ParseKMSKeyMap(envValue string) (KMSConfig, error) {
	if envValue == "" {
		return KMSConfig{}, fmt.Errorf("crypto: ParseKMSKeyMap: empty value")
	}

	keyMap := make(map[string]string)
	pairs := strings.Split(envValue, ",")

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split on first '=' only (key ARNs may contain '=').
		idx := strings.Index(pair, "=")
		if idx == -1 {
			return KMSConfig{}, fmt.Errorf("crypto: ParseKMSKeyMap: invalid format %q (expected region=key)", pair)
		}

		region := strings.TrimSpace(pair[:idx])
		keyID := strings.TrimSpace(pair[idx+1:])

		if region == "" {
			return KMSConfig{}, fmt.Errorf("crypto: ParseKMSKeyMap: empty region in %q", pair)
		}
		if keyID == "" {
			return KMSConfig{}, fmt.Errorf("crypto: ParseKMSKeyMap: empty key ID for region %q", region)
		}

		// Check for duplicates.
		if _, exists := keyMap[region]; exists {
			return KMSConfig{}, fmt.Errorf("crypto: ParseKMSKeyMap: duplicate region %q", region)
		}

		keyMap[region] = keyID
	}

	if len(keyMap) == 0 {
		return KMSConfig{}, fmt.Errorf("crypto: ParseKMSKeyMap: no valid entries")
	}

	return KMSConfig{KeyMap: keyMap}, nil
}

// KMSKeyMapEnvVar is the environment variable name for the KMS key map.
const KMSKeyMapEnvVar = "KMS_KEY_MAP"

// LoadKMSConfigFromEnv loads KMS configuration from environment variables.
//
// Reads KMS_KEY_MAP environment variable in the format:
// "region1=arn:aws:kms:...,region2=arn:aws:kms:..."
//
// Returns an error if the environment variable is not set or has invalid format.
func LoadKMSConfigFromEnv() (KMSConfig, error) {
	envValue := os.Getenv(KMSKeyMapEnvVar)
	if envValue == "" {
		return KMSConfig{}, fmt.Errorf("crypto: %s environment variable not set", KMSKeyMapEnvVar)
	}
	return ParseKMSKeyMap(envValue)
}

// NewKEKResolverFromEnv creates a KEKResolver from environment variables.
// This is a convenience function that combines LoadKMSConfigFromEnv and NewEnvKEKResolver.
//
// Returns an error if the environment variable is not set, has invalid format,
// or contains invalid entries.
func NewKEKResolverFromEnv() (KEKResolver, error) {
	cfg, err := LoadKMSConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewEnvKEKResolver(cfg)
}
