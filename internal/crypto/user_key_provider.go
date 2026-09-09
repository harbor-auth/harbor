package crypto

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const userDEKEnvelopePrefix = "harbor:user-dek:v1:"

// UserKeyProvider sends new user DEKs to the external provider. Legacy reads
// are an explicit, temporary migration option; external failures never fall
// back to the application-held key. A nil legacy provider rejects old blobs.
type UserKeyProvider struct {
	KeyProvider
	legacy      KeyProvider
	writeLegacy bool
}

func NewUserKeyProvider(external, legacy KeyProvider) *UserKeyProvider {
	return &UserKeyProvider{KeyProvider: external, legacy: legacy}
}

func (p *UserKeyProvider) WrapDEK(ctx context.Context, region string, dek DEK) ([]byte, error) {
	if p.writeLegacy {
		return p.legacy.WrapDEK(ctx, region, dek)
	}
	wrapped, err := p.KeyProvider.WrapDEK(ctx, region, dek)
	if err != nil {
		return nil, err
	}
	return append([]byte(userDEKEnvelopePrefix), wrapped...), nil
}

// UserDEKEnvelopePrefix returns the marker used to find unmigrated DB rows.
func UserDEKEnvelopePrefix() []byte { return []byte(userDEKEnvelopePrefix) }

func IsExternalUserDEK(wrapped []byte) bool {
	return bytes.HasPrefix(wrapped, []byte(userDEKEnvelopePrefix))
}

func (p *UserKeyProvider) UnwrapDEK(ctx context.Context, region string, wrapped []byte) (DEK, error) {
	if IsExternalUserDEK(wrapped) {
		return p.KeyProvider.UnwrapDEK(ctx, region, wrapped[len(userDEKEnvelopePrefix):])
	}
	// A legacy AES-GCM DEK is exactly nonce(12) + DEK(32) + tag(16).
	// Empty (crypto-shredded), truncated, and unknown-format blobs fail closed.
	if p.legacy != nil && len(wrapped) == gcmNonceSize+32+16 {
		return p.legacy.UnwrapDEK(ctx, region, wrapped)
	}
	return DEK{}, ErrDecryptFailed
}

// NewUserKeyProviderFromEnv preserves the existing local deployment until the
// operator explicitly enables OpenBao. After migration, disabling legacy reads
// rejects HARBOR_KMS_SECRET so an obsolete wrapping root cannot linger unnoticed.
func NewUserKeyProviderFromEnv() (KeyProvider, error) {
	switch provider := strings.ToLower(os.Getenv("USER_DEK_PROVIDER")); provider {
	case "", "local":
		return NewLocalKeyProvider(os.Getenv("HARBOR_KMS_SECRET"))
	case "openbao":
		config, err := ParseKMSKeyMap(os.Getenv("USER_DEK_KEY_MAP"))
		if err != nil {
			return nil, fmt.Errorf("USER_DEK_KEY_MAP: %w", err)
		}
		resolver, err := NewEnvKEKResolver(config)
		if err != nil {
			return nil, err
		}
		mount := os.Getenv("OPENBAO_TRANSIT_MOUNT")
		if mount == "" {
			mount = "transit"
		}
		client, err := NewOpenBaoKMSClient(OpenBaoKMSConfig{
			Address: os.Getenv("OPENBAO_ADDR"), Role: os.Getenv("OPENBAO_KUBERNETES_ROLE"),
			TokenPath: os.Getenv("OPENBAO_TOKEN_PATH"), CACertPath: os.Getenv("OPENBAO_CACERT"), TransitMount: mount,
		})
		if err != nil {
			return nil, err
		}
		legacyEnabled := false
		if value := os.Getenv("USER_DEK_LEGACY_READ_ENABLED"); value != "" {
			legacyEnabled, err = strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid USER_DEK_LEGACY_READ_ENABLED: %w", err)
			}
		}
		var legacy KeyProvider
		if legacyEnabled {
			legacy, err = NewLocalKeyProvider(os.Getenv("HARBOR_KMS_SECRET"))
			if err != nil {
				return nil, fmt.Errorf("legacy user-DEK migration key: %w", err)
			}
		} else if os.Getenv("HARBOR_KMS_SECRET") != "" {
			return nil, fmt.Errorf("remove HARBOR_KMS_SECRET when legacy user-DEK reads are disabled")
		}
		writesExternal := true
		if value := os.Getenv("USER_DEK_WRITE_EXTERNAL_ENABLED"); value != "" {
			writesExternal, err = strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid USER_DEK_WRITE_EXTERNAL_ENABLED: %w", err)
			}
		}
		if !writesExternal && legacy == nil {
			return nil, fmt.Errorf("legacy writes require the explicit legacy reader")
		}
		result := NewUserKeyProvider(NewKMSKeyProvider(client, resolver), legacy)
		result.writeLegacy = !writesExternal
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported USER_DEK_PROVIDER %q", provider)
	}
}
