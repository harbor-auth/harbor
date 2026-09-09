package crypto

import (
	"context"
	"errors"
	"testing"
)

func TestUserDEKMigrationPreservesKeysAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	legacy, err := NewLocalKeyProvider("legacy-user-dek-secret-with-at-least-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	kms := NewKMSKeyProvider(NewFakeKMSClient(), NewStaticKEKResolver(map[string]string{"EU": "users-eu"}))
	bridge := NewUserKeyProvider(kms, legacy)
	final := NewUserKeyProvider(kms, nil)
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	old, err := legacy.WrapDEK(ctx, "EU", dek)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bridge.UnwrapDEK(ctx, "EU", old); err != nil || got != dek {
		t.Fatal("bridge cannot read legacy envelope", err)
	}
	if _, err := final.UnwrapDEK(ctx, "EU", old); !errors.Is(err, ErrDecryptFailed) {
		t.Fatal("legacy envelope accepted after migration")
	}
	wrapped, err := bridge.WrapDEK(ctx, "EU", dek)
	if err != nil {
		t.Fatal(err)
	}
	if !IsExternalUserDEK(wrapped) {
		t.Fatal("new write is not externally wrapped")
	}
	if got, err := final.UnwrapDEK(ctx, "EU", wrapped); err != nil || got != dek {
		t.Fatal("external reader changed DEK", err)
	}
	if _, err := legacy.UnwrapDEK(ctx, "EU", wrapped); err == nil {
		t.Fatal("legacy root can decrypt external envelope")
	}
	for name, blob := range map[string][]byte{"erased": {}, "truncated": wrapped[:20], "unknown": []byte("unknown-envelope"), "tampered": append([]byte(nil), wrapped...)} {
		if name == "tampered" {
			blob[len(blob)-1] ^= 1
		}
		if _, err := bridge.UnwrapDEK(ctx, "EU", blob); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("%s did not fail closed", name)
		}
	}
	if _, err := bridge.UnwrapDEK(ctx, "US", wrapped); !errors.Is(err, ErrDecryptFailed) {
		t.Fatal("cross-region envelope accepted")
	}
}

func TestUserDEKConfigurationRejectsLingeringRoot(t *testing.T) {
	t.Setenv("USER_DEK_PROVIDER", "openbao")
	t.Setenv("USER_DEK_KEY_MAP", "EU=users-eu")
	t.Setenv("OPENBAO_ADDR", "https://bao.example")
	t.Setenv("OPENBAO_KUBERNETES_ROLE", "harbor-hot")
	t.Setenv("OPENBAO_TOKEN_PATH", "/unused/projected-token")
	t.Setenv("OPENBAO_CACERT", "")
	t.Setenv("HARBOR_KMS_SECRET", "legacy-user-dek-secret-with-at-least-32-bytes")
	t.Setenv("USER_DEK_LEGACY_READ_ENABLED", "false")
	if _, err := NewUserKeyProviderFromEnv(); err == nil {
		t.Fatal("obsolete root accepted with legacy reads disabled")
	}
	t.Setenv("USER_DEK_LEGACY_READ_ENABLED", "true")
	if _, err := NewUserKeyProviderFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HARBOR_KMS_SECRET", "")
	if _, err := NewUserKeyProviderFromEnv(); err == nil {
		t.Fatal("migration accepted without legacy key")
	}
	t.Setenv("USER_DEK_LEGACY_READ_ENABLED", "false")
	if _, err := NewUserKeyProviderFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USER_DEK_PROVIDER", "typo")
	if _, err := NewUserKeyProviderFromEnv(); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
