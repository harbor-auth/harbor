package main

import (
	"context"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
)

func TestBuildExternalKeyProviderRejectsUnknownProvider(t *testing.T) {
	t.Setenv("KMS_PROVIDER", "typo")
	_, err := buildExternalKeyProvider(context.Background(), crypto.KMSConfig{
		KeyMap: map[string]string{"EU": "test-key"},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error = %v, want unsupported provider", err)
	}
}
