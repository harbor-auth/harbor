package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestOpenBaoKMSClientRoundTripAndTokenCache(t *testing.T) {
	var logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "short-lived", "lease_duration": 3600}})
		case "/v1/transit/encrypt/harbor-eu":
			if r.Header.Get("X-Vault-Token") != "short-lived" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:ciphertext"}})
		case "/v1/transit/decrypt/harbor-eu":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("secret"))}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestOpenBaoClient(t, server)
	ciphertext, err := client.Encrypt(context.Background(), "harbor-eu", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := client.Decrypt(context.Background(), "harbor-eu", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if got := logins.Load(); got != 1 {
		t.Fatalf("Kubernetes login count = %d, want 1", got)
	}
}

func TestOpenBaoKMSClientDecryptCollapsesErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "token", "lease_duration": 3600}})
			return
		}
		http.Error(w, "specific backend failure", http.StatusBadRequest)
	}))
	defer server.Close()

	client := newTestOpenBaoClient(t, server)
	if _, err := client.Decrypt(context.Background(), "harbor-eu", []byte("vault:v1:bad")); !errors.Is(err, ErrKMSDecryptFailed) {
		t.Fatalf("Decrypt error = %v, want ErrKMSDecryptFailed", err)
	}
}

func TestOpenBaoKMSClientRequiresTLS(t *testing.T) {
	_, err := NewOpenBaoKMSClient(OpenBaoKMSConfig{Address: "http://openbao", Role: "harbor", TokenPath: "/token"})
	if err == nil {
		t.Fatal("expected plaintext HTTP configuration to fail")
	}
}

func TestOpenBaoKMSClientRejectsEndpointPath(t *testing.T) {
	_, err := NewOpenBaoKMSClient(OpenBaoKMSConfig{Address: "https://openbao.example/v1", Role: "harbor", TokenPath: "/token"})
	if err == nil {
		t.Fatal("expected endpoint path to fail")
	}
}

func newTestOpenBaoClient(t *testing.T, server *httptest.Server) *OpenBaoKMSClient {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("kubernetes-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewOpenBaoKMSClient(OpenBaoKMSConfig{
		Address:       server.URL,
		Role:          "harbor-hot",
		TokenPath:     tokenPath,
		HTTPClient:    server.Client(),
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
