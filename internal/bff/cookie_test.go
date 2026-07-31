package bff

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetBFFCookie(t *testing.T) {
	w := httptest.NewRecorder()
	SetBFFCookie(w, "test-request-id", 5*time.Minute)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != CookieName {
		t.Errorf("Name = %q, want %q", c.Name, CookieName)
	}
	if c.Value != "test-request-id" {
		t.Errorf("Value = %q, want %q", c.Value, "test-request-id")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	if c.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, 300)
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want %v", c.SameSite, http.SameSiteStrictMode)
	}
}

func TestReadBFFCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  CookieName,
		Value: "my-request-id",
	})

	got := ReadBFFCookie(req)
	if got != "my-request-id" {
		t.Errorf("ReadBFFCookie() = %q, want %q", got, "my-request-id")
	}
}

func TestReadBFFCookie_NotPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	got := ReadBFFCookie(req)
	if got != "" {
		t.Errorf("ReadBFFCookie() = %q, want empty string", got)
	}
}

func TestReadBFFCookie_WrongName(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "some-other-cookie",
		Value: "some-value",
	})

	got := ReadBFFCookie(req)
	if got != "" {
		t.Errorf("ReadBFFCookie() = %q, want empty string", got)
	}
}

func TestClearBFFCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ClearBFFCookie(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != CookieName {
		t.Errorf("Name = %q, want %q", c.Name, CookieName)
	}
	if c.Value != "" {
		t.Errorf("Value = %q, want empty string", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1 (delete)", c.MaxAge)
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
}

// --- Browser nonce helpers ---

func TestNewBrowserNonce(t *testing.T) {
	n1, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}
	if len(n1) != 32 {
		t.Errorf("len(nonce) = %d, want 32", len(n1))
	}

	n2, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Error("two successive nonces are equal; CSPRNG appears broken")
	}
}

func TestHashNonce(t *testing.T) {
	nonce := make([]byte, 32)
	hash := HashNonce(nonce)
	if len(hash) != 32 {
		t.Errorf("len(HashNonce) = %d, want 32 (SHA-256 output)", len(hash))
	}

	// Same input must produce the same hash.
	hash2 := HashNonce(nonce)
	if !bytes.Equal(hash, hash2) {
		t.Error("HashNonce is not deterministic")
	}

	// Different input must produce a different hash.
	nonce2 := make([]byte, 32)
	nonce2[0] = 1
	hash3 := HashNonce(nonce2)
	if bytes.Equal(hash, hash3) {
		t.Error("different nonces produced the same hash")
	}
}

func TestSetBFFNonceCookie(t *testing.T) {
	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}

	w := httptest.NewRecorder()
	SetBFFNonceCookie(w, nonce, 5*time.Minute)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != NonceCookieName {
		t.Errorf("Name = %q, want %q", c.Name, NonceCookieName)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	if c.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want 300", c.MaxAge)
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want %v", c.SameSite, http.SameSiteStrictMode)
	}

	// Value must be the base64url encoding of the nonce.
	gotNonce, decErr := base64.RawURLEncoding.DecodeString(c.Value)
	if decErr != nil {
		t.Fatalf("cookie value is not valid base64url: %v", decErr)
	}
	if !bytes.Equal(gotNonce, nonce) {
		t.Error("decoded cookie value does not match original nonce")
	}
}

func TestReadBFFNonceCookie(t *testing.T) {
	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  NonceCookieName,
		Value: base64.RawURLEncoding.EncodeToString(nonce),
	})

	got, err := ReadBFFNonceCookie(req)
	if err != nil {
		t.Fatalf("ReadBFFNonceCookie() error = %v", err)
	}
	if !bytes.Equal(got, nonce) {
		t.Error("ReadBFFNonceCookie() returned different nonce than was set")
	}
}

func TestReadBFFNonceCookie_NotPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := ReadBFFNonceCookie(req)
	if err == nil {
		t.Error("ReadBFFNonceCookie() expected error when cookie absent, got nil")
	}
}

func TestReadBFFNonceCookie_Malformed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  NonceCookieName,
		Value: "!!!not-base64!!!",
	})
	_, err := ReadBFFNonceCookie(req)
	if err == nil {
		t.Error("ReadBFFNonceCookie() expected error for malformed base64, got nil")
	}
}

func TestClearBFFNonceCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ClearBFFNonceCookie(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != NonceCookieName {
		t.Errorf("Name = %q, want %q", c.Name, NonceCookieName)
	}
	if c.Value != "" {
		t.Errorf("Value = %q, want empty string", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1 (delete)", c.MaxAge)
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want %v", c.SameSite, http.SameSiteStrictMode)
	}
}

func TestNonceMatches(t *testing.T) {
	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}
	storedHash := HashNonce(nonce)

	if !NonceMatches(nonce, storedHash) {
		t.Error("NonceMatches() = false for matching nonce+hash, want true")
	}
}

func TestNonceMatches_WrongNonce(t *testing.T) {
	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}
	storedHash := HashNonce(nonce)

	attackerNonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}
	if NonceMatches(attackerNonce, storedHash) {
		t.Error("NonceMatches() = true for wrong nonce, want false")
	}
}

func TestNonceMatches_EmptyNonce(t *testing.T) {
	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}
	storedHash := HashNonce(nonce)

	if NonceMatches(nil, storedHash) {
		t.Error("NonceMatches() = true for nil nonce, want false")
	}
	if NonceMatches([]byte{}, storedHash) {
		t.Error("NonceMatches() = true for empty nonce, want false")
	}
}

func TestNonceMatches_EmptyStoredHash(t *testing.T) {
	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce() error = %v", err)
	}

	if NonceMatches(nonce, nil) {
		t.Error("NonceMatches() = true for nil storedHash, want false")
	}
	if NonceMatches(nonce, []byte{}) {
		t.Error("NonceMatches() = true for empty storedHash, want false")
	}
}
