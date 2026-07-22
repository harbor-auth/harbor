package bff

import (
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
