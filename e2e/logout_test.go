//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestLogoutRevokesRefreshSession checks the effect of logout, since a redirect
// alone can also be returned when the token hint is invalid or revocation fails.
func TestLogoutRevokesRefreshSession(t *testing.T) {
	result, _, ok := runBFFPasskeyFlowDetailedAt(t, e2eScopeOffline, baseURL())
	if !ok {
		unavailable(t, "authenticated offline_access flow is not exercisable")
	}
	if result.idToken == "" || result.refreshToken == "" {
		t.Fatal("login did not return ID and refresh tokens")
	}
	client := jarNoRedirectClient(t)
	form := url.Values{"id_token_hint": {result.idToken}, "client_id": {e2eClientID()}}
	resp, err := client.Post(baseURL()+"/end_session", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal("logout request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != baseURL()+"/logged-out" {
		t.Fatalf("unexpected logout response: status %d", resp.StatusCode)
	}
	refreshed := postRefreshTokenAt(t, baseURL(), result.refreshToken)
	defer refreshed.Body.Close()
	if refreshed.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh after logout = %d, want 400", refreshed.StatusCode)
	}
	var failure struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(refreshed.Body).Decode(&failure); err != nil {
		t.Fatal("invalid refresh error response")
	}
	if failure.Error != "invalid_grant" {
		t.Errorf("refresh after logout error = %q, want invalid_grant", failure.Error)
	}
}
