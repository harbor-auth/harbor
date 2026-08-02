//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestOfflineAccessCrossReplicaFlow proves all three durable seams together:
// the authenticated authorization ceremony completes on replica A, replica B
// consumes the one-time Redis authorization code, and the PostgreSQL-backed
// refresh session is usable from replica A.
func TestOfflineAccessCrossReplicaFlow(t *testing.T) {
	if crossReplicaRequired() && hotReplicaBURL() == baseURL() {
		t.Fatal("cross-replica gate requires distinct harbor-hot endpoints")
	}

	result, _, ok := runBFFPasskeyFlowDetailedAt(t, e2eScopeOffline, hotReplicaBURL())
	if !ok {
		unavailable(t, "authenticated offline_access flow is not exercisable")
	}
	if result.refreshToken == "" {
		t.Fatal("offline_access code exchange returned no refresh_token")
	}

	resp := postRefreshTokenAt(t, baseURL(), result.refreshToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("cross-replica refresh = %d, want 200 (read body: %v)", resp.StatusCode, err)
		}
		t.Fatalf("cross-replica refresh = %d, want 200: %s", resp.StatusCode, body)
	}
	assertNoStore(t, resp)
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if rotated.AccessToken == "" || rotated.RefreshToken == "" {
		t.Fatalf("refresh response is unusable: access token set=%t, rotated refresh token set=%t", rotated.AccessToken != "", rotated.RefreshToken != "")
	}
	if !strings.EqualFold(rotated.TokenType, "Bearer") {
		t.Errorf("token_type = %q, want Bearer", rotated.TokenType)
	}
}
