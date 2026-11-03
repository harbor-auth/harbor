//go:build integration

package cloudapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// Full boundary: real HTTP router, service JWT verification, real Redis replay
// guard, PostgreSQL migration/function/store, and hot-path client authenticator.
func TestIntegrationGenerationConfigurationContract(t *testing.T) {
	env := newIntegrationEnv(t)
	namespace := uniqueID("generation-ns")
	createIntegrationNamespace(t, env, namespace)
	clientID := uniqueID("generation-web-client")
	path := fmt.Sprintf("/admin/v1/namespaces/%s/clients/%s/configuration", namespace, clientID)
	const secret = "real-configuration-contract-secret"
	body := fmt.Sprintf(`{"generation":1,"redirect_uris":["https://customer.example/cb"],"token_endpoint_auth_method":"client_secret_basic","client_secret_hash":%q}`, hashHex(secret))
	denied := env.do(t, http.MethodPut, path, "", uniqueID("generation-key"), body)
	if denied.StatusCode != 401 {
		t.Fatal("configuration route bypassed authentication")
	}
	denied.Body.Close()
	denied = env.do(t, http.MethodPut, path, env.mint(t, "clients:read", 90*time.Second), uniqueID("generation-key"), body)
	if denied.StatusCode != 403 {
		t.Fatal("configuration route bypassed write scope")
	}
	denied.Body.Close()
	accepted := env.do(t, http.MethodPut, path, env.mint(t, "clients:write", 90*time.Second), uniqueID("generation-key"), body)
	defer accepted.Body.Close()
	if accepted.StatusCode != 200 || accepted.Header.Get("X-Harbor-Generation") != "1" {
		t.Fatalf("configuration rejected or missing ACK: status=%d", accepted.StatusCode)
	}
	var result cloudopenapi.ClientResponse
	if err := json.NewDecoder(accepted.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Generation != 1 || result.ClientId != clientID || result.NamespaceId != namespace || result.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatal("configuration JSON ACK does not match request")
	}
	if _, ok := oidc.AuthenticateClient(t.Context(), env.deps.registry, clientID, oidc.ClientAuthSecretBasic, secret); !ok {
		t.Fatal("provisioned backend credential cannot authenticate")
	}
	if _, ok := oidc.AuthenticateClient(t.Context(), env.deps.registry, clientID, oidc.ClientAuthNone, ""); ok {
		t.Fatal("confidential client became public")
	}
	deletion := env.do(t, http.MethodDelete, path+"?generation=2", env.mint(t, "clients:write", 90*time.Second), uniqueID("generation-delete"), "")
	defer deletion.Body.Close()
	if deletion.StatusCode != 204 || deletion.Header.Get("X-Harbor-Generation") != "2" {
		t.Fatal("terminal deletion missing generation ACK")
	}
	if _, ok := oidc.AuthenticateClient(t.Context(), env.deps.registry, clientID, oidc.ClientAuthSecretBasic, secret); ok {
		t.Fatal("deleted client still authenticates")
	}
}
