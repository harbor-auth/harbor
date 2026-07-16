package oidcapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/harbor/harbor/internal/gen/openapi"
)

// GetOpenIDConfiguration serves the OIDC discovery document
// (GET /.well-known/openid-configuration). The response is the spec-generated
// openapi.OpenIDProviderMetadata type, so it cannot drift from the contract.
func (s *Server) GetOpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	body, err := json.Marshal(s.metadata())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to encode provider metadata")
		return
	}
	// Discovery is static-ish and edge-cacheable (docs/DESIGN.md §6.1).
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// metadata builds the discovery document from the configured issuer. Endpoints
// are derived from the issuer so a single config value keeps them consistent
// (docs/DESIGN.md §3.4). The typed enums bake in Harbor's invariants:
// pairwise subjects only (§3.2) and asymmetric signing only (§7).
func (s *Server) metadata() openapi.OpenIDProviderMetadata {
	base := strings.TrimRight(s.issuer, "/")
	userinfoEndpoint := base + "/userinfo"
	return openapi.OpenIDProviderMetadata{
		Issuer:                 base,
		AuthorizationEndpoint:  base + "/authorize",
		TokenEndpoint:          base + "/token",
		UserinfoEndpoint:       &userinfoEndpoint,
		JwksUri:                base + "/jwks.json",
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported: []openapi.OpenIDProviderMetadataSubjectTypesSupported{
			openapi.Pairwise,
		},
		IdTokenSigningAlgValuesSupported: []openapi.OpenIDProviderMetadataIdTokenSigningAlgValuesSupported{
			openapi.ES256,
			openapi.EdDSA,
		},
		// OAuth 2.1: Authorization Code + refresh only — no implicit/ROPC (§3.1).
		// (These enum constants carry the full type prefix because the same
		// values also appear on the /authorize + /token operation schemas.)
		GrantTypesSupported: []openapi.OpenIDProviderMetadataGrantTypesSupported{
			openapi.OpenIDProviderMetadataGrantTypesSupportedAuthorizationCode,
			openapi.OpenIDProviderMetadataGrantTypesSupportedRefreshToken,
		},
		ScopesSupported: []string{"openid", "profile", "email", "offline_access"},
		// PKCE mandatory; S256 only — `plain` is rejected (§3.1, §11.7).
		CodeChallengeMethodsSupported: []openapi.OpenIDProviderMetadataCodeChallengeMethodsSupported{
			openapi.OpenIDProviderMetadataCodeChallengeMethodsSupportedS256,
		},
		// Claims Harbor may assert. Privacy claims (email/email_verified) are
		// emitted only when the matching scope was granted (§3.2, §3.3).
		ClaimsSupported: []string{
			"sub", "iss", "aud", "azp", "exp", "iat",
			"auth_time", "acr", "amr", "nonce", "jti",
			"email", "email_verified",
		},
		// Public-client provider: PKCE replaces a client secret, so the token
		// endpoint requires no client authentication (§3.1).
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}
}
