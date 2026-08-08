package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
)

// AuthMethod identifies the authentication method used during a login ceremony.
// It is stored in the BFF session and mapped to OIDC ACR/AMR claims at token
// issuance time. Unknown or missing methods produce no claims (fail-closed).
type AuthMethod string

const (
	ClientAuthNone        = "none"
	ClientAuthSecretBasic = "client_secret_basic"
	ClientAuthSecretPost  = "client_secret_post"

	// AuthMethodWebAuthn is a passkey (platform or roaming authenticator)
	// login without a second factor.
	AuthMethodWebAuthn AuthMethod = "webauthn"

	// AuthMethodTOTP is a passkey login followed by a TOTP second-factor step-up.
	AuthMethodTOTP AuthMethod = "totp"

	// AuthMethodRecoveryCode is authentication via a one-time recovery code.
	AuthMethodRecoveryCode AuthMethod = "recovery_code"

	// AuthMethodFederated is authentication via the corporate-SSO handoff
	// (POST /admin/v1/user-sessions -> GET /login/sso): the user
	// authenticated against their employer's own IdP, not a Harbor-held
	// credential.
	AuthMethodFederated AuthMethod = "federated"
)

// AuthenticateClient resolves a registered client and verifies that the
// presented authentication method matches its registration. Secret hashes are
// SHA-256 digests (the format produced by dynamic registration) and are always
// compared in constant time.
func (s *Service) AuthenticateClient(ctx context.Context, clientID, method, secret string) (Client, bool) {
	if s == nil || s.clients == nil || clientID == "" {
		return Client{}, false
	}
	return AuthenticateClient(ctx, s.clients, clientID, method, secret)
}

// AuthenticateClient performs client authentication against registry without
// requiring a Service. An omitted method in legacy registrations and direct
// service requests means "none", matching RFC 7591's default.
func AuthenticateClient(ctx context.Context, registry ClientRegistry, clientID, method, secret string) (Client, bool) {
	if registry == nil || clientID == "" {
		return Client{}, false
	}
	client, found := registry.Lookup(ctx, clientID)
	registeredMethod := client.TokenEndpointAuthMethod
	if registeredMethod == "" {
		registeredMethod = ClientAuthNone
	}
	if method == "" {
		method = ClientAuthNone
	}
	if !found || registeredMethod != method {
		return Client{}, false
	}
	switch method {
	case ClientAuthNone:
		if secret != "" {
			return Client{}, false
		}
	case ClientAuthSecretBasic, ClientAuthSecretPost:
		presented := sha256.Sum256([]byte(secret))
		if len(client.SecretHash) != sha256.Size || subtle.ConstantTimeCompare(presented[:], client.SecretHash) != 1 {
			return Client{}, false
		}
	default:
		return Client{}, false
	}
	return client, true
}

// MapAuthMethodToACRAMR returns the OIDC ACR and AMR claim values for the given
// AuthMethod. Fail-closed: an unknown or empty method returns ("", nil) so that
// no ACR/AMR claims are emitted rather than emitting a lie (OIDC Core §2).
func MapAuthMethodToACRAMR(method AuthMethod) (acr string, amr []string) {
	switch method {
	case AuthMethodWebAuthn:
		return "urn:harbor:ac:webauthn", []string{"hwk", "user"}
	case AuthMethodTOTP:
		return "urn:harbor:ac:webauthn+totp", []string{"hwk", "otp", "user"}
	case AuthMethodRecoveryCode:
		return "urn:harbor:ac:recovery", []string{"rc"}
	case AuthMethodFederated:
		// "fed" is the RFC 8176 registered AMR value for a federated
		// assertion. Deliberately NOT "user" — an RFC 8176 user-presence
		// test Harbor cannot attest for a third-party redirect it never
		// witnessed a ceremony for — and NOT hwk/pwd/otp/mfa either.
		// Forwarding the IdP's own AMR values (if any) from the SAML
		// assertion is deliberately out of scope: Harbor did not verify
		// them and has no way to.
		return "urn:harbor:ac:federated", []string{"fed"}
	default:
		return "", nil
	}
}
