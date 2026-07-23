package oidc

// AuthMethod identifies the authentication method used during a login ceremony.
// It is stored in the BFF session and mapped to OIDC ACR/AMR claims at token
// issuance time. Unknown or missing methods produce no claims (fail-closed).
type AuthMethod string

const (
	// AuthMethodWebAuthn is a passkey (platform or roaming authenticator)
	// login without a second factor.
	AuthMethodWebAuthn AuthMethod = "webauthn"

	// AuthMethodTOTP is a passkey login followed by a TOTP second-factor step-up.
	AuthMethodTOTP AuthMethod = "totp"

	// AuthMethodRecoveryCode is authentication via a one-time recovery code.
	AuthMethodRecoveryCode AuthMethod = "recovery_code"
)

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
	default:
		return "", nil
	}
}
