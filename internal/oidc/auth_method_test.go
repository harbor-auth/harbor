package oidc

import (
	"reflect"
	"testing"
)

func TestMapAuthMethodToACRAMR(t *testing.T) {
	tests := []struct {
		method  AuthMethod
		wantACR string
		wantAMR []string
	}{
		{
			method:  AuthMethodWebAuthn,
			wantACR: "urn:harbor:ac:webauthn",
			wantAMR: []string{"hwk", "user"},
		},
		{
			method:  AuthMethodTOTP,
			wantACR: "urn:harbor:ac:webauthn+totp",
			wantAMR: []string{"hwk", "otp", "user"},
		},
		{
			method:  AuthMethodRecoveryCode,
			wantACR: "urn:harbor:ac:recovery",
			wantAMR: []string{"rc"},
		},
		// Fail-closed: unknown method must produce no claims rather than a lie.
		{
			method:  AuthMethod("unknown"),
			wantACR: "",
			wantAMR: nil,
		},
		// Fail-closed: empty method must produce no claims rather than a lie.
		{
			method:  AuthMethod(""),
			wantACR: "",
			wantAMR: nil,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			gotACR, gotAMR := MapAuthMethodToACRAMR(tt.method)
			if gotACR != tt.wantACR {
				t.Errorf("MapAuthMethodToACRAMR(%q) ACR = %q, want %q", tt.method, gotACR, tt.wantACR)
			}
			if !reflect.DeepEqual(gotAMR, tt.wantAMR) {
				t.Errorf("MapAuthMethodToACRAMR(%q) AMR = %v, want %v", tt.method, gotAMR, tt.wantAMR)
			}
		})
	}
}
