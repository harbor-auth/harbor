package oidc

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCanonicalizeScopes(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "empty input",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "nil input",
			input: nil,
			want:  []string{},
		},
		{
			name:  "single scope",
			input: []string{"openid"},
			want:  []string{"openid"},
		},
		{
			name:  "already sorted",
			input: []string{"email", "openid", "profile"},
			want:  []string{"email", "openid", "profile"},
		},
		{
			name:  "unsorted input",
			input: []string{"profile", "openid", "email"},
			want:  []string{"email", "openid", "profile"},
		},
		{
			name:  "duplicates removed",
			input: []string{"openid", "email", "openid", "profile", "email"},
			want:  []string{"email", "openid", "profile"},
		},
		{
			name:  "duplicates with unsorted",
			input: []string{"profile", "openid", "email", "openid", "profile"},
			want:  []string{"email", "openid", "profile"},
		},
		{
			name:  "single duplicate",
			input: []string{"openid", "openid"},
			want:  []string{"openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalizeScopes(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CanonicalizeScopes(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeScopes_DoesNotMutateInput(t *testing.T) {
	input := []string{"profile", "openid", "email"}
	original := make([]string, len(input))
	copy(original, input)

	_ = CanonicalizeScopes(input)

	if !reflect.DeepEqual(input, original) {
		t.Errorf("CanonicalizeScopes mutated input: got %v, want %v", input, original)
	}
}

func TestConsentDecision(t *testing.T) {
	tests := []struct {
		name            string
		grant           *ConsentGrant
		requestedScopes []string
		prompt          string
		wantSkip        bool
		wantEscalation  bool
		wantMerged      []string
		wantErr         error
	}{
		{
			name:            "no grant, no prompt param",
			grant:           nil,
			requestedScopes: []string{"openid", "profile"},
			prompt:          "",
			wantSkip:        false,
			wantEscalation:  false,
		},
		{
			name:            "no grant, prompt=none returns error",
			grant:           nil,
			requestedScopes: []string{"openid"},
			prompt:          "none",
			wantErr:         ErrInteractionRequired,
		},
		{
			name: "covering grant, skip consent",
			grant: &ConsentGrant{
				Scopes: []string{"email", "openid", "profile"},
			},
			requestedScopes: []string{"openid", "profile"},
			prompt:          "",
			wantSkip:        true,
			wantEscalation:  false,
		},
		{
			name: "covering grant, exact match",
			grant: &ConsentGrant{
				Scopes: []string{"openid", "profile"},
			},
			requestedScopes: []string{"profile", "openid"},
			prompt:          "",
			wantSkip:        true,
			wantEscalation:  false,
		},
		{
			name: "scope escalation, need new scopes",
			grant: &ConsentGrant{
				Scopes: []string{"openid"},
			},
			requestedScopes: []string{"openid", "profile", "email"},
			prompt:          "",
			wantSkip:        false,
			wantEscalation:  true,
			wantMerged:      []string{"email", "openid", "profile"},
		},
		{
			name: "scope escalation with prompt=none returns error",
			grant: &ConsentGrant{
				Scopes: []string{"openid"},
			},
			requestedScopes: []string{"openid", "profile"},
			prompt:          "none",
			wantErr:         ErrInteractionRequired,
		},
		{
			name: "prompt=consent forces re-prompt even with covering grant",
			grant: &ConsentGrant{
				Scopes: []string{"openid", "profile"},
			},
			requestedScopes: []string{"openid", "profile"},
			prompt:          "consent",
			wantSkip:        false,
			wantEscalation:  false,
		},
		{
			name: "prompt=consent with escalation",
			grant: &ConsentGrant{
				Scopes: []string{"openid"},
			},
			requestedScopes: []string{"openid", "email"},
			prompt:          "consent",
			wantSkip:        false,
			wantEscalation:  true,
			wantMerged:      []string{"email", "openid"},
		},
		{
			name: "revoked grant treated as no grant",
			grant: func() *ConsentGrant {
				now := time.Now()
				return &ConsentGrant{
					Scopes:    []string{"openid", "profile"},
					RevokedAt: &now,
				}
			}(),
			requestedScopes: []string{"openid"},
			prompt:          "",
			wantSkip:        false,
			wantEscalation:  false,
		},
		{
			name: "revoked grant with prompt=none returns error",
			grant: func() *ConsentGrant {
				now := time.Now()
				return &ConsentGrant{
					Scopes:    []string{"openid"},
					RevokedAt: &now,
				}
			}(),
			requestedScopes: []string{"openid"},
			prompt:          "none",
			wantErr:         ErrInteractionRequired,
		},
		{
			name:            "prompt=consent with no grant",
			grant:           nil,
			requestedScopes: []string{"openid"},
			prompt:          "consent",
			wantSkip:        false,
			wantEscalation:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ConsentDecision(tt.grant, tt.requestedScopes, tt.prompt)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ConsentDecision() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ConsentDecision() unexpected error: %v", err)
			}

			if result.Skip != tt.wantSkip {
				t.Errorf("Skip = %v, want %v", result.Skip, tt.wantSkip)
			}
			if result.Escalation != tt.wantEscalation {
				t.Errorf("Escalation = %v, want %v", result.Escalation, tt.wantEscalation)
			}
			if tt.wantMerged != nil {
				if !reflect.DeepEqual(result.MergedScopes, tt.wantMerged) {
					t.Errorf("MergedScopes = %v, want %v", result.MergedScopes, tt.wantMerged)
				}
			}
		})
	}
}
