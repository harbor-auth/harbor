package oidc

import (
	"reflect"
	"testing"
)

func TestCanonicalizeScopes(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		want   []string
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
