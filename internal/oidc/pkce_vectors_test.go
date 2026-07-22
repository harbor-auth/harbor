package oidc_test

// Foundation F2 — frozen golden-vector test for PKCE S256 challenge derivation.
//
// This test locks the exact bytes ComputeS256Challenge produces against a frozen
// corpus (testdata/pkce_vectors.json) so silent crypto drift is impossible: if
// the algorithm ever changes output, this FAILS. It NEVER regenerates the frozen
// expectations — that is the whole point (a passing test that rewrites its own
// oracle catches nothing). A vector whose want_challenge is the "<FILL>" sentinel
// is treated as not-yet-frozen: the test fails loudly and prints the computed
// value so a human can hand-verify and freeze it (VECTOR-CHANGE: policy).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/harbor-auth/harbor/internal/oidc"
)

const vectorSentinel = "<FILL>"

type pkceVector struct {
	Name          string `json:"name"`
	Verifier      string `json:"verifier"`
	WantChallenge string `json:"want_challenge"`
}

type pkceVectorFile struct {
	Comment string       `json:"_comment"`
	Vectors []pkceVector `json:"vectors"`
}

func TestPKCEGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pkce_vectors.json"))
	if err != nil {
		t.Fatalf("read pkce_vectors.json: %v", err)
	}
	var vf pkceVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse pkce_vectors.json: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("pkce_vectors.json has no vectors")
	}

	for _, v := range vf.Vectors {
		got := oidc.ComputeS256Challenge(v.Verifier)
		if v.WantChallenge == vectorSentinel {
			t.Errorf("vector %q is not frozen — verify this value by hand, then set want_challenge to:\n    %q\n(VECTOR-CHANGE: freezing a hand-verified golden vector)", v.Name, got)
			continue
		}
		if got != v.WantChallenge {
			t.Errorf("vector %q: ComputeS256Challenge drift\n  got:  %q\n  want: %q\n(if this change is intentional it requires a VECTOR-CHANGE: PR trailer + human review)", v.Name, got, v.WantChallenge)
		}
	}
}
