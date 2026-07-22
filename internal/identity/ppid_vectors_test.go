package identity_test

// Foundation F2 — frozen golden-vector test for PPID derivation.
//
// This locks the exact sub bytes DerivePPID produces against a frozen corpus
// (testdata/ppid_vectors.json). PPID drift is catastrophic — it would silently
// change every user's identity at every RP — so this test freezes the output and
// NEVER regenerates the expectations. A vector whose want_ppid is the "<FILL>"
// sentinel is not yet frozen: the test fails loudly and prints the computed
// value so a human can independently verify and freeze it (VECTOR-CHANGE: policy).

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/harbor-auth/harbor/internal/identity"
)

const ppidVectorSentinel = "<FILL>"

type ppidVector struct {
	Name      string `json:"name"`
	SecretHex string `json:"secret_hex"`
	Sector    string `json:"sector"`
	UserID    string `json:"user_id"`
	WantPPID  string `json:"want_ppid"`
}

type ppidVectorFile struct {
	Comment string       `json:"_comment"`
	Vectors []ppidVector `json:"vectors"`
}

func TestPPIDGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "ppid_vectors.json"))
	if err != nil {
		t.Fatalf("read ppid_vectors.json: %v", err)
	}
	var vf ppidVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse ppid_vectors.json: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("ppid_vectors.json has no vectors")
	}

	for _, v := range vf.Vectors {
		secret, err := hex.DecodeString(v.SecretHex)
		if err != nil {
			t.Errorf("vector %q: bad secret_hex: %v", v.Name, err)
			continue
		}
		got, err := identity.DerivePPID(secret, v.Sector, v.UserID)
		if err != nil {
			t.Errorf("vector %q: DerivePPID error = %v", v.Name, err)
			continue
		}
		if v.WantPPID == ppidVectorSentinel {
			t.Errorf("vector %q is not frozen — verify this value by hand, then set want_ppid to:\n    %q\n(VECTOR-CHANGE: freezing a hand-verified golden vector)", v.Name, got)
			continue
		}
		if got != v.WantPPID {
			t.Errorf("vector %q: DerivePPID drift\n  got:  %q\n  want: %q\n(if this change is intentional it requires a VECTOR-CHANGE: PR trailer + human review)", v.Name, got, v.WantPPID)
		}
	}
}
