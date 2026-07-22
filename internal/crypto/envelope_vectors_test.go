package crypto_test

// Foundation F2 — frozen golden-vector test for AES-256-GCM.
//
// Drift in the GCM output (wrong nonce prefix, changed tag size, altered
// layout) is a crypto regression. This test freezes the byte-exact output
// against a known corpus (testdata/gcm_vectors.json). A value of "<FILL>" is not
// yet frozen: the test FAILS loudly and prints the computed hex so a human can
// independently verify and freeze it. VECTOR-CHANGE policy: frozen values MUST
// NOT be auto-regenerated; changing one requires a `VECTOR-CHANGE:` PR trailer
// and human review.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
)

const gcmVectorSentinel = "<FILL>"

type gcmVector struct {
	Name         string `json:"name"`
	DEKHex       string `json:"dek_hex"`
	NonceHex     string `json:"nonce_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	AADHex       string `json:"aad_hex"`
	WantHex      string `json:"want_hex"`
}

type gcmVectorFile struct {
	Comment string      `json:"_comment"`
	Vectors []gcmVector `json:"vectors"`
}

func TestCryptoGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gcm_vectors.json"))
	if err != nil {
		t.Fatalf("read gcm_vectors.json: %v", err)
	}
	var vf gcmVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse gcm_vectors.json: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("gcm_vectors.json has no vectors")
	}

	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			dekBytes, err := hex.DecodeString(v.DEKHex)
			if err != nil || len(dekBytes) != 32 {
				t.Fatalf("bad dek_hex (len=%d): %v", len(dekBytes), err)
			}
			var dek crypto.DEK
			copy(dek[:], dekBytes)

			nonce, err := hex.DecodeString(v.NonceHex)
			if err != nil {
				t.Fatalf("bad nonce_hex: %v", err)
			}
			plaintext, err := hex.DecodeString(v.PlaintextHex)
			if err != nil {
				t.Fatalf("bad plaintext_hex: %v", err)
			}
			aad, err := hex.DecodeString(v.AADHex)
			if err != nil {
				t.Fatalf("bad aad_hex: %v", err)
			}

			ct := crypto.EncryptForTest(dek, nonce, plaintext, aad)
			got := hex.EncodeToString(ct)

			if v.WantHex == gcmVectorSentinel {
				t.Errorf("vector %q is not frozen — verify this value by hand, then set want_hex to:\n    %q\n(VECTOR-CHANGE: freezing a hand-verified golden vector)",
					v.Name, got)
				return
			}
			if got != v.WantHex {
				t.Errorf("vector %q: GCM output drift\n  got:  %q\n  want: %q\n(if intentional: VECTOR-CHANGE: PR trailer + human review)",
					v.Name, got, v.WantHex)
			}
		})
	}
}
