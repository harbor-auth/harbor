package relay

// invariant_test.go anchors the privacy non-negotiables of the email relay
// (Hide-My-Email) service. These tests fail loudly if a future change weakens
// any of the guarantees the design promises (docs/DESIGN.md §5, §7.5):
//
//   1. Unlinkability: a relay token is purely random, never derived from the
//      user id, so the token cannot be reversed to a user.
//   2. RP-uncorrelation: two relying parties' relay addresses for the SAME user
//      are uncorrelated, so RPs cannot join a user across services.
//   3. Region-pinning: the encrypted mapping (relay token -> real email) is
//      bound to the user's home region and cannot be decrypted in any other
//      region, so the identity link never leaves its region.
//   4. No body retention/logging: the inbound MTA never writes message-body
//      content to logs (§7.5.6).

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/region"
)

const invRealEmail = "user@real.example"

// --- Invariant 1: token is not derived from the user id ---------------------

func TestInvariant_RelayTokenNotDerivedFromUserID(t *testing.T) {
	gen := NewTokenGenerator()
	userID := uuid.New()
	const clientID = "rp.example.com"

	addr1, _, err := NewAddress(gen, userID, clientID, invRealEmail, region.EU)
	if err != nil {
		t.Fatalf("NewAddress() error = %v", err)
	}
	addr2, _, err := NewAddress(gen, userID, clientID, invRealEmail, region.EU)
	if err != nil {
		t.Fatalf("NewAddress() error = %v", err)
	}

	// Two mints with IDENTICAL (user, client, email, region) inputs must yield
	// DIFFERENT tokens. A token derived from any of those inputs would be
	// deterministic (and thus reversible/linkable); randomness is the guarantee.
	if addr1.Token == addr2.Token {
		t.Fatal("token is deterministic across identical inputs — it must be random and unlinkable")
	}

	// The raw user-id bytes must not be embedded anywhere in the decoded token.
	raw, err := base64.RawURLEncoding.DecodeString(addr1.Token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	uid := userID[:]
	if bytes.Contains(raw, uid) {
		t.Error("decoded token contains the raw user-id bytes — the token must not embed the user id")
	}
	// And neither the canonical nor the hex string form of the user id.
	for _, form := range []string{userID.String(), strings.ReplaceAll(userID.String(), "-", "")} {
		if strings.Contains(strings.ToLower(addr1.Token), strings.ToLower(form)) {
			t.Errorf("token contains a user-id string form %q — token must not embed the user id", form)
		}
	}
}

// --- Invariant 2: two RPs for one user are uncorrelated ---------------------

func TestInvariant_TwoRPsForOneUserAreUncorrelated(t *testing.T) {
	gen := NewTokenGenerator()
	userID := uuid.New()

	addrA, _, err := NewAddress(gen, userID, "rp-a.example", invRealEmail, region.EU)
	if err != nil {
		t.Fatalf("NewAddress(rp-a) error = %v", err)
	}
	addrB, _, err := NewAddress(gen, userID, "rp-b.example", invRealEmail, region.EU)
	if err != nil {
		t.Fatalf("NewAddress(rp-b) error = %v", err)
	}

	if addrA.Token == addrB.Token {
		t.Fatal("two RPs' tokens for the same user are identical — they must be uncorrelated")
	}

	rawA, err := base64.RawURLEncoding.DecodeString(addrA.Token)
	if err != nil {
		t.Fatalf("decode token A: %v", err)
	}
	rawB, err := base64.RawURLEncoding.DecodeString(addrB.Token)
	if err != nil {
		t.Fatalf("decode token B: %v", err)
	}

	// The two tokens must not share a long common prefix. For independent random
	// tokens a shared prefix beyond a few bytes is astronomically unlikely, so a
	// long shared prefix would betray a common (linkable) derivation.
	shared := 0
	for i := 0; i < len(rawA) && i < len(rawB); i++ {
		if rawA[i] != rawB[i] {
			break
		}
		shared++
	}
	if shared > 4 {
		t.Errorf("tokens share a %d-byte common prefix — RPs' addresses for one user must be uncorrelated", shared)
	}
}

// --- Invariant 1/2 corollary: tokens are unique across many mints -----------

func TestInvariant_RelayTokensAreUnique(t *testing.T) {
	gen := NewTokenGenerator()
	userID := uuid.New()

	const n = 2000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		addr, _, err := NewAddress(gen, userID, "rp.example", invRealEmail, region.EU)
		if err != nil {
			t.Fatalf("NewAddress() iteration %d error = %v", i, err)
		}
		if _, dup := seen[addr.Token]; dup {
			t.Fatalf("duplicate token generated after %d mints — tokens must be unique/random", i)
		}
		seen[addr.Token] = struct{}{}
	}
}

// --- Invariant 3: mapping is region-pinned ----------------------------------

func TestInvariant_MappingIsRegionPinned(t *testing.T) {
	cipher := crypto.NewCipher()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error = %v", err)
	}
	store := NewStore(&mockQuerier{}, cipher)

	// Encrypt the mapping bound to the EU home region.
	encEU, err := store.encryptMapping(invRealEmail, region.EU, dek)
	if err != nil {
		t.Fatalf("encryptMapping(EU) error = %v", err)
	}

	// It decrypts in its home region...
	got, err := store.decryptMapping(encEU, region.EU, dek)
	if err != nil {
		t.Fatalf("decryptMapping(EU) error = %v", err)
	}
	if got != invRealEmail {
		t.Fatalf("decryptMapping(EU) = %q, want %q", got, invRealEmail)
	}

	// ...but MUST NOT decrypt in any other region. The region is bound as AAD,
	// so a ciphertext created in EU is unreadable elsewhere even with the same
	// DEK — the identity link never leaves its home region.
	for _, other := range []region.Region{region.US, region.Region("AP"), region.Region("other-region")} {
		if other == region.EU {
			continue
		}
		if _, err := store.decryptMapping(encEU, other, dek); err == nil {
			t.Errorf("mapping decrypted cross-region into %q — it must be region-pinned to EU", other)
		}
	}
}

func TestInvariant_MappingCarriesHomeRegion(t *testing.T) {
	// The domain Mapping produced at mint time records the home region so the
	// encrypted blob is always decrypted under the correct region AAD.
	gen := NewTokenGenerator()
	_, mapping, err := NewAddress(gen, uuid.New(), "rp.example", invRealEmail, region.US)
	if err != nil {
		t.Fatalf("NewAddress() error = %v", err)
	}
	if mapping.Region != region.US {
		t.Errorf("mapping.Region = %q, want %q", mapping.Region, region.US)
	}
	_ = mapping.RealEmail // plaintext lives only in the in-memory Mapping, never logged
}

// --- Invariant 4: no message body is ever logged ----------------------------

// invBodyLookup is a minimal AddressLookup returning a fixed active address.
type invBodyLookup struct{ addr *Address }

func (l *invBodyLookup) GetByToken(_ context.Context, _ string) (*Address, []byte, error) {
	return l.addr, []byte("enc-mapping"), nil
}

// invDiscardForwarder streams the message to /dev/null without retaining it.
type invDiscardForwarder struct{}

func (invDiscardForwarder) Forward(_ context.Context, _, _ string, r io.Reader) error {
	_, _ = io.Copy(io.Discard, r)
	return nil
}

// invStubResolver resolves any mapping to a fixed real email.
type invStubResolver struct{}

func (invStubResolver) ResolveRealEmail(_ context.Context, _ *Address, _ []byte) (string, error) {
	return "real@user.example", nil
}

// runInboundTransaction drives a full MAIL/RCPT/DATA transaction against a
// backend built from cfg (Lookup/Domain/Region are filled in) and returns the
// captured log output. The debug level is enabled so nothing is filtered out.
func runInboundTransaction(t *testing.T, cfg MTAConfig, msg string) string {
	t.Helper()
	var logBuf bytes.Buffer
	cfg.Logger = slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.Lookup = &invBodyLookup{addr: &Address{Token: "tok", State: StateActive, Region: region.EU}}
	cfg.Domain = "relay.eu.harbor.id"
	cfg.Region = region.EU

	b := NewBackend(cfg)
	sess := &Session{backend: b, recipients: make([]*recipientInfo, 0, 1)}

	if err := sess.Mail("sender@external.example", nil); err != nil {
		t.Fatalf("Mail() error = %v", err)
	}
	if err := sess.Rcpt("tok@relay.eu.harbor.id", nil); err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}
	if err := sess.Data(strings.NewReader(msg)); err != nil {
		t.Fatalf("Data() error = %v", err)
	}
	return logBuf.String()
}

func TestInvariant_NoMessageBodyLogging(t *testing.T) {
	const bodyMarker = "SUPER-SECRET-BODY-MARKER-ce6f1a2b"
	const subjectMarker = "SECRET-SUBJECT-MARKER-9d4e"
	msg := "From: sender@external.example\r\n" +
		"To: tok@relay.eu.harbor.id\r\n" +
		"Subject: " + subjectMarker + "\r\n" +
		"\r\n" +
		bodyMarker + "\r\n"

	cases := []struct {
		name string
		cfg  MTAConfig
	}{
		{
			// Fast path: no authenticator — the body is read and discarded.
			name: "fast path (no auth)",
			cfg:  MTAConfig{},
		},
		{
			// Auth + forward path: the body is buffered in memory for
			// SPF/DKIM/DMARC and forwarding, then discarded — still never logged.
			name: "auth + forward path",
			cfg: MTAConfig{
				Authenticator: newAuthenticatorWithResolvers(nil, func(string) ([]string, error) {
					return nil, nil // no SPF/DKIM/DMARC records → verdicts "none", accepted
				}),
				Forwarder:       invDiscardForwarder{},
				MappingResolver: invStubResolver{},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := runInboundTransaction(t, tc.cfg, msg)

			if strings.Contains(logs, bodyMarker) {
				t.Errorf("message body content leaked into logs (§7.5.6):\n%s", logs)
			}
			if strings.Contains(logs, subjectMarker) {
				t.Errorf("message subject leaked into logs (§7.5.6):\n%s", logs)
			}
		})
	}
}
