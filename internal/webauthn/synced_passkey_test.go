package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Exercise real signature/challenge validation against the DB adapter, including
// counterless synced passkeys and metadata lost by historical registrations.
func TestSyncedPasskeyLogin(t *testing.T) {
	const deviceFlags = int16(0x05)   // UP + UV
	const syncedFlags = int16(0x1d)   // UP + UV + BE + BS
	const eligibleFlags = int16(0x0d) // UP + UV + BE
	for _, tc := range []struct {
		name             string
		stored           *int16
		invalidSignature bool
		race             bool
		wantOK           bool
	}{
		{name: "new synced credential", stored: flagPointer(syncedFlags), wantOK: true},
		{name: "legacy synced credential", wantOK: true},
		{name: "backup state changes", stored: flagPointer(eligibleFlags), wantOK: true},
		{name: "invalid signature cannot initialize legacy flags", invalidSignature: true},
		{name: "known eligibility cannot change", stored: flagPointer(deviceFlags)},
		{name: "concurrent initialization cannot change eligibility", race: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, q, uid := newFakeDBStore(t)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			x, y := make([]byte, 32), make([]byte, 32)
			key.X.FillBytes(x)
			key.Y.FillBytes(y)
			publicKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
			if err != nil {
				t.Fatal(err)
			}
			cred := gowebauthn.Credential{ID: []byte("synced-credential"), PublicKey: publicKey, Flags: gowebauthn.NewCredentialFlags(0x1d)}
			if err := store.AddCredential(context.Background(), uidBytes(uid), cred); err != nil {
				t.Fatal(err)
			}
			if q.credentials[0].WebauthnFlags == nil || *q.credentials[0].WebauthnFlags != syncedFlags {
				t.Fatal("registration did not persist authenticator flags")
			}
			q.credentials[0].WebauthnFlags = tc.stored
			if tc.race {
				q.beforeCounterUpdate = func() { q.credentials[0].WebauthnFlags = flagPointer(deviceFlags) }
			}
			svc, err := NewService(testConfig(), store, NewInMemorySessionStore())
			if err != nil {
				t.Fatal(err)
			}
			options, session, err := svc.BeginDiscoverableLogin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			body := signedSyncedAssertion(t, key, options.Response.Challenge, uidBytes(uid), cred.ID, byte(syncedFlags), tc.invalidSignature)
			userID, _, _, err := svc.FinishDiscoverableLogin(context.Background(), session, strings.NewReader(body))
			if (err == nil) != tc.wantOK {
				t.Fatalf("login error = %v, want success %v", err, tc.wantOK)
			}
			if tc.wantOK {
				if userID != uuid.UUID(uid.Bytes).String() {
					t.Fatal("login changed the account identity")
				}
				loaded, err := store.GetUser(context.Background(), uidBytes(uid))
				if err != nil {
					t.Fatal(err)
				}
				flags := loaded.WebAuthnCredentials()[0].Flags
				if !flags.BackupEligible || !flags.BackupState {
					t.Fatalf("signed flags were lost: %+v", flags)
				}
			} else if tc.invalidSignature {
				if q.credentials[0].WebauthnFlags != nil || q.counterUpdateCalls != 0 {
					t.Fatal("invalid signature persisted credential metadata")
				}
			} else if q.credentials[0].WebauthnFlags == nil || *q.credentials[0].WebauthnFlags != deviceFlags {
				t.Fatal("assertion overwrote established backup eligibility")
			}
		})
	}
}

func flagPointer(flags int16) *int16 { return &flags }

func signedSyncedAssertion(t *testing.T, key *ecdsa.PrivateKey, challenge, handle, id []byte, flags byte, invalid bool) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": encode(challenge), "origin": "http://localhost:8081"})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("localhost"))
	authData := append(append([]byte{}, rpHash[:]...), flags, 0, 0, 0, 0)
	clientHash := sha256.Sum256(client)
	message := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, message[:])
	if err != nil {
		t.Fatal(err)
	}
	if invalid {
		signature[len(signature)-1] ^= 1
	}
	body, err := json.Marshal(map[string]any{
		"id": encode(id), "rawId": encode(id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": encode(client), "authenticatorData": encode(authData), "signature": encode(signature), "userHandle": encode(handle)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
