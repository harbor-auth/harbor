package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// forgeAttestationBody builds a WebAuthn "none"-format registration response
// for a freshly generated ES256 credential, ready to feed to
// Handler.FinishRegistration. It lets handler-level tests exercise the real
// go-webauthn verification path (challenge match, RP ID hash, signature) end
// to end without a browser or authenticator — mirroring the forging logic in
// e2e/enrollment_test.go's makeAttestation, adapted to run in-process against
// a challenge obtained directly from BeginRegistration.
func forgeAttestationBody(rpID, origin, challengeB64 string) (*strings.Reader, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	coseKey := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	}
	cosePub, err := cbor.Marshal(coseKey)
	if err != nil {
		return nil, err
	}

	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}

	// authData = rpIdHash(32) | flags(1) | signCount(4) | attestedCredentialData.
	rpHash := sha256.Sum256([]byte(rpID))
	var authData []byte
	authData = append(authData, rpHash[:]...)
	const flagUP, flagUV, flagAT = 0x01, 0x04, 0x40
	authData = append(authData, byte(flagUP|flagUV|flagAT))
	authData = append(authData, make([]byte, 4)...) // signCount = 0

	// attestedCredentialData = aaguid(16) | credIdLen(2) | credId | coseKey.
	authData = append(authData, make([]byte, 16)...) // all-zero AAGUID
	credLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credLen, uint16(len(credID)))
	authData = append(authData, credLen...)
	authData = append(authData, credID...)
	authData = append(authData, cosePub...)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, err
	}

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": challengeB64,
		"origin":    origin,
	})
	if err != nil {
		return nil, err
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	resp := map[string]any{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		},
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return strings.NewReader(string(out)), nil
}
