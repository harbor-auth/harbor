// Package signup verifies an account identifier before new passkey enrollment.
// Verification never grants access to an existing account.
package signup

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/region"
)

const TTL = 10 * time.Minute

var ErrInvalidCode = errors.New("signup: invalid or expired code")
var ErrInvalidEmail = errors.New("signup: invalid email")
var ErrRateLimited = errors.New("signup: rate limited")

// Challenges must atomically count failures and consume a successful code.
// Payload contains a purpose-wrapped email, never plaintext.
type Challenges interface {
	Save(ctx context.Context, key, proof string, payload []byte) error
	Consume(ctx context.Context, key, proof string) ([]byte, error)
	AllowDestination(ctx context.Context, key string) (bool, error)
}
type Mailer interface {
	SendCode(context.Context, string, string) error
}
type Service struct {
	challenges Challenges
	mailer     Mailer
	keys       crypto.KeyProvider
	lookupKey  []byte
	enroller   *identity.Enroller
	persist    identity.IdentifiedUserPersister
}

func New(ch Challenges, mailer Mailer, keys crypto.KeyProvider, lookupKey []byte, enroller *identity.Enroller, persist identity.IdentifiedUserPersister) (*Service, error) {
	if ch == nil || mailer == nil || keys == nil || len(lookupKey) != 32 || enroller == nil || persist == nil {
		return nil, errors.New("signup: verification dependencies and a 32-byte lookup key are required")
	}
	return &Service{ch, mailer, keys, append([]byte(nil), lookupKey...), enroller, persist}, nil
}

// NormalizeEmail deliberately rejects display names, comments, quoted local
// parts and non-ASCII addresses. Provider-specific aliases are not collapsed.
func NormalizeEmail(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > 254 || len(value) == 0 {
		return "", ErrInvalidEmail
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return "", ErrInvalidEmail
		}
	}
	a, err := mail.ParseAddress(value)
	if err != nil || a.Name != "" || a.Address != value || strings.ContainsAny(value, "\"()<>,;:\\[]") {
		return "", ErrInvalidEmail
	}
	parts := strings.Split(value, "@")
	if len(parts) != 2 || len(parts[0]) > 64 || !strings.Contains(parts[1], ".") {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(value), nil
}
func (s *Service) digest(purpose, value string) []byte {
	h := hmac.New(sha256.New, s.lookupKey)
	h.Write([]byte("harbor-signup-v1:" + purpose + "\x00" + value))
	return h.Sum(nil)
}
func (s *Service) hash(purpose, value string) string {
	return hex.EncodeToString(s.digest(purpose, value))
}
func (s *Service) Lookup(reg, email string) []byte {
	return s.digest("identifier:"+reg+":email", email)
}

type verifiedRequest struct {
	Email    string
	Region   string
	ReturnTo string
}
type sealedRequest struct {
	Region string
	Value  []byte
}

// Start issues a browser secret and emails a code; no account is created yet.
func (s *Service) Start(ctx context.Context, email, rawRegion, returnTo string) (string, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	reg, err := region.Parse(rawRegion)
	if err != nil {
		return "", err
	}
	allowed, err := s.challenges.AllowDestination(ctx, s.hash("destination:"+string(reg), email))
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrRateLimited
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return "", err
	}
	key := hex.EncodeToString(secret)
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%08d", n.Int64())
	value, err := json.Marshal(verifiedRequest{email, string(reg), returnTo})
	if err != nil {
		return "", err
	}
	sealed, err := s.keys.WrapKey(ctx, string(reg), "signup-email:"+key, value)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(sealedRequest{string(reg), sealed})
	if err != nil {
		return "", err
	}
	if err = s.challenges.Save(ctx, key, s.hash("code:"+key, code), payload); err != nil {
		return "", err
	}
	// Do not return/log SMTP errors: some servers include recipient addresses.
	if err = s.mailer.SendCode(ctx, email, code); err != nil {
		return "", errors.New("signup: verification email delivery failed")
	}
	return key, nil
}

func (s *Service) Finish(ctx context.Context, key, code string) (identity.EnrollResult, string, error) {
	if len(key) != 64 {
		return identity.EnrollResult{}, "", ErrInvalidCode
	}
	if _, err := hex.DecodeString(key); err != nil {
		return identity.EnrollResult{}, "", ErrInvalidCode
	}
	// Even malformed codes count against the attempt budget.
	payload, err := s.challenges.Consume(ctx, key, s.hash("code:"+key, code))
	if err != nil {
		return identity.EnrollResult{}, "", err
	}
	var sealed sealedRequest
	if err = json.Unmarshal(payload, &sealed); err != nil {
		return identity.EnrollResult{}, "", err
	}
	value, err := s.keys.UnwrapKey(ctx, sealed.Region, "signup-email:"+key, sealed.Value)
	if err != nil {
		return identity.EnrollResult{}, "", err
	}
	var req verifiedRequest
	if err = json.Unmarshal(value, &req); err != nil {
		return identity.EnrollResult{}, "", err
	}
	result, err := s.enroller.EnrollIdentified(ctx, req.Region, "email", req.Email, s.Lookup(req.Region, req.Email), s.persist)
	return result, req.ReturnTo, err
}
