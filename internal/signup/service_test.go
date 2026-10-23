package signup

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/redis/go-redis/v9"
)

type captureMail struct {
	code, email string
	err         error
}

func (m *captureMail) SendCode(_ context.Context, email, code string) error {
	m.email = email
	m.code = code
	return m.err
}

type captureAccount struct {
	user       identity.UserRecord
	identifier identity.IdentifierRecord
	count      int
	err        error
	mu         sync.Mutex
}

func (p *captureAccount) PersistUser(context.Context, identity.UserRecord) error {
	panic("unverified enrollment used")
}
func (p *captureAccount) PersistIdentifiedUser(_ context.Context, u identity.UserRecord, i identity.IdentifierRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.user = u
	p.identifier = i
	p.count++
	return nil
}
func testService(t *testing.T) (*Service, *miniredis.Miniredis, *captureMail, *captureAccount) {
	t.Helper()
	r := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: r.Addr()})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	keys, err := crypto.NewLocalKeyProvider(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	mail := &captureMail{}
	p := &captureAccount{}
	s, err := New(NewRedisChallenges(client), mail, keys, bytes.Repeat([]byte{7}, 32), identity.NewEnroller(keys, crypto.NewCipher(), p), p)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, mail, p
}
func TestNormalizeEmail(t *testing.T) {
	for _, value := range []string{"", "no-at", "Name <a@example.com>", "a@example.com\r\nBcc: b@example.com", "a@localhost", "a(comment)@example.com", "\"a\"@example.com", "a@éxample.com"} {
		if _, err := NormalizeEmail(value); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("accepted %q", value)
		}
	}
	got, err := NormalizeEmail("  ME+work@Example.COM ")
	if err != nil || got != "me+work@example.com" {
		t.Fatalf("normalize: %q %v", got, err)
	}
}
func TestVerifiedEnrollmentEncryptsIdentifierAndConsumesCode(t *testing.T) {
	s, r, mail, p := testService(t)
	ctx := context.Background()
	key, err := s.Start(ctx, "Me@Example.com", "EU", "/dashboard/next")
	if err != nil {
		t.Fatal(err)
	}
	if p.count != 0 || mail.email != "me@example.com" || len(mail.code) != 8 {
		t.Fatal("incorrect initial state")
	}
	for _, k := range r.Keys() {
		if strings.Contains(k, "me@example.com") {
			t.Fatal("plaintext destination in Redis key")
		}
	}
	for _, field := range []string{"payload", "proof"} {
		value := r.HGet(challengePrefix+key, field)
		if strings.Contains(value, mail.email) || strings.Contains(value, mail.code) {
			t.Fatal("PII or code persisted in plaintext")
		}
	}
	result, dest, err := s.Finish(ctx, key, mail.code)
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID == "" || dest != "/dashboard/next" || p.count != 1 || !p.user.RecoveryRequired {
		t.Fatal("bad account creation")
	}
	dek, err := s.keys.UnwrapDEK(ctx, "EU", p.user.DekWrapped)
	if err != nil {
		t.Fatal(err)
	}
	value, err := crypto.NewCipher().Decrypt(dek, p.identifier.EncryptedValue, identity.IdentifierAAD(result.UserID, "email"))
	if err != nil || string(value) != mail.email {
		t.Fatalf("identifier decrypt: %s %v", value, err)
	}
	if _, err = crypto.NewCipher().Decrypt(dek, p.identifier.EncryptedValue, identity.IdentifierAAD("other", "email")); err == nil {
		t.Fatal("identifier ciphertext not bound to account")
	}
	if bytes.Equal(s.Lookup("EU", mail.email), s.Lookup("US", mail.email)) {
		t.Fatal("cross-region correlatable lookup")
	}
	if _, _, err = s.Finish(ctx, key, mail.code); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("replayed code accepted")
	}
}
func TestVerificationExpiryAttemptsAndBrowserBinding(t *testing.T) {
	for _, scenario := range []string{"expiry", "attempts", "browser"} {
		t.Run(scenario, func(t *testing.T) {
			s, r, mail, p := testService(t)
			ctx := context.Background()
			key, err := s.Start(ctx, "a@example.com", "EU", "")
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "expiry":
				r.FastForward(TTL)
			case "attempts":
				for range 5 {
					if _, _, err = s.Finish(ctx, key, "bad"); !errors.Is(err, ErrInvalidCode) {
						t.Fatal("bad code accepted")
					}
				}
			case "browser":
				key = strings.Repeat("b", 64)
			}
			if _, _, err = s.Finish(ctx, key, mail.code); !errors.Is(err, ErrInvalidCode) || p.count != 0 {
				t.Fatalf("%s bypass: %v", scenario, err)
			}
		})
	}
}
func TestConcurrentCodeConsumption(t *testing.T) {
	s, _, mail, p := testService(t)
	ctx := context.Background()
	key, err := s.Start(ctx, "a@example.com", "EU", "")
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Finish(ctx, key, mail.code); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrInvalidCode) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || p.count != 1 {
		t.Fatalf("created %d accounts", p.count)
	}
}
func TestDestinationLimitAndDeliveryFailure(t *testing.T) {
	s, r, mail, p := testService(t)
	ctx := context.Background()
	for range 5 {
		if _, err := s.Start(ctx, "a@example.com", "EU", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Start(ctx, "A@example.com", "EU", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatal("destination limit bypass")
	}
	r.FastForward(2 * TTL * 6)
	mail.err = errors.New("smtp failed a@example.com")
	if _, err := s.Start(ctx, "a@example.com", "EU", ""); err == nil || strings.Contains(err.Error(), "a@example.com") {
		t.Fatal("delivery failure leaked or succeeded")
	}
	if p.count != 0 {
		t.Fatal("mail request created account")
	}
}
func TestDuplicateCannotMintExistingAccountAuthority(t *testing.T) {
	s, _, mail, p := testService(t)
	p.err = identity.ErrIdentifierExists
	key, err := s.Start(context.Background(), "a@example.com", "EU", "")
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := s.Finish(context.Background(), key, mail.code)
	if !errors.Is(err, identity.ErrIdentifierExists) || result.UserID != "" {
		t.Fatal("duplicate gained account authority")
	}
}
