package mfa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/harbor-auth/harbor/internal/crypto"
)

const (
	testUserID = "11111111-1111-1111-1111-111111111111"
	testRegion = "eu"
)

// testNow is a fixed instant so TOTP generation/validation is deterministic.
var testNow = time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

// fakeKeyResolver is a test KeyResolver returning a fixed DEK + region (or a
// forced error) so the service can be exercised without the user/key store.
type fakeKeyResolver struct {
	dek    crypto.DEK
	region string
	err    error
}

func (f fakeKeyResolver) ResolveDEK(_ context.Context, _ string) (crypto.DEK, string, error) {
	if f.err != nil {
		return crypto.DEK{}, "", f.err
	}
	return f.dek, f.region, nil
}

// newTestService returns a Service backed by an in-memory store, a real cipher,
// and a fixed-DEK key resolver. now controls the service's clock; pass nil for
// the fixed testNow.
func newTestService(t *testing.T, now func() time.Time) (*Service, *InMemoryStore) {
	t.Helper()
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	if now == nil {
		now = func() time.Time { return testNow }
	}
	store := NewInMemoryStore()
	svc, err := NewService(ServiceConfig{
		Store:  store,
		Cipher: crypto.NewCipher(),
		Keys:   fakeKeyResolver{dek: dek, region: testRegion},
		Now:    now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

// codeAt generates the valid TOTP code for secret at time at, using the same
// algorithm parameters the service validates against.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    totpPeriod,
		Digits:    totpDigits,
		Algorithm: totpAlgorithm,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	return code
}

// enrollAndActivate runs a full enrollment for testUserID and returns the
// EnrollResult (secret + recovery codes).
func enrollAndActivate(t *testing.T, svc *Service) *EnrollResult {
	t.Helper()
	ctx := context.Background()
	res, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := svc.Activate(ctx, testUserID, codeAt(t, res.Secret, testNow)); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return res
}

func TestNewService_RequiredFields(t *testing.T) {
	cipher := crypto.NewCipher()
	keys := fakeKeyResolver{region: testRegion}
	store := NewInMemoryStore()

	tests := []struct {
		name string
		cfg  ServiceConfig
	}{
		{"missing store", ServiceConfig{Cipher: cipher, Keys: keys}},
		{"missing cipher", ServiceConfig{Store: store, Keys: keys}},
		{"missing keys", ServiceConfig{Store: store, Cipher: cipher}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewService(tc.cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestNewService_Defaults(t *testing.T) {
	svc, err := NewService(ServiceConfig{
		Store:  NewInMemoryStore(),
		Cipher: crypto.NewCipher(),
		Keys:   fakeKeyResolver{region: testRegion},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.issuer != defaultIssuer {
		t.Errorf("issuer = %q, want %q", svc.issuer, defaultIssuer)
	}
	if svc.recoveryCodeCount != defaultRecoveryCodeCount {
		t.Errorf("recoveryCodeCount = %d, want %d", svc.recoveryCodeCount, defaultRecoveryCodeCount)
	}
	if svc.now == nil {
		t.Error("now must default to a non-nil clock")
	}
}

func TestEnroll_Success(t *testing.T) {
	svc, store := newTestService(t, nil)
	ctx := context.Background()

	res, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.FactorID == "" {
		t.Error("expected non-empty FactorID")
	}
	if res.Secret == "" {
		t.Error("expected non-empty Secret")
	}
	if !strings.HasPrefix(res.ProvisioningURI, "otpauth://totp/") {
		t.Errorf("ProvisioningURI = %q, want otpauth://totp/ prefix", res.ProvisioningURI)
	}
	if len(res.RecoveryCodes) != defaultRecoveryCodeCount {
		t.Errorf("got %d recovery codes, want %d", len(res.RecoveryCodes), defaultRecoveryCodeCount)
	}
	for _, c := range res.RecoveryCodes {
		if len(c) != recoveryCodeLen {
			t.Errorf("recovery code %q length = %d, want %d", c, len(c), recoveryCodeLen)
		}
	}

	// One PENDING TOTP factor + N recovery factors persisted.
	factors, err := store.ListFactors(ctx, testUserID)
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	var totpCount, recoveryCount int
	for _, f := range factors {
		switch f.Type {
		case FactorTypeTOTP:
			totpCount++
			if f.Used {
				t.Error("newly-enrolled TOTP factor must be PENDING (used=false)")
			}
			if len(f.Secret) == 0 {
				t.Error("TOTP factor must carry an encrypted secret")
			}
			if string(f.Secret) == res.Secret {
				t.Error("stored secret must be encrypted, not the plaintext base32 secret")
			}
		case FactorTypeRecovery:
			recoveryCount++
			if len(f.CodeHash) == 0 {
				t.Error("recovery factor must carry a code hash")
			}
		}
	}
	if totpCount != 1 {
		t.Errorf("got %d TOTP factors, want 1", totpCount)
	}
	if recoveryCount != defaultRecoveryCodeCount {
		t.Errorf("got %d recovery factors, want %d", recoveryCount, defaultRecoveryCodeCount)
	}
}

func TestEnroll_AlreadyEnrolled(t *testing.T) {
	svc, _ := newTestService(t, nil)
	ctx := context.Background()
	enrollAndActivate(t, svc)

	if _, err := svc.Enroll(ctx, testUserID); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("err = %v, want ErrAlreadyEnrolled", err)
	}
}

func TestEnroll_ClearsStalePending(t *testing.T) {
	svc, store := newTestService(t, nil)
	ctx := context.Background()

	first, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	// Re-enroll without activating: the stale pending factor + its recovery
	// codes must be replaced, not accumulated.
	second, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if first.Secret == second.Secret {
		t.Error("re-enroll should mint a fresh secret")
	}

	factors, err := store.ListFactors(ctx, testUserID)
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	want := 1 + defaultRecoveryCodeCount
	if len(factors) != want {
		t.Errorf("got %d factors after re-enroll, want %d (no accumulation)", len(factors), want)
	}
}

func TestActivate_ValidCode(t *testing.T) {
	svc, store := newTestService(t, nil)
	ctx := context.Background()

	res, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := svc.Activate(ctx, testUserID, codeAt(t, res.Secret, testNow)); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// The TOTP factor must now be ACTIVE (used=true).
	factors, _ := store.ListFactors(ctx, testUserID)
	var activated bool
	for _, f := range factors {
		if f.Type == FactorTypeTOTP {
			activated = f.Used
		}
	}
	if !activated {
		t.Error("TOTP factor must be ACTIVE after Activate")
	}
}

func TestActivate_InvalidCode(t *testing.T) {
	svc, store := newTestService(t, nil)
	ctx := context.Background()

	res, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// A code from far in the future is well-formed but outside the ±1 window.
	bad := codeAt(t, res.Secret, testNow.Add(10*time.Minute))
	if err := svc.Activate(ctx, testUserID, bad); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("err = %v, want ErrInvalidCode", err)
	}

	// Factor must stay PENDING on a failed activation.
	factors, _ := store.ListFactors(ctx, testUserID)
	for _, f := range factors {
		if f.Type == FactorTypeTOTP && f.Used {
			t.Error("TOTP factor must remain PENDING after a failed Activate")
		}
	}
}

func TestActivate_NotEnrolled(t *testing.T) {
	svc, _ := newTestService(t, nil)
	if err := svc.Activate(context.Background(), testUserID, "123456"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

func TestVerify_ValidCode(t *testing.T) {
	svc, _ := newTestService(t, nil)
	res := enrollAndActivate(t, svc)
	if err := svc.Verify(context.Background(), testUserID, codeAt(t, res.Secret, testNow)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_InvalidCode(t *testing.T) {
	svc, _ := newTestService(t, nil)
	res := enrollAndActivate(t, svc)
	bad := codeAt(t, res.Secret, testNow.Add(10*time.Minute))
	if err := svc.Verify(context.Background(), testUserID, bad); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("err = %v, want ErrInvalidCode", err)
	}
}

func TestVerify_NotEnrolled(t *testing.T) {
	svc, _ := newTestService(t, nil)
	ctx := context.Background()
	// Enroll but do NOT activate: no ACTIVE factor exists.
	if _, err := svc.Enroll(ctx, testUserID); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := svc.Verify(ctx, testUserID, "123456"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

// TestVerify_TimeWindow proves the ±1 period skew: a code minted for the
// previous 30s window is still accepted, but one two windows back is rejected.
func TestVerify_TimeWindow(t *testing.T) {
	svc, _ := newTestService(t, nil)
	res := enrollAndActivate(t, svc)
	ctx := context.Background()

	prev := codeAt(t, res.Secret, testNow.Add(-totpPeriod*time.Second))
	if err := svc.Verify(ctx, testUserID, prev); err != nil {
		t.Errorf("code from previous window must be accepted (±1 skew): %v", err)
	}

	next := codeAt(t, res.Secret, testNow.Add(totpPeriod*time.Second))
	if err := svc.Verify(ctx, testUserID, next); err != nil {
		t.Errorf("code from next window must be accepted (±1 skew): %v", err)
	}

	tooOld := codeAt(t, res.Secret, testNow.Add(-3*totpPeriod*time.Second))
	if err := svc.Verify(ctx, testUserID, tooOld); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("code three windows back must be rejected: err = %v, want ErrInvalidCode", err)
	}
}

func TestVerifyRecoveryCode_BurnOnUse(t *testing.T) {
	svc, _ := newTestService(t, nil)
	res := enrollAndActivate(t, svc)
	ctx := context.Background()

	code := res.RecoveryCodes[0]
	if err := svc.VerifyRecoveryCode(ctx, testUserID, code); err != nil {
		t.Fatalf("first VerifyRecoveryCode: %v", err)
	}
	// Replaying the same code must fail: it was burned.
	if err := svc.VerifyRecoveryCode(ctx, testUserID, code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed code err = %v, want ErrInvalidCode", err)
	}
}

func TestVerifyRecoveryCode_DifferentCodesStillWork(t *testing.T) {
	svc, _ := newTestService(t, nil)
	res := enrollAndActivate(t, svc)
	ctx := context.Background()

	// Burning one code must not invalidate the others.
	if err := svc.VerifyRecoveryCode(ctx, testUserID, res.RecoveryCodes[0]); err != nil {
		t.Fatalf("burn code 0: %v", err)
	}
	if err := svc.VerifyRecoveryCode(ctx, testUserID, res.RecoveryCodes[1]); err != nil {
		t.Fatalf("code 1 should still be valid: %v", err)
	}
}

func TestVerifyRecoveryCode_Invalid(t *testing.T) {
	svc, _ := newTestService(t, nil)
	enrollAndActivate(t, svc)
	if err := svc.VerifyRecoveryCode(context.Background(), testUserID, "NOTACODE"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("err = %v, want ErrInvalidCode", err)
	}
}

func TestListFactors(t *testing.T) {
	svc, _ := newTestService(t, nil)
	enrollAndActivate(t, svc)

	factors, err := svc.ListFactors(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	want := 1 + defaultRecoveryCodeCount
	if len(factors) != want {
		t.Errorf("got %d factors, want %d", len(factors), want)
	}
	for _, f := range factors {
		if f.UserID != testUserID {
			t.Errorf("factor UserID = %q, want %q", f.UserID, testUserID)
		}
		if f.Region != testRegion {
			t.Errorf("factor Region = %q, want %q", f.Region, testRegion)
		}
	}
}

func TestListFactors_Empty(t *testing.T) {
	svc, _ := newTestService(t, nil)
	factors, err := svc.ListFactors(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(factors) != 0 {
		t.Errorf("got %d factors for a user with no MFA, want 0", len(factors))
	}
}

func TestDisable(t *testing.T) {
	svc, store := newTestService(t, nil)
	ctx := context.Background()
	enrollAndActivate(t, svc)

	if err := svc.Disable(ctx, testUserID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	factors, err := store.ListFactors(ctx, testUserID)
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(factors) != 0 {
		t.Errorf("got %d factors after Disable, want 0", len(factors))
	}
	// After Disable the user must read as MFA-disabled.
	has, err := svc.HasMFA(ctx, testUserID)
	if err != nil {
		t.Fatalf("HasMFA: %v", err)
	}
	if has {
		t.Error("HasMFA must be false after Disable")
	}
}

func TestHasMFA(t *testing.T) {
	svc, _ := newTestService(t, nil)
	ctx := context.Background()

	// No factors → false.
	if has, err := svc.HasMFA(ctx, testUserID); err != nil || has {
		t.Fatalf("HasMFA (none) = %v, %v; want false, nil", has, err)
	}

	// Pending (enrolled, not activated) → false.
	if _, err := svc.Enroll(ctx, testUserID); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if has, err := svc.HasMFA(ctx, testUserID); err != nil || has {
		t.Fatalf("HasMFA (pending) = %v, %v; want false, nil", has, err)
	}

	// Active → true. Re-enroll (clears the pending factor and returns a fresh
	// secret we can activate against) then confirm the code.
	enroll, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := svc.Activate(ctx, testUserID, codeAt(t, enroll.Secret, testNow)); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if has, err := svc.HasMFA(ctx, testUserID); err != nil || !has {
		t.Fatalf("HasMFA (active) = %v, %v; want true, nil", has, err)
	}
}

// TestEnrollActivateVerify_FullFlow exercises the whole happy path end to end.
func TestEnrollActivateVerify_FullFlow(t *testing.T) {
	svc, _ := newTestService(t, nil)
	ctx := context.Background()

	res, err := svc.Enroll(ctx, testUserID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := svc.Activate(ctx, testUserID, codeAt(t, res.Secret, testNow)); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := svc.Verify(ctx, testUserID, codeAt(t, res.Secret, testNow)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := svc.VerifyRecoveryCode(ctx, testUserID, res.RecoveryCodes[0]); err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
}
