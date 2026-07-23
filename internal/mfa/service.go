package mfa

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// TOTP algorithm parameters (RFC 6238). These are frozen: changing Period,
// Digits, or Algorithm would invalidate every already-enrolled authenticator,
// so they are constants rather than config.
const (
	// totpPeriod is the code rotation interval in seconds (RFC 6238 default).
	totpPeriod = 30
	// totpDigits is the number of digits in a generated code.
	totpDigits = otp.DigitsSix
	// totpAlgorithm is the HMAC hash (RFC 6238 default; the algorithm every
	// mainstream authenticator app assumes when the otpauth URI omits it).
	totpAlgorithm = otp.AlgorithmSHA1
	// totpSecretSize is the generated shared-secret length in bytes (160 bits,
	// the RFC 4226 recommended minimum for HMAC-SHA1).
	totpSecretSize = 20
	// totpSkew is the number of periods of clock drift tolerated on either side
	// of the current step (±1 → a code is accepted for ~90s total). This is the
	// ±1 time window the step-up gate validates against.
	totpSkew = 1
)

// Recovery-code parameters. Eight single-use codes of eight characters each,
// drawn from an unambiguous alphabet (no 0/O/1/I/L) so users can transcribe
// them from paper without confusion (docs/DESIGN.md §7.3).
const (
	defaultRecoveryCodeCount = 8
	recoveryCodeLen          = 8
	recoveryCodeAlphabet     = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// defaultIssuer is the otpauth issuer label shown in the authenticator app when
// the caller does not override it.
const defaultIssuer = "Harbor"

// KeyResolver resolves a user's data-encryption key (DEK) and home region so
// the service can envelope-encrypt/decrypt the TOTP secret. It is the seam
// between this pure verification core and the user/key storage: the production
// implementation reads users.dek_wrapped + users.region and unwraps the DEK via
// crypto.KeyProvider, while tests inject a fixed key (docs/DESIGN.md §1.7).
type KeyResolver interface {
	// ResolveDEK returns the user's DEK and home region, or an error if the user
	// is unknown or the DEK cannot be unwrapped.
	ResolveDEK(ctx context.Context, userID string) (dek crypto.DEK, region string, err error)
}

// ServiceConfig wires the Service's collaborators. Store, Cipher, and Keys are
// required; Issuer, Now, and RecoveryCodeCount default to sensible values (the
// last two are seams for deterministic tests).
type ServiceConfig struct {
	// Store persists MFA factors (required).
	Store Store
	// Cipher performs AES-256-GCM envelope encryption of the TOTP secret
	// (required).
	Cipher *crypto.Cipher
	// Keys resolves each user's DEK + region (required).
	Keys KeyResolver
	// Issuer is the otpauth issuer label (defaults to "Harbor").
	Issuer string
	// Now supplies the current time for TOTP validation (defaults to time.Now).
	Now func() time.Time
	// RecoveryCodeCount is how many recovery codes to mint at enrollment
	// (defaults to 8).
	RecoveryCodeCount int
}

// Service is the concrete TOTPService. It owns no per-request state and
// performs no HTTP; persistence and DEK resolution are delegated to its
// collaborators so the verification logic stays unit-testable.
//
// TOTP factor lifecycle in mfa_factors: a TOTP factor's `used` column encodes
// its activation state, mirroring the one-way false→true transition the store's
// MarkUsed performs for recovery codes:
//   - used=false → PENDING (enrolled via Enroll, awaiting confirmation)
//   - used=true  → ACTIVE  (confirmed via Activate; eligible for step-up)
//
// Verify and HasMFA operate only on the ACTIVE (used=true) factor; a mis-scanned
// QR leaves a harmless PENDING factor that the next Enroll clears.
type Service struct {
	store             Store
	cipher            *crypto.Cipher
	keys              KeyResolver
	issuer            string
	now               func() time.Time
	recoveryCodeCount int
}

// NewService validates the required collaborators and returns a ready Service,
// applying defaults for the optional config fields.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("mfa: ServiceConfig.Store is required")
	}
	if cfg.Cipher == nil {
		return nil, errors.New("mfa: ServiceConfig.Cipher is required")
	}
	if cfg.Keys == nil {
		return nil, errors.New("mfa: ServiceConfig.Keys is required")
	}
	svc := &Service{
		store:             cfg.Store,
		cipher:            cfg.Cipher,
		keys:              cfg.Keys,
		issuer:            cfg.Issuer,
		now:               cfg.Now,
		recoveryCodeCount: cfg.RecoveryCodeCount,
	}
	if svc.issuer == "" {
		svc.issuer = defaultIssuer
	}
	if svc.now == nil {
		svc.now = time.Now
	}
	if svc.recoveryCodeCount == 0 {
		svc.recoveryCodeCount = defaultRecoveryCodeCount
	}
	return svc, nil
}

// Enroll begins TOTP enrollment: it generates a fresh secret (envelope-
// encrypted under the user's DEK) plus a set of single-use recovery codes,
// persists them, and returns the plaintext material for the user to record. The
// TOTP factor is PENDING (used=false) until confirmed via Activate.
//
// If the user already has an ACTIVE TOTP factor, Enroll fails with
// ErrAlreadyEnrolled — re-enrollment requires Disable first, so a lost-device
// attacker cannot silently swap in a new secret. Any leftover PENDING factors
// (and their recovery codes) from an abandoned prior attempt are cleared first,
// giving each enrollment a clean slate.
func (s *Service) Enroll(ctx context.Context, userID string) (*EnrollResult, error) {
	factors, err := s.store.ListFactors(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa: list factors: %w", err)
	}
	for _, f := range factors {
		if f.Type == FactorTypeTOTP && f.Used {
			return nil, ErrAlreadyEnrolled
		}
	}
	// No active factor: any existing rows are stale (an abandoned pending
	// enrollment). Clear them so recovery codes and pending secrets never
	// accumulate across retries.
	for _, f := range factors {
		if err := s.store.DeleteFactor(ctx, f.ID); err != nil {
			return nil, fmt.Errorf("mfa: clear stale factor: %w", err)
		}
	}

	dek, region, err := s.keys.ResolveDEK(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa: resolve DEK: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: userID,
		Period:      totpPeriod,
		SecretSize:  totpSecretSize,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: generate TOTP secret: %w", err)
	}
	secret := key.Secret()

	encSecret, err := s.encryptSecret(dek, region, secret)
	if err != nil {
		return nil, err
	}

	factor, err := s.store.CreateFactor(ctx, CreateFactorParams{
		UserID: userID,
		Region: region,
		Type:   FactorTypeTOTP,
		Secret: encSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: persist TOTP factor: %w", err)
	}

	codes, err := s.createRecoveryCodes(ctx, userID, region)
	if err != nil {
		return nil, err
	}

	return &EnrollResult{
		FactorID:        factor.ID,
		Secret:          secret,
		ProvisioningURI: key.URL(),
		RecoveryCodes:   codes,
	}, nil
}

// Activate confirms a pending TOTP enrollment: it validates code against the
// freshly-enrolled secret and, on success, promotes the factor to ACTIVE
// (used=true) so it becomes eligible for step-up challenges.
//
// Returns ErrNotEnrolled if there is no pending factor, or ErrInvalidCode if the
// code does not match.
func (s *Service) Activate(ctx context.Context, userID, code string) error {
	factor, found, err := s.findTOTPFactor(ctx, userID, false)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotEnrolled
	}
	if err := s.validateAgainstFactor(ctx, userID, factor, code); err != nil {
		return err
	}
	if err := s.store.MarkUsed(ctx, factor.ID); err != nil {
		return fmt.Errorf("mfa: activate factor: %w", err)
	}
	return nil
}

// Verify checks a TOTP code against the user's ACTIVE TOTP factor for a step-up
// challenge. It is read-only — a TOTP code is reusable within its ±1 window by
// design.
//
// Returns ErrNotEnrolled if the user has no active factor, or ErrInvalidCode on
// mismatch.
func (s *Service) Verify(ctx context.Context, userID, code string) error {
	factor, found, err := s.findTOTPFactor(ctx, userID, true)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotEnrolled
	}
	return s.validateAgainstFactor(ctx, userID, factor, code)
}

// VerifyRecoveryCode checks a submitted recovery code against the user's stored
// bcrypt hashes and, on the first match, BURNS it (marks the factor used) so it
// can never be replayed. This is the fail-closed single-use operation for
// lost-authenticator recovery.
//
// Returns ErrInvalidCode if no unused code matches. Note: this implementation
// does not early-exit on a match (avoiding timing differences within a single
// call), but the total number of bcrypt comparisons correlates with unused code
// count. Full constant-time protection is deferred (acceptable for this use case
// where recovery codes are high-entropy and rarely used).
func (s *Service) VerifyRecoveryCode(ctx context.Context, userID, code string) error {
	factors, err := s.store.ListFactors(ctx, userID)
	if err != nil {
		return fmt.Errorf("mfa: list factors: %w", err)
	}
	matchedID := ""
	for _, f := range factors {
		if f.Type != FactorTypeRecovery || f.Used {
			continue
		}
		if bcrypt.CompareHashAndPassword(f.CodeHash, []byte(code)) == nil {
			matchedID = f.ID
			// Do not break: keep comparing so a successful match is not
			// distinguishable from a failure by response time.
		}
	}
	if matchedID == "" {
		return ErrInvalidCode
	}
	if err := s.store.MarkUsed(ctx, matchedID); err != nil {
		return fmt.Errorf("mfa: burn recovery code: %w", err)
	}
	return nil
}

// ListFactors returns the user's enrolled MFA factors as metadata only (never
// secrets or hashes). Safe to surface to a management UI.
func (s *Service) ListFactors(ctx context.Context, userID string) ([]Factor, error) {
	stored, err := s.store.ListFactors(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa: list factors: %w", err)
	}
	out := make([]Factor, len(stored))
	for i, f := range stored {
		out[i] = f.Metadata()
	}
	return out, nil
}

// Disable removes ALL of the user's MFA factors (the TOTP secret and every
// recovery code). After this the step-up gate treats the user as MFA-disabled.
func (s *Service) Disable(ctx context.Context, userID string) error {
	factors, err := s.store.ListFactors(ctx, userID)
	if err != nil {
		return fmt.Errorf("mfa: list factors: %w", err)
	}
	for _, f := range factors {
		if err := s.store.DeleteFactor(ctx, f.ID); err != nil {
			return fmt.Errorf("mfa: delete factor: %w", err)
		}
	}
	return nil
}

// HasMFA reports whether the user has an ACTIVE TOTP factor enrolled — the
// predicate the BFF step-up gate consults before a sensitive action.
func (s *Service) HasMFA(ctx context.Context, userID string) (bool, error) {
	_, found, err := s.findTOTPFactor(ctx, userID, true)
	if err != nil {
		return false, err
	}
	return found, nil
}

// findTOTPFactor returns the user's TOTP factor in the requested activation
// state (activated=true → ACTIVE/used=true; activated=false → PENDING).
func (s *Service) findTOTPFactor(ctx context.Context, userID string, activated bool) (StoredFactor, bool, error) {
	factors, err := s.store.ListFactors(ctx, userID)
	if err != nil {
		return StoredFactor{}, false, fmt.Errorf("mfa: list factors: %w", err)
	}
	for _, f := range factors {
		if f.Type == FactorTypeTOTP && f.Used == activated {
			return f, true, nil
		}
	}
	return StoredFactor{}, false, nil
}

// validateAgainstFactor decrypts factor's TOTP secret and checks code against
// it within the ±1 time window. Returns ErrInvalidCode on any mismatch or
// malformed code; a decryption failure surfaces as a wrapped error (a genuine
// key/storage fault, not a wrong code).
func (s *Service) validateAgainstFactor(ctx context.Context, userID string, factor StoredFactor, code string) error {
	dek, region, err := s.keys.ResolveDEK(ctx, userID)
	if err != nil {
		return fmt.Errorf("mfa: resolve DEK: %w", err)
	}
	secret, err := s.decryptSecret(dek, region, factor.Secret)
	if err != nil {
		return err
	}
	valid, err := totp.ValidateCustom(code, secret, s.now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    totpDigits,
		Algorithm: totpAlgorithm,
	})
	if err != nil || !valid {
		return ErrInvalidCode
	}
	return nil
}

// createRecoveryCodes generates, hashes, and persists the recovery-code
// factors, returning the plaintext codes for one-time display.
func (s *Service) createRecoveryCodes(ctx context.Context, userID, region string) ([]string, error) {
	codes := make([]string, 0, s.recoveryCodeCount)
	for i := 0; i < s.recoveryCodeCount; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("mfa: generate recovery code: %w", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("mfa: hash recovery code: %w", err)
		}
		if _, err := s.store.CreateFactor(ctx, CreateFactorParams{
			UserID:   userID,
			Region:   region,
			Type:     FactorTypeRecovery,
			CodeHash: hash,
		}); err != nil {
			return nil, fmt.Errorf("mfa: persist recovery code: %w", err)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// encryptSecret envelope-encrypts the base32 TOTP secret under the user's DEK.
// The region is bound as GCM AAD, so a secret encrypted in one region cannot be
// decrypted in another (region isolation, mirroring internal/relay).
func (s *Service) encryptSecret(dek crypto.DEK, region, secret string) ([]byte, error) {
	enc, err := s.cipher.Encrypt(dek, []byte(secret), totpSecretAAD(region))
	if err != nil {
		return nil, fmt.Errorf("mfa: encrypt secret: %w", err)
	}
	return enc, nil
}

// decryptSecret opens the envelope-encrypted TOTP secret. The region must match
// the one used at encryption time or GCM authentication fails.
func (s *Service) decryptSecret(dek crypto.DEK, region string, enc []byte) (string, error) {
	pt, err := s.cipher.Decrypt(dek, enc, totpSecretAAD(region))
	if err != nil {
		return "", fmt.Errorf("mfa: decrypt secret: %w", err)
	}
	return string(pt), nil
}

// totpSecretAAD returns the region-bound additional authenticated data for the
// TOTP secret envelope. Versioned so the binding can be rotated in lockstep if
// the scheme ever changes.
func totpSecretAAD(region string) []byte {
	return []byte("mfa-totp-secret-v1:" + region)
}

// generateRecoveryCode returns a single random recovery code drawn uniformly
// from recoveryCodeAlphabet. crypto/rand + rejection-free big.Int selection
// avoids the modulo bias a naive `rand % len` would introduce.
func generateRecoveryCode() (string, error) {
	b := make([]byte, recoveryCodeLen)
	max := big.NewInt(int64(len(recoveryCodeAlphabet)))
	for i := range b {
		n, err := cryptorand.Int(cryptorand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = recoveryCodeAlphabet[n.Int64()]
	}
	return string(b), nil
}

// Compile-time assertion: Service implements TOTPService.
var _ TOTPService = (*Service)(nil)
