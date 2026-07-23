package clients

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// signingKeyPurpose is the KeyProvider domain-separation purpose string for
// wrapping/unwrapping signing private keys. It derives a KEK cryptographically
// independent from the user-DEK path ("dek"), even though both share the same
// master secret (RFC 5869 §3.2). NEVER reuse this purpose for anything else.
const signingKeyPurpose = "signing-key"

// SigningKeyLoader reconstructs in-memory signers from the encrypted signing_keys
// table at process startup (docs/DESIGN.md §7.3). It is the bridge between the
// persistent store and the crypto.MultiKeyProvider used by the JWT issuer and
// the JWKS endpoint.
type SigningKeyLoader struct {
	keyStore SigningKeyStore
	kp       crypto.KeyProvider
	region   string
}

// NewSigningKeyLoader constructs a SigningKeyLoader. region stamps newly seeded
// keys and selects the KEK used to unwrap existing keys.
func NewSigningKeyLoader(keyStore SigningKeyStore, kp crypto.KeyProvider, region string) *SigningKeyLoader {
	return &SigningKeyLoader{keyStore: keyStore, kp: kp, region: region}
}

// Load reads all live signing keys from the DB, unwraps their private keys, and
// returns a MultiKeyProvider ready to sign tokens and publish JWKS. It returns
// an error if no live keys exist (use SeedAndLoad to auto-seed the first key).
func (l *SigningKeyLoader) Load(ctx context.Context) (*crypto.MultiKeyProvider, error) {
	liveKeys, err := l.keyStore.ListLive(ctx)
	if err != nil {
		return nil, fmt.Errorf("signingkeyloader: list live keys: %w", err)
	}
	if len(liveKeys) == 0 {
		return nil, fmt.Errorf("signingkeyloader: no live signing keys in DB")
	}
	return l.buildProvider(ctx, liveKeys)
}

// SeedAndLoad loads live signing keys from the DB. If the table is empty, it
// generates a fresh key, seals its private key under the regional KEK, persists
// it as the active signing key, then loads it. This makes a cold-start
// deployment self-bootstrapping: the first boot mints the first key.
func (l *SigningKeyLoader) SeedAndLoad(ctx context.Context) (*crypto.MultiKeyProvider, error) {
	liveKeys, err := l.keyStore.ListLive(ctx)
	if err != nil {
		return nil, fmt.Errorf("signingkeyloader: list live keys: %w", err)
	}
	if len(liveKeys) == 0 {
		if err := l.seedFirstKey(ctx); err != nil {
			return nil, fmt.Errorf("signingkeyloader: seed first key: %w", err)
		}
		liveKeys, err = l.keyStore.ListLive(ctx)
		if err != nil {
			return nil, fmt.Errorf("signingkeyloader: list live keys after seed: %w", err)
		}
	}
	return l.buildProvider(ctx, liveKeys)
}

// seedFirstKey generates a new signing key, seals its private key, persists it
// in pending state, then immediately promotes it to active. Used only when the
// signing_keys table is empty.
func (l *SigningKeyLoader) seedFirstKey(ctx context.Context) error {
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	wrapped, err := l.wrapSigner(ctx, signer)
	if err != nil {
		return err
	}
	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		return fmt.Errorf("parse public key from JWK: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	created, err := l.keyStore.Create(ctx, NewSigningKey{
		ID:                uuid.NewString(),
		Kid:               signer.KeyID(),
		PublicKeyBytes:    pubDER,
		PrivateKeyWrapped: wrapped,
		Region:            l.region,
	})
	if err != nil {
		return fmt.Errorf("persist signing key: %w", err)
	}
	now := time.Now()
	if _, err := l.keyStore.SetState(ctx, created.ID, string(crypto.KeyStateActive), &now, nil); err != nil {
		return fmt.Errorf("promote signing key: %w", err)
	}
	return nil
}

// wrapSigner seals signer's PKCS#8 DER private key under the regional KEK using
// the signing-key purpose. Only software signers (LocalSigner) can be wrapped;
// HSM signers keep their key inside the HSM and are handled elsewhere.
func (l *SigningKeyLoader) wrapSigner(ctx context.Context, signer crypto.Signer) ([]byte, error) {
	exporter, ok := signer.(crypto.PrivateKeyExporter)
	if !ok {
		return nil, fmt.Errorf("signingkeyloader: signer %T does not export a private key", signer)
	}
	privDER, err := exporter.PrivateKeyDER()
	if err != nil {
		return nil, fmt.Errorf("signingkeyloader: marshal private key: %w", err)
	}
	wrapped, err := l.kp.WrapKey(ctx, l.region, signingKeyPurpose, privDER)
	if err != nil {
		return nil, fmt.Errorf("signingkeyloader: wrap private key: %w", err)
	}
	return wrapped, nil
}

// buildProvider reconstructs signers from live DB records and assembles a
// MultiKeyProvider with the active key signing and pending keys published.
func (l *SigningKeyLoader) buildProvider(ctx context.Context, keys []SigningKey) (*crypto.MultiKeyProvider, error) {
	var active crypto.Signer
	var pending []crypto.Signer

	for _, key := range keys {
		signer, err := l.reconstructSigner(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("signingkeyloader: reconstruct signer for kid %q: %w", key.Kid, err)
		}
		if key.State == string(crypto.KeyStateActive) {
			active = signer
			continue
		}
		pending = append(pending, signer)
	}

	if active == nil {
		return nil, fmt.Errorf("signingkeyloader: no active signing key among %d live keys", len(keys))
	}
	return crypto.NewMultiKeyProvider(active, pending...)
}

// reconstructSigner unwraps a stored key's private bytes and rebuilds a signer.
func (l *SigningKeyLoader) reconstructSigner(ctx context.Context, key SigningKey) (crypto.Signer, error) {
	privDER, err := l.kp.UnwrapKey(ctx, key.Region, signingKeyPurpose, key.PrivateKeyWrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap private key: %w", err)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	ecKey, ok := privAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", privAny)
	}
	return crypto.NewSignerFromKey(ecKey), nil
}

// NewPrivateKeyWrapper returns a callback for crypto.KeyRotator.
// WithPrivateKeyWrapper that seals a generated signer's private key under the
// regional KEK using the signing-key purpose (RFC 5869 §3.2 domain separation).
// The wrapped bytes are persisted by DBRotationStore so the key survives a
// restart.
func NewPrivateKeyWrapper(kp crypto.KeyProvider, region string) func(crypto.Signer) ([]byte, error) {
	return func(signer crypto.Signer) ([]byte, error) {
		exporter, ok := signer.(crypto.PrivateKeyExporter)
		if !ok {
			return nil, fmt.Errorf("privatekeywrapper: signer %T does not export a private key", signer)
		}
		privDER, err := exporter.PrivateKeyDER()
		if err != nil {
			return nil, fmt.Errorf("privatekeywrapper: marshal private key: %w", err)
		}
		// The generator callback has no context parameter; the wrap is a local
		// KEK operation (no network), so context.Background is acceptable here.
		wrapped, err := kp.WrapKey(context.Background(), region, signingKeyPurpose, privDER)
		if err != nil {
			return nil, fmt.Errorf("privatekeywrapper: wrap private key: %w", err)
		}
		return wrapped, nil
	}
}
