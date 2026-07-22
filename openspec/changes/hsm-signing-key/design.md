---
change: hsm-signing-key
kind: design
status: draft
created: 2026-07-22
---

# Design: HSM / KMS-backed signing key

## Architecture overview

```
                    ┌─────────────────────────────────────────────────────┐
                    │  cmd/harbor-hot/main.go                             │
                    │                                                     │
                    │  buildSigner(ctx, logger, pool, kmsClient)          │
                    │    │                                                │
                    │    ├─ KMS_KEY_ARN unset? → NewLocalSigner() [DEV]   │
                    │    │                                                │
                    │    └─ KMS_KEY_ARN set:                             │
                    │         DBSigningKeyStore.GetActive()               │
                    │           ├─ ErrSigningKeyNotFound?                 │
                    │           │    └─ first-run: generate + wrap + store │
                    │           └─ row found:                             │
                    │                KMS.Decrypt(row.PrivateKeyWrapped)   │
                    │                NewKMSBackedSigner(priv, kid)        │
                    └─────────────────────────────────────────────────────┘

  ┌──────────────────────┐        ┌──────────────────────────────────────┐
  │  internal/crypto/    │        │  internal/clients/                   │
  │                      │        │                                      │
  │  KMSBackedSigner     │        │  DBSigningKeyStore (✅ already done) │
  │    Sign()            │        │    PrivateKeyWrapped: []byte         │
  │    KeyID()           │        │                                      │
  │    PublicJWK()       │        │  DBRotationStore  ← NEW              │
  │                      │        │    implements crypto.RotationStore   │
  │  kmsKeyProvider      │        │    wraps DBSigningKeyStore           │
  │    WrapDEK()  ← IMPL │        └──────────────────────────────────────┘
  │    UnwrapDEK() ← IMPL│
  │                      │
  │  kmsClient.go  ← NEW │
  │    NewKMSClient()    │
  └──────────────────────┘
```

## New types

### `internal/crypto/signer_kms.go`

```go
// KMSBackedSigner is a production Signer whose private key was decrypted
// from AWS KMS at startup. The key lives in process memory only; it is never
// logged, serialised, or written to disk after decryption.
//
// Contrast with LocalSigner (ephemeral, regenerated on restart) and hsmSigner
// (Phase 2: key never leaves KMS boundary). KMSBackedSigner is the intermediate
// step: key protected at rest by KMS, decrypted once at startup.
type KMSBackedSigner struct {
    priv *ecdsa.PrivateKey
    jwk  crypto.JWK
    kid  string
}

var _ crypto.Signer = (*KMSBackedSigner)(nil)

func NewKMSBackedSigner(priv *ecdsa.PrivateKey, kid string) *KMSBackedSigner
func (s *KMSBackedSigner) Sign(signingInput []byte) ([]byte, error)  // identical to LocalSigner
func (s *KMSBackedSigner) KeyID() string
func (s *KMSBackedSigner) PublicJWK() crypto.JWK
func (s *KMSBackedSigner) String() string  // → "kmsBackedSigner(kid=<kid>)"
```

### `internal/crypto/kms_client.go`

```go
// NewKMSClient builds an AWS KMS client. endpoint is used only for LocalStack
// in CI; in production it is empty (SDK auto-resolves from region/metadata).
func NewKMSClient(ctx context.Context, keyARN, region, endpoint string) (*kms.Client, error)

// WrapPrivateKey encrypts rawPrivKeyBytes (the PKCS#8 or raw D scalar) under
// keyARN using kms:Encrypt. Returns the ciphertext blob.
func WrapPrivateKey(ctx context.Context, client *kms.Client, keyARN string, rawPrivKey []byte) ([]byte, error)

// UnwrapPrivateKey decrypts a ciphertext blob from WrapPrivateKey.
func UnwrapPrivateKey(ctx context.Context, client *kms.Client, ciphertext []byte) ([]byte, error)
```

### `internal/clients/signingkeys_rotstore.go`

```go
// DBRotationStore adapts DBSigningKeyStore to the crypto.RotationStore interface
// that KeyRotator depends on. It bridges domain types between internal/crypto
// (which must not import internal/clients) and the DB layer.
type DBRotationStore struct {
    store     *DBSigningKeyStore
    kmsClient *kms.Client
    keyARN    string
}

var _ crypto.RotationStore = (*DBRotationStore)(nil)

// Create persists a new signing key. PrivateKeyWrapped must be pre-encrypted
// by the caller (KeyRotator's generator) before calling Create.
func (s *DBRotationStore) Create(ctx context.Context, key crypto.NewKeyMaterial) error
func (s *DBRotationStore) ActiveKid(ctx context.Context) (string, error)
func (s *DBRotationStore) Promote(ctx context.Context, kid string, promotedAt time.Time) error
func (s *DBRotationStore) Retire(ctx context.Context, kid string) error
```

## Private key format

The private key stored in `signing_keys.private_key_wrapped` is:

```
KMS.Encrypt(plaintext = ecdsa.PrivateKey.D.Bytes()  // 32-byte scalar, big-endian)
```

Why raw D scalar (not PKCS#8):
- Minimal serialisation; no ASN.1 parsing on the hot path
- D is the entire secret for P-256 (curve parameters are implicit from kid/alg)
- Reconstruction: `ecdsa.GenerateKey` → replace D, recompute X/Y from curve

Alternatively PKCS#8 DER is acceptable; the implementation should document
whichever format is chosen and add a round-trip test.

## Startup bootstrap sequence

```
main.go run():
1. ConnectDB(ctx)        → pool *pgxpool.Pool  (if DATABASE_URL set)
2. NewKMSClient(ctx)     → kmsClient *kms.Client  (if KMS_KEY_ARN set)
3. buildSigner(ctx, logger, pool, kmsClient):
   a. if pool == nil || kmsClient == nil:
        warn "falling back to LocalSigner (dev)"
        return NewLocalSigner()
   b. store = NewDBSigningKeyStore(pool)
   c. active, err = store.GetActive(ctx)
      if errors.Is(err, ErrSigningKeyNotFound):
        // First run — generate and persist
        priv = ecdsa.GenerateKey(P256)
        wrapped = WrapPrivateKey(ctx, kmsClient, KMS_KEY_ARN, priv.D.Bytes())
        pubDER = x509.MarshalPKIXPublicKey(&priv.PublicKey)
        kid = jwkThumbprint(priv)  // RFC 7638
        store.Create(ctx, NewSigningKey{Kid: kid, PublicKeyBytes: pubDER, PrivateKeyWrapped: wrapped})
        return NewKMSBackedSigner(priv, kid)
      if err != nil: return err  // fatal
   d. // Key exists in DB
      rawD = UnwrapPrivateKey(ctx, kmsClient, active.PrivateKeyWrapped)
      priv = reconstructFromD(rawD)
      return NewKMSBackedSigner(priv, active.Kid)
4. Wire signer into OIDC service (replaces NewPlaceholderIssuer)
5. Wire KeyRotator.WithGenerator(kmsKeyGenerator(kmsClient, store))
```

## KMS key generator (for rotation)

```go
// kmsKeyGenerator returns a Signer-factory for KeyRotator.WithGenerator.
// Each call generates a fresh P-256 key, wraps it with KMS, and returns a
// KMSBackedSigner. The wrapped bytes are stored in NewKeyMaterial.WrappedKey
// (a new field added to crypto.NewKeyMaterial) so DBRotationStore.Create can
// persist them.
func kmsKeyGenerator(client *kms.Client, keyARN string) func() (crypto.Signer, error) {
    return func() (crypto.Signer, error) {
        priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        wrapped, _ := WrapPrivateKey(context.Background(), client, keyARN, priv.D.Bytes())
        kid := jwkThumbprint(priv)
        // Store wrapped bytes in a goroutine-local; DBRotationStore.Create picks them up.
        // Implementation detail: extend crypto.NewKeyMaterial with PrivateKeyWrapped []byte.
        return NewKMSBackedSigner(priv, kid), nil
    }
}
```

## `kmsKeyProvider` implementation

`keyprovider_kms.go` currently returns `ErrKMSNotImplemented`. Replace with:

```go
type kmsKeyProvider struct {
    client *kms.Client
    keyARN string
}

func (p *kmsKeyProvider) WrapDEK(ctx context.Context, region string, dek crypto.DEK) ([]byte, error) {
    // Use kms.GenerateDataKey to create a data key, OR kms.Encrypt the DEK directly.
    // Bind region as EncryptionContext so a blob wrapped for EU cannot unwrap in US.
    out, err := p.client.Encrypt(ctx, &kms.EncryptInput{
        KeyId:             &p.keyARN,
        Plaintext:         dek[:],
        EncryptionContext: map[string]string{"region": region},
    })
    if err != nil { return nil, fmt.Errorf("kms: WrapDEK: %w", err) }
    return out.CiphertextBlob, nil
}

func (p *kmsKeyProvider) UnwrapDEK(ctx context.Context, region string, wrapped []byte) (crypto.DEK, error) {
    out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
        CiphertextBlob:    wrapped,
        EncryptionContext: map[string]string{"region": region},
    })
    if err != nil { return crypto.DEK{}, crypto.ErrDecryptFailed }
    var dek crypto.DEK
    copy(dek[:], out.Plaintext)
    return dek, nil
}
```

## Test strategy

### Unit tests (no AWS required)

Define a `KMSEncryptDecryptAPI` interface covering `Encrypt`/`Decrypt`/`Sign`/`GetPublicKey`
methods. Provide a `fakeKMS` test double in `_test.go` files. This keeps unit
tests fast and offline.

```go
// TestKMSBackedSigner_Sign: sign input, verify with public key (no KMS needed)
// TestKMSKeyProvider_WrapUnwrap: round-trip through fakeKMS
// TestBuildSigner_LocalFallback: KMS_KEY_ARN unset → LocalSigner returned
// TestBuildSigner_KMSPath: KMS_KEY_ARN set, DB has active key → KMSBackedSigner
// TestBuildSigner_FirstRun: DB empty → key generated + stored + returned
```

### Integration tests (LocalStack)

Tagged `//go:build integration`. Require `LOCALSTACK_ENDPOINT` env var.
Full flow: NewKMSClient → CreateKey → WrapPrivateKey → UnwrapPrivateKey →
reconstruct → Sign → verify.

## Helm values additions

```yaml
hot:
  kms:
    # ARN of the AWS KMS symmetric key protecting signing key material.
    # Leave empty in dev — falls back to ephemeral LocalSigner.
    keyArn: ""
    # AWS region for KMS API calls. Defaults to EC2 metadata region if empty.
    region: ""
    # Custom KMS endpoint (LocalStack only). Leave empty in production.
    endpoint: ""
```

ConfigMap template additions:
```yaml
{{- with .Values.hot.kms }}
KMS_KEY_ARN: {{ .keyArn | quote }}
KMS_REGION: {{ .region | quote }}
KMS_ENDPOINT: {{ .endpoint | quote }}
{{- end }}
```
