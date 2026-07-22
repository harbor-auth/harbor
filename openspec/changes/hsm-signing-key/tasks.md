---
change: hsm-signing-key
kind: tasks
status: draft
created: 2026-07-22
---

# Tasks: HSM / KMS-backed signing key (Phase 1)

Estimated total: **~10 hours** (parallelisable by a Weft agent to ~4 hours).

## T1 — KMS client factory (1 h)

**File:** `internal/crypto/kms_client.go`

- [ ] T1.1 Check `go.mod` for `github.com/aws/aws-sdk-go-v2/service/kms`; add if absent
- [ ] T1.2 `func NewKMSClient(ctx, keyARN, region, endpoint string) (*kms.Client, error)`
      — use `config.LoadDefaultConfig`, override endpoint if set (LocalStack)
- [ ] T1.3 `func WrapPrivateKey(ctx, client, keyARN string, rawKey []byte) ([]byte, error)`
      — `kms.Encrypt` with `EncryptionContext: {"purpose": "signing-key"}`
- [ ] T1.4 `func UnwrapPrivateKey(ctx, client, ciphertext []byte) ([]byte, error)`
      — `kms.Decrypt`; clear plaintext slice after copy (memory hygiene)
- [ ] T1.5 Unit test: `fakeKMS` implementing `EncryptAPI`/`DecryptAPI`; round-trip test

## T2 — `kmsKeyProvider` implementation (1 h)

**File:** `internal/crypto/keyprovider_kms.go`

- [ ] T2.1 Add `client *kms.Client` and `keyARN string` fields to `kmsKeyProvider`
- [ ] T2.2 Export `NewKMSKeyProvider(client *kms.Client, keyARN string) KeyProvider`
- [ ] T2.3 Implement `WrapDEK`: call `kms.Encrypt` with `region` in `EncryptionContext`
- [ ] T2.4 Implement `UnwrapDEK`: call `kms.Decrypt`; return `ErrDecryptFailed` on any KMS error
- [ ] T2.5 Unit tests: `TestKMSKeyProvider_WrapUnwrap` (fakeKMS round-trip),
      `TestKMSKeyProvider_WrongRegion` (EncryptionContext mismatch → error)

## T3 — `KMSBackedSigner` type (1 h)

**File:** `internal/crypto/signer_kms.go`

- [ ] T3.1 `type KMSBackedSigner struct { priv *ecdsa.PrivateKey; jwk JWK; kid string }`
- [ ] T3.2 `NewKMSBackedSigner(priv *ecdsa.PrivateKey, kid string) *KMSBackedSigner`
      — derives JWK from pub key; logs `"harbor-hot: kms-backed signer loaded"` + kid at Info level
- [ ] T3.3 `Sign`: identical to `LocalSigner.Sign` (SHA-256 then ECDSA)
- [ ] T3.4 `KeyID`, `PublicJWK`, `String` (returns `"kmsBackedSigner(kid=<kid>)")
- [ ] T3.5 Compile-time `var _ Signer = (*KMSBackedSigner)(nil)`
- [ ] T3.6 Tests: `TestKMSBackedSigner_Sign` (sign + verify with pubkey),
      `TestKMSBackedSigner_String`, kid derivation round-trip

## T4 — `DBRotationStore` adapter (1.5 h)

**File:** `internal/clients/signingkeys_rotstore.go`

- [ ] T4.1 `type DBRotationStore struct { store *DBSigningKeyStore }`
- [ ] T4.2 `NewDBRotationStore(store *DBSigningKeyStore) *DBRotationStore`
- [ ] T4.3 `Create(ctx, key crypto.NewKeyMaterial) error`
      — maps `crypto.NewKeyMaterial` → `NewSigningKey`; `PrivateKeyWrapped` passed through
      — requires extending `crypto.NewKeyMaterial` with `PrivateKeyWrapped []byte` field
- [ ] T4.4 `ActiveKid(ctx) (string, error)` — calls `store.GetActive`, returns kid or ""
- [ ] T4.5 `Promote(ctx, kid string, promotedAt time.Time) error`
      — calls `store.SetState(ctx, id, "active", &promotedAt, nil)`
      — needs `GetByKid` first to resolve kid → id
- [ ] T4.6 `Retire(ctx, kid string) error` — calls `store.Retire(ctx, kid)`
- [ ] T4.7 Compile-time `var _ crypto.RotationStore = (*DBRotationStore)(nil)`
- [ ] T4.8 Unit tests with `MemSigningKeyStore` as the backing store

## T5 — Startup bootstrap in `cmd/harbor-hot/main.go` (2 h)

**File:** `cmd/harbor-hot/main.go`

- [ ] T5.1 Add `connectDB(ctx, logger) (*pgxpool.Pool, error)` helper
      (mirrors pattern in `cmd/harbor-mgmt/main.go`; reads `DATABASE_URL` env)
- [ ] T5.2 Add `buildKMSClient(ctx) (*kms.Client, bool)` helper
      (reads `KMS_KEY_ARN`, `KMS_REGION`, `KMS_ENDPOINT`; returns nil,false when unset)
- [ ] T5.3 Add `buildSigner(ctx, logger, pool, kmsClient) (crypto.Signer, error)` function:
      - pool==nil || kmsClient==nil: warn + return `NewLocalSigner()`
      - else: call `DBSigningKeyStore.GetActive()`, handle first-run, decrypt, return `KMSBackedSigner`
- [ ] T5.4 Add `buildRotator(signer, pool, kmsClient)` function:
      - if kmsClient==nil: return minimal in-memory rotator
      - else: `KeyRotator.WithGenerator(kmsKeyGenerator(kmsClient, KMS_KEY_ARN))`
- [ ] T5.5 Wire `buildSigner` result into `oidc.ServiceConfig` (replacing `NewPlaceholderIssuer`)
      — Note: this is blocked by the `fix-auth-bypass` P0 item which wires the real
        `JWTIssuer`; coordinate with that feature or stub-connect for now
- [ ] T5.6 Unit tests: `TestBuildSigner_LocalFallback`, `TestBuildSigner_KMSPath`,
      `TestBuildSigner_FirstRun` (uses fakeKMS + MemSigningKeyStore)

## T6 — Helm chart (0.5 h)

**Files:** `deploy/helm/values.yaml`, `deploy/helm/templates/configmap-hot.yaml`

- [ ] T6.1 Add `hot.kms.keyArn`, `hot.kms.region`, `hot.kms.endpoint` to `values.yaml`
      with empty defaults and comments
- [ ] T6.2 Add `KMS_KEY_ARN`, `KMS_REGION`, `KMS_ENDPOINT` env vars to `configmap-hot.yaml`
      (guarded by `{{- with .Values.hot.kms }}` or similar)
- [ ] T6.3 Update `values.yaml` comment block for `hot.secrets` to note KMS replaces `kekSecret`
      for signing keys (DEK wrapping still uses `kekSecret` in dev)

## T7 — Integration test with LocalStack (1.5 h)

**File:** `internal/crypto/kms_integration_test.go`

- [ ] T7.1 `//go:build integration` tag + skip if `LOCALSTACK_ENDPOINT` unset
- [ ] T7.2 `TestKMSRoundTrip_WrapUnwrap`: generate key → wrap → unwrap → bytes equal
- [ ] T7.3 `TestKMSRoundTrip_SignAndVerify`: full flow — generate P-256, wrap, store in
      MemSigningKeyStore, unwrap, reconstruct, sign token, verify with pubkey
- [ ] T7.4 `TestKMSKeyProvider_RegionBinding`: blob wrapped for "EU" fails to unwrap for "US"

## T8 — CI / quality (0.5 h)

- [ ] T8.1 `go build ./...` passes (no new import cycles)
- [ ] T8.2 `go vet ./...` clean
- [ ] T8.3 `go test ./internal/crypto/... ./internal/clients/... ./cmd/harbor-hot/...` green
- [ ] T8.4 `make agent-check` (gofmt, golangci-lint, docs-links, codegen-drift) clean
- [ ] T8.5 Update `docs/features/hsm-signing-key.md` stub (created by earlier CI run) with
      a one-paragraph description so docs-links check passes

## Acceptance criteria

- With `KMS_KEY_ARN` + `DATABASE_URL` set:
  - `harbor-hot` starts without error
  - logs `"kms-backed signer loaded"` + kid at Info level
  - `/jwks.json` returns the correct ES256 public key
  - Pod restart preserves the same kid (token continuity)
  - `POST /admin/keys/rotate` generates a new KMS-wrapped key and schedules rotation
- Without `KMS_KEY_ARN`:
  - `harbor-hot` starts with a DEV-ONLY warning and ephemeral `LocalSigner`
  - All existing e2e tests pass unchanged
- Unit test coverage: all T1–T5 subtasks have tests; `go test -race` passes
- `make agent-check` fully clean on the PR branch
