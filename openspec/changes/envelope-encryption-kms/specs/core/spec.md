# Spec: Envelope encryption & KMS

`internal/crypto` provides per-user data encryption (DEK) with the DEK wrapped by a regional KEK. This realizes DESIGN §4.4 and serves the 🔒 columns in §10. It defines the encryption/decryption contracts, the key-provider boundary, and the invariants that guarantee fail-closed, region-isolated, crypto-shreddable storage.

## ADDED Requirements

### Requirement: REQ-001 DEK generation and envelope encryption primitives

The system SHALL provide DEK generation and envelope encryption primitives.

The system MUST provide a 256-bit per-user data encryption key (DEK) sourced from a CSPRNG, and MUST provide AES-256-GCM sealing/opening of plaintext under a DEK. The DEK is held in memory only transiently; at rest only the KEK-wrapped form is stored.

```go
package crypto

// DEK is a 256-bit per-user data encryption key. Held in memory only
// transiently; at rest we store only the KEK-wrapped form.
type DEK [32]byte

// GenerateDEK returns a fresh CSPRNG DEK.
func GenerateDEK() (DEK, error)

// Encryptor seals plaintext under a DEK using AES-256-GCM.
// Output layout: nonce ‖ ciphertext ‖ tag.
type Encryptor interface {
    Encrypt(dek DEK, plaintext, aad []byte) (ciphertext []byte, err error)
}

// Decryptor opens ciphertext under a DEK. It fails CLOSED: any tag mismatch
// returns an error and NEVER partial plaintext.
type Decryptor interface {
    Decrypt(dek DEK, ciphertext, aad []byte) (plaintext []byte, err error)
}
```

#### Scenario: Round-trip encryption

**Given** a freshly generated DEK and some plaintext with AAD  
**When** the plaintext is encrypted and then decrypted with the same DEK and AAD  
**Then** the recovered plaintext equals the original and the ciphertext layout is nonce ‖ ciphertext ‖ tag

#### Scenario: CSPRNG-only key and nonce material

**Given** a request to generate a DEK or encrypt plaintext  
**When** key or nonce material is required  
**Then** it is drawn from `crypto/rand` and no zero or predictable value is used

#### Scenario: RNG failure never yields a zero key

**Given** the system RNG fails  
**When** `GenerateDEK` or `Encrypt` is invoked  
**Then** an error is returned and never a zero key or zero nonce

### Requirement: REQ-002 Fail-closed decryption

The system SHALL fail closed on decryption.

Decryption MUST fail closed. Any GCM authentication-tag mismatch or malformed input MUST return an error and MUST NEVER return partial plaintext.

#### Scenario: Tampered ciphertext is rejected

**Given** a valid ciphertext whose bytes have been altered  
**When** `Decrypt` is called  
**Then** an error is returned and no plaintext is emitted

#### Scenario: Short or malformed ciphertext is rejected

**Given** a ciphertext shorter than the required nonce+tag length  
**When** `Decrypt` is called  
**Then** an error is returned (fail-closed) with no partial output

### Requirement: REQ-003 KeyProvider wrap/unwrap boundary

The system SHALL enforce the KeyProvider wrap/unwrap boundary.

The system MUST provide a `KeyProvider` that wraps and unwraps a DEK under a region's KEK. The KEK never leaves the provider (in prod, the HSM boundary; DESIGN §7.3). A DEK wrapped for one region MUST NOT be unwrappable as another region.

```go
// KeyProvider wraps/unwraps a DEK under a region's KEK. The KEK never leaves
// the provider (in prod, the HSM boundary; DESIGN §7.3).
type KeyProvider interface {
    WrapDEK(ctx context.Context, region string, dek DEK) (wrapped []byte, err error)
    UnwrapDEK(ctx context.Context, region string, wrapped []byte) (DEK, error)
}
```

#### Scenario: Wrap then unwrap in same region

**Given** a DEK wrapped for region A  
**When** it is unwrapped for region A  
**Then** the original DEK is recovered

#### Scenario: Region isolation on unwrap

**Given** a DEK wrapped for region A  
**When** `UnwrapDEK` is called with region B  
**Then** an error is returned (§5.4) and no DEK is recovered

#### Scenario: DEK at rest is always wrapped

**Given** a user record persisted to storage  
**When** the DEK is stored  
**Then** only `WrapDEK` output is written to `users.dek_wrapped` and no plaintext DEK persists

### Requirement: REQ-004 Key provider implementations

The system SHALL provide local and KMS key provider implementations.

The system MUST provide two implementations: `localKeyProvider` for dev/test and `kmsKeyProvider` for production. The local provider derives KEK = HKDF(env secret, region), is self-identifying, refuses an empty secret, and MUST NEVER be used in production. The KMS provider delegates wrap/unwrap to the regional KMS/HSM.

- `localKeyProvider` — dev/test: KEK = HKDF(env secret, region). Refuses an empty secret; self-identifying; NEVER for production.
- `kmsKeyProvider` — prod scaffold: wrap/unwrap delegate to the regional KMS/HSM.

#### Scenario: Empty dev secret fails loudly

**Given** an empty environment secret  
**When** `localKeyProvider` is constructed  
**Then** construction fails loudly with an error

#### Scenario: Crypto-shred renders data unrecoverable

**Given** data encrypted under a DEK whose `dek_wrapped` is stored  
**When** `dek_wrapped` is destroyed  
**Then** all data encrypted under that DEK is permanently unrecoverable (§11.6)
