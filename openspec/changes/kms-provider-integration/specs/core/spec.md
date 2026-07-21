# Spec: KMS provider integration (real regional KEK)

Replaces the fail-closed `kmsKeyProvider` scaffold with a real regional KEK
provider behind the existing `KeyProvider` seam: a vendor-neutral `kmsClient`
interface, a versioned self-describing wrapped-DEK envelope, region-scoped
wrap/unwrap that fails closed rather than crossing a jurisdiction, and a
`RewrapDEK` KEK-rotation primitive. Defines the client seam, the envelope
binding, the fail-closed region invariant, and rotation semantics.

## ADDED Requirements

### Requirement: REQ-001 Vendor-neutral kmsClient seam

The system SHALL wrap and unwrap DEKs through a narrow, vendor-neutral
`kmsClient` interface so the crypto package never depends on a specific KMS/HSM
SDK.

The `kmsKeyProvider` MUST depend only on a `kmsClient` interface exposing
encrypt/decrypt-by-key-ID; concrete vendor adapters MUST live behind that
interface. A test fake MUST satisfy the same interface so the provider is
testable hermetically.

```go
package crypto

type kmsClient interface {
    Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)
    Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
}
```

#### Scenario: Provider drives the seam, not a vendor SDK

**Given** a `kmsKeyProvider` backed by a fake `kmsClient`
**When** `WrapDEK` is called
**Then** the wrap is performed via the fake's `Encrypt` and no vendor SDK is invoked

#### Scenario: Fake satisfies the kmsClient interface

**Given** a test fake KMS implementation
**When** it is assigned to a variable of type `kmsClient`
**Then** the assignment compiles (compile-time interface assertion)

### Requirement: REQ-002 Versioned wrapped-DEK envelope with region binding

The system SHALL wrap a DEK into a versioned, self-describing envelope that
binds the region and KEK key-ID, and MUST validate that binding on unwrap.

`WrapDEK` MUST produce bytes carrying a header (`version`, `region`,
`kek_key_id`) ahead of the KMS ciphertext. `UnwrapDEK` MUST validate the header's
region and key-ID against the caller's `region` before decrypting; a mismatch,
tamper, or parse failure MUST return the single generic fail-closed error and
MUST NOT return plaintext.

#### Scenario: Wrap then unwrap round-trips the DEK

**Given** a DEK wrapped for region `eu` via a valid `kmsClient`
**When** `UnwrapDEK` is called with region `eu`
**Then** the original DEK is returned

#### Scenario: Region mismatch on unwrap fails closed

**Given** a wrapped DEK whose envelope header records region `eu`
**When** `UnwrapDEK` is called with region `us`
**Then** it returns the generic fail-closed error and no plaintext

#### Scenario: Tampered envelope header fails closed

**Given** a wrapped DEK whose header bytes have been altered
**When** `UnwrapDEK` is called
**Then** it returns the generic fail-closed error and no plaintext

### Requirement: REQ-003 Unknown region never crosses a jurisdiction

The system SHALL resolve a region to its KEK key-ID and MUST fail closed on an
unknown region without falling back to any other region's KEK.

Region→key-ID resolution MUST return a generic error for an unrecognised region.
The provider MUST NOT wrap or unwrap under a different region's KEK under any
circumstance (§5.4 jurisdiction invariant).

#### Scenario: Unknown region wrap fails closed

**Given** a provider configured with regions `us` and `eu`
**When** `WrapDEK` is called with region `zz`
**Then** it returns a generic error and performs no wrap

#### Scenario: No cross-region KEK fallback

**Given** a provider configured with regions `us` and `eu`
**When** an operation is requested for an unconfigured region
**Then** the provider never substitutes a configured region's KEK

### Requirement: REQ-004 KEK-rotation RewrapDEK primitive

The system SHALL provide a `RewrapDEK` operation that re-wraps an existing DEK
under the region's current KEK without exposing DEK plaintext beyond the
transient in-memory window.

`RewrapDEK(ctx, region, wrapped)` MUST unwrap under the KEK recorded in the
envelope header and re-wrap under the region's current KEK key-ID, returning a
new envelope. The re-wrapped DEK MUST unwrap to the same DEK value.

#### Scenario: Rewrap preserves the DEK under a rotated KEK

**Given** a DEK wrapped under KEK key-ID `kek-1` for region `eu`
**And** the region's current KEK key-ID is now `kek-2`
**When** `RewrapDEK` is called and the result is unwrapped
**Then** the recovered DEK equals the original DEK
**And** the new envelope records `kek_key_id = kek-2`
