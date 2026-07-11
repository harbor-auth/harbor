# Spec: User enrollment

`internal/identity` enrolls users into a home region, generating and storing per-user secrets (DEK and pairwise secret) only in encrypted form, transactionally with credential rows. Defines the enrollment contract plus region-immutability, secret-hygiene, and transactional invariants.

## ADDED Requirements

### Requirement: REQ-001 Enrollment contract and home region

The system SHALL enroll users into exactly one immutable home region.

The system MUST enroll a user into exactly one home region via `Enroller.Enroll`. The region is encoded in the user `id` and is immutable thereafter.

```go
package identity

type EnrollParams struct { Region string }
type EnrolledUser struct { ID, Region string }

func (s *Enroller) Enroll(ctx context.Context, p EnrollParams) (EnrolledUser, error)
```

SQL: `CreateUser :one` (id, region, status, dek_wrapped, pairwise_secret), `GetUser :one`, `SetStatus :exec`.

#### Scenario: Successful enrollment encodes region in id

**Given** valid `EnrollParams` with a region  
**When** `Enroll` succeeds  
**Then** an `EnrolledUser` is returned whose `id` encodes the immutable home region

#### Scenario: Invalid region rejected before any write

**Given** `EnrollParams` with an invalid region  
**When** `Enroll` is called  
**Then** it is rejected before any database write occurs

### Requirement: REQ-002 Secrets encrypted at rest

The system SHALL store user secrets only in encrypted form at rest.

The user's `pairwise_secret` MUST be CSPRNG-generated and stored encrypted under the user's DEK. The `dek_wrapped` column MUST be the DEK wrapped by `KeyProvider.WrapDEK(region, dek)`. No secret is ever stored in plaintext.

#### Scenario: Pairwise secret stored encrypted

**Given** a new user being enrolled  
**When** `CreateUser` persists the row  
**Then** `pairwise_secret` is stored encrypted under the user DEK and never in plaintext

#### Scenario: DEK stored wrapped

**Given** a freshly generated DEK for the user's region  
**When** the row is written  
**Then** `dek_wrapped` equals `KeyProvider.WrapDEK(region, dek)` output

#### Scenario: No PII in logs

**Given** enrollment is in progress  
**When** log lines are emitted  
**Then** no PII is written to logs

### Requirement: REQ-003 Transactional enrollment

The system SHALL enroll users transactionally.

Enrollment MUST be transactional: the user row and credential rows commit together or not at all. Any failure MUST leave no partial state, and the insecure dev `user_id` query-param path MUST be removed.

#### Scenario: KEK wrap failure aborts with no row

**Given** `KeyProvider.WrapDEK` fails  
**When** enrollment runs  
**Then** enrollment aborts and no user row is written

#### Scenario: Passkey registration failure rolls back

**Given** passkey registration fails after the user row is staged  
**When** the transaction is finalized  
**Then** the whole transaction is rolled back leaving no partial state

#### Scenario: No dev backdoor

**Given** a request using the previously-existing insecure `user_id` query-param path  
**When** the request is processed  
**Then** the path does not exist and the request is not honored

### Requirement: REQ-004 Duplicate enrollment handling

The system SHALL reject or idempotently handle duplicate enrollment.

Duplicate enrollment attempts MUST be either rejected or handled idempotently, never producing conflicting duplicate users.

#### Scenario: Duplicate enrollment rejected or idempotent

**Given** a user that is already enrolled  
**When** enrollment is attempted again  
**Then** the request is rejected or returns the existing user idempotently
