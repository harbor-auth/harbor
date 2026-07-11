# Spec: Client & grant persistence

Backs the OIDC `ClientRegistry` with sqlc-generated queries over the `relying_parties` table and introduces a `GrantStore` for durable, region-scoped consent grants. Defines the client-lookup and grant contracts plus the exact-redirect-URI and region-write invariants (DESIGN §7.4).

## ADDED Requirements

### Requirement: REQ-001 sqlc-backed ClientRegistry

The system SHALL back the ClientRegistry with sqlc queries over the relying_parties table.

The existing `ClientRegistry` MUST be backed by sqlc queries over the `relying_parties` table. Lookups return a `Client` describing its sector, redirect URIs, allowed scopes, and token format.

```go
package oidc

// ClientRegistry (existing) — now sqlc-backed
type ClientRegistry interface {
    Lookup(ctx context.Context, clientID string) (Client, bool)
}

type Client struct {
    ID, SectorID string
    RedirectURIs, ScopesAllowed []string
    TokenFormat string
}
```

SQL: `GetRelyingParty :one`, `ListRelyingParties :many`, `UpsertRelyingParty :one` over the `relying_parties` table.

#### Scenario: Known client resolves

**Given** a `client_id` present in `relying_parties`  
**When** `Lookup` is called  
**Then** the corresponding `Client` and `true` are returned

#### Scenario: Unknown client returns not-found

**Given** a `client_id` not present in `relying_parties`  
**When** `Lookup` is called  
**Then** `(_, false)` is returned, which the caller maps to `invalid_client`

### Requirement: REQ-002 Exact redirect-URI matching

The system SHALL match redirect URIs exactly.

Redirect URIs MUST be matched exactly against the client's registered `RedirectURIs`. No prefix or substring matching is permitted (§7.4).

#### Scenario: Exact match accepted

**Given** a client with a registered redirect URI  
**When** an authorization request presents that exact URI  
**Then** it is accepted

#### Scenario: Mismatched redirect URI rejected without redirect

**Given** a client with a registered redirect URI  
**When** an authorization request presents a URI that differs by prefix, substring, or any character  
**Then** the request is rejected with a non-redirect error

### Requirement: REQ-003 GrantStore for durable consent

The system SHALL provide a GrantStore for durable, region-scoped consent grants.

The system MUST provide a `GrantStore` to find, create, revoke, and list consent grants. Grants are scoped and carry region, and `sector_id` drives PPID grouping.

```go
// GrantStore (new)
type GrantStore interface {
    FindGrant(ctx context.Context, userID, clientID string) (Grant, bool, error)
    CreateGrant(ctx context.Context, g Grant) (Grant, error)
    RevokeGrant(ctx context.Context, grantID string) error
    ListGrantsByUser(ctx context.Context, userID string) ([]Grant, error)
}

type Grant struct {
    ID, Region, UserID, ClientID, PairwiseSub string
    Scopes []string
}
```

#### Scenario: Create then find a grant

**Given** no existing grant for a user/client pair  
**When** a grant is created and then looked up via `FindGrant`  
**Then** the stored grant is returned with `found = true`

#### Scenario: Region written on every user-owned write

**Given** a grant being persisted  
**When** `CreateGrant` executes  
**Then** the `Region` field is populated on the written row

#### Scenario: Revoking an unknown grant is a no-op

**Given** a grant ID that does not exist  
**When** `RevokeGrant` is called  
**Then** the operation is a no-op and returns no error
