# Spec: Real token issuance

Replaces placeholder tokens with real, asymmetrically-signed JWTs (ES256) issued by the OIDC layer and verifiable offline against a published JWKS. Defines the `Signer` contract, the `JWTIssuer`, the `/jwks.json` endpoint, and the claim-minimization and verifiability invariants.

## ADDED Requirements

### Requirement: REQ-001 Asymmetric signer contract

The system SHALL sign tokens with an asymmetric signer whose private key never leaves the provider.

The system MUST sign tokens using an asymmetric `Signer` whose private key never leaves the KeyProvider/HSM. The signer exposes its key ID and public JWK for publication.

```go
package crypto

type Signer interface {
    Sign(signingInput []byte) (sig []byte, err error)
    KeyID() string
    PublicJWK() JWK
}
```

#### Scenario: Sign produces an ES256 signature

**Given** a signing input for a JWT  
**When** `Sign` is called  
**Then** an ES256 signature is returned and the private key never leaves the provider/HSM

#### Scenario: Signer failure surfaces as server_error

**Given** the signer fails to produce a signature  
**When** `JWTIssuer.Issue` is invoked during a `/token` request  
**Then** `Issue` returns an error and `/token` responds with `server_error`

### Requirement: REQ-002 JWT issuance with minimal claims

The system SHALL issue JWTs with minimal claims and short TTLs.

The system MUST issue JWTs via `JWTIssuer.Issue`. Tokens MUST use short TTLs and minimal claims: `sub` is always the PPID, never the raw `user_id`, and no email/name is included unless consented.

```go
package oidc

type JWTIssuer struct{}

func (JWTIssuer) Issue(ctx context.Context, p IssueParams) (IssuedTokens, error)
```

#### Scenario: sub is always the PPID

**Given** issuance parameters for an authenticated user  
**When** `Issue` produces tokens  
**Then** the `sub` claim is the PPID and never the raw `user_id`

#### Scenario: No PII without consent

**Given** issuance parameters without consent for profile claims  
**When** `Issue` produces tokens  
**Then** no email or name claims are included

#### Scenario: Short TTL enforced

**Given** issuance parameters  
**When** `Issue` produces an access token  
**Then** the token carries a short expiry

### Requirement: REQ-003 JWKS publication endpoint

The system SHALL publish signing keys at a JWKS endpoint.

The system MUST add `GET /jwks.json` to the OpenAPI spec, returning the public signing keys so relying parties can verify tokens offline.

Returns:

```json
{"keys":[{"kty":"EC","crv":"P-256","kid":"...","x":"...","y":"...","use":"sig","alg":"ES256"}]}
```

#### Scenario: JWKS returns the active signing key

**Given** an active ES256 signing key  
**When** a client requests `GET /jwks.json`  
**Then** the response contains a JWK with `kty=EC`, `crv=P-256`, `use=sig`, `alg=ES256`, and the matching `kid`

#### Scenario: kid consistency

**Given** an issued token  
**When** its header `kid` is resolved against the JWKS  
**Then** it resolves to exactly one published JWKS key

### Requirement: REQ-004 Offline verifiability and rejection of bad tokens

The system SHALL support offline verification and reject invalid tokens.

Relying parties MUST be able to verify tokens against the JWKS with no callback. Tokens that are expired, tampered, or reference an unknown `kid` MUST be rejected.

#### Scenario: Offline verification succeeds

**Given** a freshly issued token and a cached JWKS  
**When** the RP verifies the token  
**Then** verification succeeds with no callback to the issuer

#### Scenario: Expired token rejected

**Given** a token past its expiry  
**When** the RP verifies it  
**Then** the RP rejects the token

#### Scenario: Tampered token rejected

**Given** a token whose payload or signature has been altered  
**When** the RP verifies it  
**Then** the signature check fails and the RP rejects the token

#### Scenario: Unknown kid rejected

**Given** a token whose header `kid` is not present in the JWKS  
**When** the RP verifies it  
**Then** the RP rejects the token
