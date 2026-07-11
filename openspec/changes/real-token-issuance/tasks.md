# Tasks: Real token issuance (crypto.Signer + JWKS)

## Prerequisites

- [ ] None — foundational root (can build in parallel with `envelope-encryption-kms`).

## Implementation

- [ ] `internal/crypto/signer.go`: `Signer` (ES256) + signing `KeyProvider` (dev in-proc key; HSM seam).
- [ ] `internal/oidc/jwt_issuer.go`: `JWTIssuer` implements `TokenIssuer`; minimal claims; `kid` header; short TTLs.
- [ ] `internal/oidc/jwks.go`: build the JWKS document from public key(s).
- [ ] `api/openapi/harbor.yaml`: add `GET /jwks.json` + JWKS schema; regenerate `internal/gen/openapi`.
- [ ] `internal/oidcapi/jwks.go`: implement the handler against the generated interface.
- [ ] `cmd/harbor-hot/main.go`: wire `JWTIssuer` (replace `NewPlaceholderIssuer`).

## Tests

- [ ] Sign→verify round-trip; header `kid` present.
- [ ] Issued JWT verifies against the served JWKS; unknown `kid` rejected.
- [ ] Expired + tampered tokens rejected.
- [ ] No PII in claims (only PPID `sub` + consented scopes).
- [ ] Frozen vectors verify a fixed token against a fixed key (byte-equality; never regenerated).

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate real-token-issuance --strict`
