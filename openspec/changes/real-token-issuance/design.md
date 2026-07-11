# Design: Real token issuance (crypto.Signer + JWKS)

## Key Decisions

### Decision 1: ES256 (P-256 ECDSA), not RS256
**Chosen:** ES256 as the default signing algorithm.
**Rationale:** Smaller tokens and signatures + faster verification on the hot
path (§3.3), which is what makes millions/sec cheap. EdDSA is an acceptable
alternative behind the same interface.
**Alternatives considered:** RS256 (larger, slower verify — rejected as default).

### Decision 2: Drop into the existing `TokenIssuer` seam
**Chosen:** `JWTIssuer implements oidc.TokenIssuer`; the `/token` flow logic in
`service.go` is untouched.
**Rationale:** The seam was built for exactly this swap. Keeps the DoS-safe
code-exchange ordering and error channels intact; the diff is additive.
**Alternatives considered:** Inlining signing into the service (couples crypto
to flow logic, rejected).

### Decision 3: Contract-first `/jwks.json`
**Chosen:** Add the operation to `api/openapi/harbor.yaml`, regenerate, then
implement the handler.
**Rationale:** DESIGN §1.2 — the spec is the source of truth; the compile-time
`ServerInterface` assertion stops the spec outrunning the server.
**Alternatives considered:** Hand-rolled handler outside the contract (violates
§1.3, rejected).

### Decision 4: Signing key in a `KeyProvider` (dev key now, HSM later)
**Chosen:** Same `KeyProvider` abstraction shape as the KEK side; dev uses an
in-process ECDSA key with a stable `kid`, prod delegates to the HSM.
**Rationale:** Hermetic tests (F3) without a real HSM; identical production
shape; private key never leaves the boundary (§7.3).

### Decision 5: Golden vectors verify a fixed token, not re-signing
**Chosen:** Freeze a known-good signed token + its verifying key; the vector
test asserts *verification*, not signature bytes.
**Rationale:** ES256 signatures are non-deterministic (random `k`), so signature
bytes can't be frozen — but a fixed token's verifiability can (F2).
