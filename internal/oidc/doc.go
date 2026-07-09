// Package oidc holds Harbor's OpenID Connect / OAuth 2.1 flow logic — the
// Authorization Code + PKCE exchange, its error channels, and token issuance
// (docs/DESIGN.md §3.1, §11.2, §11.7). The core is pure and deterministic (the
// code/challenge/params are passed in), so it is unit-testable without mocks
// (§1.7).
//
// Enforced invariants (see invariants/registry.yaml, Foundation F1):
//   - INV-PKCE-MANDATORY        S256 required; plain rejected (pkce.go).
//   - INV-REDIRECT-EXACT        exact redirect_uri match (token.go).
//   - INV-CODE-SINGLE-USE       short-TTL, one-time codes (token.go, store.go).
//   - INV-INVALID-GRANT-GENERIC every /token failure collapses to invalid_grant
//     so it never leaks which check failed (token.go).
//   - INV-CONSTANT-TIME-COMPARE constant-time PKCE comparison (pkce.go).
//   - INV-SIGN-ASYM-ONLY        asymmetric-only signing; the current issuer is an
//     obvious unsigned scaffold until the HSM signer
//     lands (issuer.go).
//
// Crypto outputs are additionally frozen by the golden-vector corpus in
// testdata/pkce_vectors.json (Foundation F2) so silent drift is impossible.
package oidc
