// Package mfa implements Harbor's TOTP second-factor (2FA) and single-use
// recovery codes (docs/DESIGN.md §3.1, §7.3, §10). It is the enrollment and
// step-up verification core consulted by the BFF step-up gate before a
// sensitive action proceeds.
//
// Security model:
//   - The TOTP shared secret is envelope-encrypted under the user's per-user
//     DEK (crypto-shred pattern, same as users.pairwise_secret) and stored in
//     mfa_factors.secret — never in plaintext at rest (internal/crypto).
//   - Recovery codes are bcrypt-hashed (mfa_factors.code_hash) and burned on
//     use (mfa_factors.used flips false → true exactly once), so a code can
//     never be replayed.
//   - Every factor row is region-pinned (mfa_factors.region) and never
//     cross-region replicated (docs/DESIGN.md §10).
//
// Following the package convention (internal/oidc, internal/webauthn), the
// verification logic is kept behind the [TOTPService] interface with the
// persistence surface behind a store interface, so the core stays unit-testable
// without a database and the in-memory dev store can be swapped for the
// sqlc-backed store (db/queries/mfa_factors.sql) without touching the logic.
package mfa
