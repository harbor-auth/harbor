# Tasks: Compliance export & erasure (DSAR)

## Prerequisites

- [ ] **No DB migration** — reads existing user-scoped stores; erasure
  crypto-shreds the existing `users.dek_wrapped`. This change reserves no
  migration prefix.
- [ ] Depends on `user-audit-trail` (the decrypted, user-owned event history is
  a primary export source) and the shipped envelope crypto
  (`envelope-encryption-kms` ✅) whose crypto-shred is the erasure mechanism.
  Inherits the Gate-1 guardrails (`regional-data-residency-routing`,
  `observability-metrics`).

## Implementation

- [ ] `internal/identity/export.go`: assemble the **caller's own decrypted** data
  (profile, consent grants, audit-trail events, relay mappings) into a portable
  bundle — strictly caller-scoped, decrypted only under the caller's DEK, no
  operator plaintext path.
- [ ] `internal/mgmtapi/compliance.go`: user-authenticated, region-pinned export
  + erase endpoints; the export bundle is region-pinned and short-lived.
- [ ] `internal/identity/erase.go`: erasure via the shipped **crypto-shred**
  (destroy `users.dek_wrapped`); mark the user erased; irreversible.
- [ ] Reuse `internal/crypto/` crypto-shred entry point (add one if not already
  exposed) — do not invent a parallel erasure path.
- [ ] Meter export/erase **aggregate-only**; emit `user-audit-trail` events
  (`compliance.export_*`, `compliance.erase_*`).

## Tests

- [ ] EXPORT returns only the caller's own data — a cross-user read is not
  possible.
- [ ] Export/erase are region-pinned; the bundle is short-lived.
- [ ] Crypto-shred: after erase, the user's envelope-encrypted PII is
  permanently unrecoverable (destroying `users.dek_wrapped`); a prior export
  cannot re-hydrate erased data.
- [ ] Erasure is irreversible — the destroyed DEK cannot be reconstructed.
- [ ] Security: no operator plaintext path to another user's export; erase is
  audited.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate compliance-export --strict`
