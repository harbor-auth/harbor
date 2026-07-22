# compliance-export

Honour **data-subject rights** (§11.5): let a signed-in user **export** all their
data (access / portability) and **erase** it (right to be forgotten) — without
ever giving the operator a plaintext path. **EXPORT** assembles the caller's
**own decrypted** data (profile, consent grants, `user-audit-trail` events,
relay mappings) into a portable bundle that is **strictly caller-scoped**,
**region-pinned**, and **short-lived** (the bundle is itself PII). **ERASE**
uses Harbor's **crypto-shred** model (§11.6): destroying the user's wrapped DEK
(`users.dek_wrapped`) renders every envelope-encrypted record for that user
**permanently, provably unrecoverable** in one stroke — no per-table row-delete
sweep, and a prior export cannot re-hydrate erased data. Both operations are
region-pinned, metered aggregate-only, and audited (`compliance.export_*` /
`compliance.erase_*`). Adds **no new table** — it reads existing user-scoped
stores and erases by destroying the existing DEK.
