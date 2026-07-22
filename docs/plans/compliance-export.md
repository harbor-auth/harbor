---
title: Compliance export & erasure (DSAR — data-subject access & right-to-be-forgotten)
status: draft
design_refs: [§11.5, §11.6, §11.2]
targets: [internal/mgmtapi/, internal/identity/, internal/crypto/]
promoted_to: null
openspec: changes/compliance-export
created: 2026-07-22
---

# Compliance export & erasure (plan)

> **Dependency order:** **Gate 3** of Wave 5 — depends on `user-audit-trail`
> (the decrypted, user-owned event history is a **primary export source**) and
> the shipped envelope crypto (`envelope-encryption-kms` ✅), whose **crypto-shred**
> is the erasure mechanism. Inherits the **Gate-1 guardrails** — every read is
> region-pinned (`regional-data-residency-routing`) and every counter is
> aggregate-only (`observability-metrics`). It adds **no new table**: it reads
> existing user-scoped stores and erases by destroying the user's DEK. Lands
> alongside `consent-management-ui` in Gate 3.

## Problem

A privacy-first OP must honour **data-subject rights** (§11.5): a user has the
right to **export** all their data (access / portability) and to **erase** it
(right to be forgotten). Harbor holds each user's PII under a per-user
envelope-encryption DEK (§11.6), which means erasure can be **provable** —
destroying the user's DEK renders all their envelope-encrypted PII permanently
unrecoverable — but there is **no user-facing DSAR flow** to actually export or
erase. Without it, Harbor cannot satisfy GDPR/CCPA obligations, and its
strongest privacy property (crypto-shred erasure) is unreachable by the very
users it protects.

## Proposed approach

A user-authenticated, region-pinned **DSAR flow** composed over shipped
user-scoped primitives — no new store.

1. **EXPORT (access / portability)** — assemble the **caller's own decrypted**
   data into a portable bundle: profile, `consent_grants`, `user-audit-trail`
   events, and `relay_addresses` mappings. The assembly is **strictly
   caller-scoped** — decrypted only under the caller's DEK — with **no operator
   plaintext path** and no cross-user read. The bundle is itself PII, so it is
   **region-pinned** and **short-lived**.
2. **ERASE (right to be forgotten)** — **crypto-shred** by destroying the user's
   wrapped DEK (`users.dek_wrapped`), so every envelope-encrypted record for that
   user becomes **permanently unrecoverable** at once — no per-table row-delete
   sweep, no risk of a missed table. Erasure is **irreversible** and audited.
3. **Guardrails** — export and erase are user-authenticated, region-pinned,
   metered **aggregate-only** (`observability-metrics`), and every request emits
   a `user-audit-trail` event (`compliance.export_*` / `compliance.erase_*`).

## DESIGN alignment

Realises §11.5 (compliance / DSAR — access, portability, erasure) **via** §11.6
(the crypto-shred model — destroy the DEK, not the rows) and keeps §11.2 (the
user data surface is user-controlled). Does **not** change `DESIGN.md` — the
crypto-shred erasure property is already designed; this plan builds the DSAR
surface that exercises it.

## Target code paths

- `internal/mgmtapi/compliance.go` — user endpoints: `POST` export (assemble +
  return a region-pinned, short-lived bundle) and `POST` erase (crypto-shred),
  both strictly caller-scoped.
- `internal/identity/export.go` — caller-scoped assembly of the user's decrypted
  profile / grants / audit events / relay mappings into the portable bundle.
- `internal/identity/erase.go` — the erasure lifecycle: invoke crypto-shred,
  mark the user erased, audit.
- `internal/crypto/` — reuse the shipped crypto-shred (destroy `users.dek_wrapped`);
  add an erase entry point if one is not already exposed.

## Implementation checklist

- [ ] `internal/identity/export.go`: assemble the **caller's own decrypted** data (profile, consent grants, audit-trail events, relay mappings) into a portable bundle — strictly caller-scoped, no operator plaintext path.
- [ ] `internal/mgmtapi/compliance.go`: user-authenticated, region-pinned export + erase endpoints; the export bundle is region-pinned and short-lived.
- [ ] `internal/identity/erase.go`: erasure via shipped **crypto-shred** (destroy `users.dek_wrapped`); mark the user erased; irreversible.
- [ ] Meter export/erase **aggregate-only**; emit `user-audit-trail` events (`compliance.export_*`, `compliance.erase_*`).
- [ ] Tests: export returns only the caller's own data (no cross-user leak); export/erase are region-pinned; erase is audited.
- [ ] Tests (crypto-shred): after erase, the user's envelope-encrypted PII is permanently unrecoverable (destroying `users.dek_wrapped`); a prior export bundle cannot re-hydrate erased data.
- [ ] Tests (security): no operator plaintext path to another user's export; erasure is irreversible (the destroyed DEK cannot be reconstructed).
- [ ] Author & verify paired OpenSpec change: `openspec validate compliance-export --strict`
- [ ] Reconcile & promote: `@plan promote compliance-export`

## Risks & open questions

- **Erasure must be irreversible and provable** — crypto-shred is chosen
  precisely because destroying the DEK makes recovery cryptographically
  impossible; the test suite must **prove** unrecoverability, not merely assert a
  row was deleted. A residual copy of the DEK (backup, cache) would defeat this —
  audit every place the wrapped DEK can live.
- **Export must be strictly caller-scoped** — assembly decrypts only under the
  caller's DEK; any code path that could read another user's plaintext is a
  design violation. No operator plaintext path.
- **Partial-erase hazards** — crypto-shred erases *envelope-encrypted* PII in one
  stroke, but any non-DEK-wrapped derived data (aggregate counters are fine;
  anything user-identifying is not) must be accounted for so erasure is complete.
- **Legal-hold vs erasure tension** — a legal hold may conflict with a
  right-to-be-forgotten request; the flow records the erase decision in the
  audit trail, and hold policy is an operator concern layered above this
  mechanism (out of scope here, but the audit event makes the tension visible).
- **The export bundle is PII** — it is region-pinned and short-lived; it must not
  be cached cross-region or retained after delivery, or it becomes a second copy
  of everything crypto-shred is meant to destroy.

## Definition of done

`go build/vet/test ./...` green; a signed-in user can **export** a portable
bundle of their own decrypted data (strictly caller-scoped, region-pinned,
short-lived, no operator plaintext path) and **erase** their account via
crypto-shred (destroying `users.dek_wrapped`) such that their envelope-encrypted
PII is provably, permanently unrecoverable and a prior export cannot re-hydrate
it; both are region-pinned, metered aggregate-only, and audited; `make
agent-check` clean. Ready to `@plan promote`.
