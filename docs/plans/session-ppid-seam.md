---
title: Session seam — WebAuthn login → PPID → token subject
status: draft
design_refs: [§3.2, §11.2]
targets: [internal/oidc/, internal/identity/, internal/webauthn/]
promoted_to: null
openspec: changes/session-ppid-seam
created: 2026-07-10
---

# Session seam — login → PPID → subject (plan)

> **Dependency order:** depends on **`user-enrollment`** (needs a real user with
> a `pairwise_secret`), **`client-grant-persistence`** (needs the RP's
> `sector_id` + a place to record consent), and **`real-token-issuance`**
> (so the resolved PPID is signed into a real ES256 token — required, not
> optional). Build after those.

## Problem

`internal/oidc/service.go` uses a `stubSessionResolver` that **auto-approves a
fixed demo subject** (`demo-subject-ppid`). `internal/identity.DerivePPID` is
real and tested — but **never called on the hot path**. The result: `/authorize`
issues codes for a hardcoded fake subject, so no real user ever logs in and the
core privacy guarantee (a per-RP pairwise `sub`, §3.2) is completely bypassed.
This is *the* seam that connects authentication to the OIDC flow.

## Proposed approach

Replace `stubSessionResolver` with a real `SessionResolver` that runs the §11.2
login + consent step and derives the pairwise subject:

1. **Authenticate** the user via the existing `webauthn.FinishLogin` ceremony,
   yielding the real `users.id`.
2. **Load the user's `pairwise_secret`** (decrypt with their DEK via
   `crypto`/`envelope-encryption-kms`).
3. **Look up the RP's `sector_id`** from the DB-backed client registry
   (`client-grant-persistence`).
4. **Resolve the pairwise subject via `GrantStore`** — look up the existing
   consent grant for `(user_id, client_id)` via `GrantStore.FindGrant`.
   - **Returning user (grant found):** read `grant.PairwiseSub` directly — no
     PPID re-derivation needed (§3.2.3: the materialized `pairwise_sub` is
     persisted in the `grants` table for cheap hot-path lookup).
   - **First consent (no grant):** derive the PPID now:
     `sub = DerivePPID(pairwise_secret, sector_id, user_id)` (§3.2), then
     record the new grant via `GrantStore.CreateGrant` (storing `pairwise_sub`).
5. **Consent**: skip the consent screen when the requested scopes are already
   granted, else record new consent on the grant.
6. Return `(sub, approved)` — the resolved PPID flows through the *unchanged*
   `/authorize` → code → `/token` path into the token's `sub` claim.

The `SessionResolver` interface already exists as the seam; this plan supplies
the real implementation without touching the flow logic in `service.go`.

## DESIGN alignment

Realizes §3.2 (pairwise PPID as the `sub` an RP sees) and the login/consent
step of §11.2. Closes the gap where a real, tested primitive (`DerivePPID`) was
never invoked. Does **not** change `DESIGN.md`.

## Target code paths

- `internal/oidc/resolver.go` — real `SessionResolver` (login → PPID → consent)
- `internal/identity/` — reuse `DerivePPID` (no change expected)
- `internal/webauthn/` — expose the authenticated `user_id` to the resolver
- `cmd/harbor-hot/main.go` — wire the real resolver (replace `NewStubSessionResolver`)
- `internal/oidc/resolver_test.go`

## Implementation checklist

- [ ] Real `SessionResolver` implementation over webauthn login + PPID + `GrantStore`.
- [ ] Decrypt `pairwise_secret` via the user's DEK; never log it (§6.5.7).
- [ ] Find-or-create grant: on existing grant, read `grant.PairwiseSub` directly (§3.2.3); on new grant, derive via `identity.DerivePPID(pairwise_secret, sector_id, user_id)` and persist as `pairwise_sub`.
- [ ] Find-or-create grant; scope-superset check to skip redundant consent.
- [ ] Wire into `cmd/harbor-hot/main.go`; keep the stub for tests only.
- [ ] Tests: **same user + same RP ⇒ stable `sub`**; **same user + different RP (sector) ⇒ different `sub`** (unlinkability, §3.2); consent recorded once; rejection ⇒ `access_denied`; `pairwise_secret` never appears in logs/tokens.
- [ ] Author & verify paired OpenSpec change: `openspec validate session-ppid-seam --strict`
- [ ] Reconcile & promote: `@plan promote session-ppid-seam`

## Risks & open questions

- The hosted **login/consent UI** (§11.2) is a larger surface — v1 can wire the resolver against a minimal/programmatic consent step, with the full UI a follow-up; the PPID derivation + grant recording are the security-critical parts to land now.
- Decrypting `pairwise_secret` on the hot path adds a KEK unwrap — cache the *unwrapped DEK* per session carefully (never persist it) to stay within latency budget.
- Must never fall back to a raw `user_id` as `sub` on any error — fail closed (§11.7), because leaking `user_id` breaks cross-RP unlinkability.

## Definition of done

`go build/vet/test ./...` green; `/authorize` issues codes bound to a **real,
per-RP PPID** derived from the authenticated user; consent persists via
`GrantStore`; the unlinkability property (same user, different RP ⇒ different
`sub`) is test-enforced; `pairwise_secret` never logged; `make agent-check`
clean. Ready to `@plan promote`.
