# Design: User creation & enrollment (§11.1)

## Key Decisions

### Decision 1: Region chosen at signup, encoded into the id
**Chosen:** Explicit user-chosen home region, region-prefixed id (reuse
`internal/region`).
**Rationale:** §3.4/§5 — routing and key discovery need no global lookup; the id
carries its jurisdiction. Explicit choice avoids brittle geo-inference.
**Alternatives considered:** Geo-IP inference (fragile, privacy-sensitive —
rejected as the default).

### Decision 2: Generate DEK + pairwise_secret at enrollment
**Chosen:** Create a fresh DEK, wrap it via the regional KEK, and store
`pairwise_secret` encrypted under that DEK — all in the create-user step.
**Rationale:** The account is encrypted from birth (§4.4); nothing exists in
plaintext at rest, and crypto-shred works from day one (§11.6).
**Alternatives considered:** Lazy secret generation on first login (leaves a
window of a secret-less account, rejected).

### Decision 3: Transactional multi-row enrollment
**Chosen:** users + first credential in one DB transaction.
**Rationale:** A half-enrolled account (user with no passkey, or passkey with no
secret) is a security/UX hazard; atomicity removes the failure mode.
**Alternatives considered:** Best-effort sequential writes (partial state on
crash, rejected).

### Decision 4: Delete the dev-only `user_id` path in the same change
**Chosen:** Remove the insecure query-param path as part of enrollment landing.
**Rationale:** Leaving it would be a live auth bypass alongside a real signup —
the §1.11 "no silent insecure path" posture demands removing it now.

### Decision 5: Recovery is partially scoped
**Chosen:** Record the ≥2-method requirement + recovery codes; defer social
guardians (§7.2) to a separate plan.
**Rationale:** Keeps this change focused on account creation while honoring the
"recovery set up in advance" contract.
