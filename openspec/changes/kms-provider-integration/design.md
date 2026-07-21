# Design: KMS provider integration (real regional KEK)

## Key Decisions

### Decision 1: Vendor-neutral `kmsClient` seam (not a vendor SDK in-package)
**Chosen:** `kmsKeyProvider` depends on a narrow internal `kmsClient` interface
(`Encrypt`/`Decrypt` by key-ID); the AWS/GCP/Vault/PKCS#11 adapter lives behind
it, and tests use an in-process fake.
**Rationale:** Keeps `internal/crypto` vendor-neutral and hermetically testable,
models the one primitive (wrap under a key never exported) that every KMS/HSM
exposes, and lets the deployment pick a provider without touching the crypto
core.
**Alternatives considered:** Bake the AWS KMS SDK directly into
`kmsKeyProvider` (couples crypto to one cloud, breaks hermetic tests, leaks
vendor types — rejected); mount the KEK as a secret and wrap in-process (that is
`localKeyProvider`; defeats the §7.3 "KEK never leaves the HSM boundary"
guarantee — rejected).

### Decision 2: Versioned self-describing wrapped-DEK envelope
**Chosen:** The wrapped DEK is `header{version, region, kek_key_id} ‖
kms_ciphertext`. `UnwrapDEK` validates the header's region/key-ID against the
caller's `region` before asking the KMS to decrypt.
**Rationale:** Makes region/jurisdiction and key-ID part of the persisted,
tamper-evident record (`users.dek_wrapped`), enables safe KEK rotation, and lets
unwrap fail closed on a region mismatch without a KMS round-trip. Versioning
from day one avoids a painful format migration later.
**Alternatives considered:** Store raw KMS ciphertext only (no region binding —
can't detect a cross-jurisdiction unwrap, can't rotate cleanly — rejected); a
side table mapping wrapped-DEK → region (extra state, drift risk — rejected).

### Decision 3: Unknown region fails closed — never a KEK fallback
**Chosen:** Region→key-ID resolution on an unrecognised region returns a generic
error; there is no default/fallback KEK.
**Rationale:** A silent fallback would wrap/unwrap a DEK under another
jurisdiction's KEK, violating the §5.4 invariant that key operations never cross
a jurisdiction. Fail-closed is the only safe posture for a sovereignty control.
**Alternatives considered:** Fall back to a "global" KEK (breaks data
sovereignty — rejected); pick the first configured region (nondeterministic,
unsafe — rejected).

### Decision 4: `RewrapDEK` rotation primitive (not a batch job)
**Chosen:** Provide `RewrapDEK(ctx, region, wrapped)` that unwraps under the
envelope's recorded KEK and re-wraps under the region's current KEK key-ID.
**Rationale:** KEK rotation must re-wrap existing DEKs without ever exposing DEK
plaintext beyond the transient window; a small, testable primitive is the right
unit. Bulk orchestration (iterate every DEK on rotation) is a separate concern
that composes this primitive.
**Alternatives considered:** Bundle a full re-wrap batch job here (scope creep,
harder to test — rejected); rotate by re-encrypting column plaintext under a new
DEK (unnecessary — the KEK layer is what rotates — rejected).

### Decision 5: Cold-path fail-closed availability posture
**Chosen:** KMS operations sit on the enrolment/decrypt (cold) path and fail
**closed** on KMS unavailability.
**Rationale:** Unlike the hot-path rate limiter (which fails open to protect
verification availability), a KMS outage must never produce unencrypted or
wrongly-wrapped rows. Correctness of at-rest encryption outweighs cold-path
availability.
**Alternatives considered:** Fail-open with a cached KEK (would move the KEK into
app memory, defeating §7.3 — rejected).
