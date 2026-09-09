---
title: Signing Key Rotation (JWKS kid lifecycle)
status: implemented
design_refs: [§7.3, §3.5, §3.3]
code:  [internal/crypto/, internal/clients/, internal/oidcapi/, cmd/harbor-hot/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/crypto/, internal/clients/, internal/oidcapi/]
depends_on: [real-token-issuance]
plan: signing-key-rotation
last_reconciled: 2026-09-08
---

# Signing Key Rotation (JWKS kid lifecycle)

## Production behavior

The hot process uses `clients.LiveSigningKeys` for issuance, JWKS, introspection,
and logout verification. Each operation reads a coherent live key set from
PostgreSQL. Private keys are unwrapped once per replica/key and cached locally;
metadata reads do not call the KMS. A database failure fails these operations
closed rather than serving stale trusted keys. Already in-flight operations may
complete using their captured snapshot.

Migration `0022_signing_key_rotation` extends the lifecycle to
`pending → active → draining → retired` and stores promotion/retirement
deadlines. A PostgreSQL transaction advisory lock serializes first-key seeding,
rotation requests, and reconciliation across replicas. The unique active-key
index remains in force. Promotion demotes the old active key before promoting
the replacement, in the same transaction.

Production publishes pending keys for six minutes, exceeding the five-minute
JWKS cache lifetime, then keeps outgoing keys published for fifteen minutes.
The one-second reconciliation worker resumes persisted schedules on startup.
Only one pending rotation may exist; an emergency rotation atomically retires
all previous active, pending, and draining keys and activates its replacement.
The API response contains planned promotion and retirement times; delayed
reconciliation starts the overlap window at actual promotion.

`POST /admin/keys/rotate` retains its authenticated API contract. A
`crypto.SigningKeySource` supplies request snapshots; the original static signer
configuration remains available for small tests and SDK consumers.

External verifiers may retain cached public keys. Removing a key from Harbor's
JWKS is not a promise that every third-party cache immediately invalidates it.
The relying-party contract must cover cache refresh and acceptable token age.
Production generates software signing keys and wraps them through the configured
external key provider; it does not perform per-token HSM signing.

## Verification

`TestIntegrationLiveSigningKeyRotation` uses real PostgreSQL, independent replica
objects, and a continuously running JWKS HTTP server. It verifies concurrent
bootstrap and rotation, durable scheduling/restart recovery, overlap, emergency
revocation including pending keys, consistent ID/access-token key IDs, cached
unwrapping, and failure-closed behavior after database loss. It does not rebuild
the issuer or HTTP server to simulate a key change.

Schema rollback refuses to discard lifecycle states that the old schema cannot
represent. Roll application code forward to repair an in-progress rotation;
do not force a schema downgrade that would silently republish canceled keys or
truncate overlap.
