---
title: User DEK wrapping with OpenBao
status: implemented
design_refs: [§4.4, §10]
code: [internal/crypto/, internal/clients/, cmd/harbor-rewrap-user-deks/]
tests: [internal/crypto/, internal/clients/]
last_reconciled: 2026-09-08
---

# User DEK wrapping with OpenBao

User DEKs use a separate Transit key (`harbor-users-eu`) from signing-key
wrapping (`harbor-eu`). Management has encrypt/decrypt access only to the
user-data key. Hot has access to both because it derives pairwise identities
and records token audit events. Both use projected Kubernetes identities and
verified TLS; no static OpenBao token is mounted.

`USER_DEK_PROVIDER=openbao` selects this provider, and `USER_DEK_KEY_MAP` uses
the existing `region=key-name` format. New envelopes carry a distinct
`harbor:user-dek:v1:` marker. The external wrapping root stays inside OpenBao;
individual DEKs are transiently available to authorized application processes.
This does not prevent a compromised application from invoking its authorized
OpenBao operations. OVH auto-unseal protects OpenBao's storage root at restart,
not each running application's decisions.

## Migration sequence

Deploy the compatible binaries everywhere before changing providers. Provision
the non-exportable user-data Transit key and the hot/management policies;
management also needs its projected token, CA mount and NetworkPolicy access.
Use the chart's `userDEK` values for the following phases:

1. Enable OpenBao with `legacyReadEnabled=true` and
   `writeExternalEnabled=false`. Keep `HARBOR_KMS_SECRET` temporarily. Wait for
   every hot and management replica to be Ready with this configuration. They
   can now read both formats while continuing to write legacy envelopes.
2. Set `writeExternalEnabled=true` and wait for every writer to roll. The
   previous phase's readers already understand the new format, so rollout does
   not strand newly enrolled users on an older replica.
3. Execute `/harbor-rewrap-user-deks` from the hot image using its normal
   projected identity and database configuration. It locks each batch of rows,
   unwraps each existing DEK, wraps it externally, verifies the same DEK comes
   back, and changes only `users.dek_wrapped`. Ciphertext and PPIDs are preserved.
   Empty, erased keys are skipped. Corrupt envelopes abort the whole batch.
   Interrupted migrations resume safely; repeat execution is idempotent.
4. Verify no nonempty legacy envelopes remain and run real authentication,
   recovery and audit/export journeys. Set `legacyReadEnabled=false` and remove
   `HARBOR_KMS_SECRET` together in the new pod specification. A separate Secret
   without that field can make this rollout atomic. Restart every consumer to
   discard its old environment and provider state. The new configuration
   rejects a lingering legacy root at startup.
5. Remove the obsolete field from every remaining runtime Secret, reconcile
   final configuration into Git, and remove any temporary migration overrides.

Never run the migration while legacy writers remain, and never roll back to a
binary that cannot read the external format after phase 2. A provider outage
fails closed; it does not silently use the legacy root. Old snapshots with
legacy envelopes still require the old root, retained only under the operator's
protected recovery process. Removing it from current pods cannot retroactively
protect an old snapshot or a previously stolen key.

Relay is currently disabled. Before enabling it, supply a compatible user-DEK
reader and its own narrow OpenBao identity; its existing local-only composition
cannot consume migrated user envelopes.

## Verification

Unit tests cover both envelope formats, region/tamper rejection, phase-one
read/write compatibility, rejection after legacy access is disabled, and
refusal to retain an obsolete root. A real PostgreSQL integration test verifies
unchanged user ciphertext and DEKs, idempotence, batch rollback, and serialization
with concurrent erasure so rewrapping cannot resurrect a shredded key.
