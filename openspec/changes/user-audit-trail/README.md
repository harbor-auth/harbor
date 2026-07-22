# user-audit-trail

Build the user-owned audit trail — a named privacy pillar (§2.1) with nothing
shipped — on the existing envelope-encryption primitive. Adds a
`user_audit_events` table (migration 0013) keyed by `user_id`, carrying a coarse
`event_type`, a timestamp, and an **envelope-encrypted `payload` (🔒)** holding
the event detail encrypted under the **user's DEK**. A closed event taxonomy
(`auth.login`, `token.issued`, `token.refreshed`, `token.revoked`, plus the
`consent.*` events aligned with `consent-ledger`) is emitted through a
best-effort, non-blocking `AuditRecorder` so an audit-write failure never breaks
the auth/token flow. A user-authenticated `harbor-mgmt` endpoint lets the owner
list their own decrypted trail; the operator has **no plaintext read path** (it
sees only `user_id`/`event_type`/timestamp). Because every payload is encrypted
under the user's DEK, the shipped crypto-shred erasure (§11.6) reaches the trail
— destroying `users.dek_wrapped` renders it permanently unrecoverable. The trail
is regional, with no cross-user leakage and no cross-region aggregation.
