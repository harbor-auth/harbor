# consent-ledger

**Status:** planned  
**DESIGN §:** §3.2, §10  
**Code:** `internal/oidc/consent.go` (planned)

Append-only consent ledger recording each user's per-RP consent decisions
(grant/revoke) as immutable, region-pinned events, providing an auditable
history of what a user authorized and when.
