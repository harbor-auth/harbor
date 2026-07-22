# Proposal: Wire sqlc-backed WebAuthn store in harbor-mgmt

## Problem

`cmd/harbor-mgmt/main.go` always builds the WebAuthn ceremony store with
`webauthn.NewInMemoryStore()`, behind a stale TODO. The SQLC-backed `DBStore`
(with the atomic first-passkey enrollment path via `.WithPool`) already exists
and is tested in `internal/webauthn/store_db.go`, but the binary never
instantiates it. So registered passkeys live only in memory and are lost on
restart even when a real Postgres pool is available — the durable credential
store (§4.1, §9) is built but not connected.

## Proposed Solution

Replace the unconditional construction in `cmd/harbor-mgmt/main.go` with:

```go
var store webauthn.Store
if pool != nil {
    store = webauthn.NewDBStore(db.New(pool)).WithPool(pool)
    logger.Info("webauthn store: using DB-backed store")
} else {
    logger.Warn("DATABASE_URL not set — using in-memory WebAuthn store (dev only; credentials lost on restart)")
    store = webauthn.NewInMemoryStore()
}
```

`.WithPool(pool)` is required so credential insertion and user activation commit
atomically in one transaction. The stale comment is removed. No other files change.

## Non-Goals

- No new database migrations (all required tables already exist).
- No new interfaces or adapters (`DBStore` already satisfies `webauthn.Store`).
- No changes to `internal/webauthn/` — the store implementation is complete.
- No changes to enrollment sessions or BFF flows (covered by separate proposals).
- No configuration flags beyond the existing `DATABASE_URL` presence check.

## Success Criteria

- [ ] With `DATABASE_URL` set, harbor-mgmt selects `webauthn.NewDBStore(db.New(pool)).WithPool(pool)` and logs the selection at `Info`.
- [ ] Without `DATABASE_URL`, harbor-mgmt logs a `Warn` and falls back to `webauthn.NewInMemoryStore()`.
- [ ] A credential registered in DB mode survives a process restart.
- [ ] Only `cmd/harbor-mgmt/main.go` is modified; no new migrations.
- [ ] `go build ./... && go vet ./... && go test ./...` pass.
