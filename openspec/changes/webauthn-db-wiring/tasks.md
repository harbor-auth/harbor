# Tasks: Wire sqlc-backed WebAuthn store in harbor-mgmt

## Prerequisites

- [ ] `internal/webauthn/store_db.go` provides `NewDBStore` and `.WithPool`
      (already present and tested).
- [ ] `pool` and `db.New` are already available in `cmd/harbor-mgmt/main.go`.

## Implementation

- [ ] In `cmd/harbor-mgmt/main.go`, replace the stale-TODO
      `store := webauthn.NewInMemoryStore()` and its preceding comment with
      `var store webauthn.Store` and a `pool != nil` branch.
- [ ] DB branch: `store = webauthn.NewDBStore(db.New(pool)).WithPool(pool)`;
      `logger.Info("webauthn store: using DB-backed store")`.
- [ ] Fallback branch: `store = webauthn.NewInMemoryStore()`;
      `logger.Warn("DATABASE_URL not set — using in-memory WebAuthn store (dev only; credentials lost on restart)")`.
- [ ] Confirm the `db` import is present (it already is for other wiring in
      `main.go`; verify and add only if missing).

## Tests

- [ ] No new unit tests required — DB store and in-memory store are already
      covered by their respective test files; rely on `go build` + `go vet` +
      `go test` for the wiring change.
- [ ] Smoke check: with `DATABASE_URL` set, register a passkey, restart the
      process, and confirm the credential survives; with `DATABASE_URL` unset,
      confirm the dev-only `Warn` is logged.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate webauthn-db-wiring --strict`
