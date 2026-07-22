# Tasks: User creation & enrollment (§11.1)

## Prerequisites

- [ ] `envelope-encryption-kms` (needs `GenerateDEK` + `KeyProvider.WrapDEK` and the `Encryptor` for `pairwise_secret`).

## Implementation

- [ ] `db/queries/users.sql`: `CreateUser`, `GetUser`, `SetStatus`; regenerate `internal/gen/db`.
- [ ] `internal/identity/enroll.go`: region selection + region-encoded id; generate `pairwise_secret` + DEK; wrap DEK; encrypt secret; write row transactionally.
- [ ] `internal/webauthn/store.go`: sqlc-backed credential `Store` (replace in-memory).
- [ ] First-passkey registration keyed off the real `users.id`.
- [ ] `cmd/harbor-mgmt/main.go`: real signup endpoint; **delete** the dev-only `user_id` query-param path.

## Tests

- [ ] Enrollment creates exactly one `users` row with region + wrapped DEK + encrypted `pairwise_secret`.
- [ ] First passkey persists to `credentials`, keyed off the real id.
- [ ] Transaction rolls back on passkey/KEK failure (no orphan user).
- [ ] Negative: the dev-only `user_id` path is gone (compile/route assertion).
- [ ] No PII in enrollment logs.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate user-enrollment --strict`
