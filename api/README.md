# Harbor contracts (`api/`, `db/`)

**Contracts are the single source of truth** (DESIGN §1.2–§1.5). Everything below
is hand-written; the code that implements/consumes it is **generated** and lives
under `internal/gen/**` — **never hand-edit generated output**. If code and spec
disagree, the code is the bug. Regenerate with **`@codegen`**.

## Layout

| Path | Contract | Generates | Tool |
|---|---|---|---|
| `api/openapi/harbor.yaml` | Public HTTP surface (OpenAPI 3.1) | Go server stubs + TS client | `oapi-codegen`, `openapi-typescript` |
| `api/openapi/oapi-codegen.yaml` | Go-generation config | — | `oapi-codegen` |
| `api/proto/**` | Internal gRPC (Protobuf) | Go types + gRPC | `buf generate` |
| `db/migrations/**` | SQL schema (baseline + changes) | — (applied by migrator) | `golang-migrate` / `goose` |
| `db/queries/**` | SQL queries (the query is the contract) | Typed Go queries | `sqlc generate` |

Root configs: **`buf.yaml`** / **`buf.gen.yaml`** (Protobuf lint/breaking/gen) and
**`sqlc.yaml`** (SQL → Go).

## Rules

- **Spec-first:** edit the contract → regenerate → commit **both** (§1.2).
- **Zero drift:** CI regenerates and fails on any diff (§1.5); `@validate` runs the
  same check on changed files.
- **Frontend never hand-writes API types** — they come from the same OpenAPI the Go
  server uses, so frontend and backend cannot silently drift.

## Related skills

- **`@codegen`** — regenerate every artifact from these contracts.
- **`@db-migrate`** — Postgres expand/contract migrations under `db/migrations/`
  (this initial `0001_init` is the greenfield baseline; expand/contract governs
  future changes to live tables).
