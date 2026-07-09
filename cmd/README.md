# Backend (Go)

Harbor's backend is a modular monolith in Go that compiles into small,
separately-deployable binaries (see `docs/DESIGN.md` §4.2, §8).

## Binaries (`cmd/`)

| Binary | Path | Role |
|---|---|---|
| `harbor-hot` | `cmd/harbor-hot` | Stateless OIDC / verify **hot path** (authorize, token, jwks, discovery, introspect). Default port `8080`. |
| `harbor-mgmt` | `cmd/harbor-mgmt` | Management / dashboard **cold path** (dashboard/BFF, enrollment, consent, audit, admin). Default port `8081`. |

Both currently expose `GET /healthz` → `200 ok` and share the tiny HTTP wiring in
`internal/httpserver`. Set `PORT` to override the listen port.

## Internal packages (`internal/`)

Layout follows `docs/DESIGN.md` §4.2:

| Package | Status | Responsibility |
|---|---|---|
| `internal/identity` | **real** | Users/credentials and **PPID derivation** (§3.2) — pure, deterministic, no I/O. |
| `internal/region` | **real** | Region resolution & validation (§5). |
| `internal/httpserver` | **real** | Shared health server + graceful shutdown. |
| `internal/oidc` | stub | OP endpoints (§11) — package boundary documented, impl pending. |
| `internal/crypto` | stub | Envelope encryption / DEK-KEK / signing (§4.4) — impl pending. |

## Build & test

Use the skills:

- **`@go-build`** — `go build ./...`, or build the binaries into `bin/`.
- **`@go-test`** — `go test ./...` (add `-race`, `-cover` as needed).

Quick start:

```bash
go build ./...      # compile everything
go vet ./...        # static checks
go test ./...       # run the unit tests
```
