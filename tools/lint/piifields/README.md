# piifields — PII-in-telemetry analyzer (Foundation F10)

A small, dependency-free (`go/parser` + `go/ast`) static analyzer that enforces
the observability privacy invariants of **DESIGN §6.5.7** ("No PII in metrics
labels, trace spans, or logs — ever").

## What it flags

Any logging/attribute call that passes a **known-PII field name** as a string
literal key, e.g.:

```go
slog.String("email", user.Email)          // flagged
logger.Info("login", "user_id", u.ID)      // flagged
slog.Any("access_token", tok)              // flagged
```

The PII key list mirrors `internal/telemetry.DeniedFields`
(`email`, `user_id`, `sub`, `ppid`, `ip`, `ip_address`, `token`, `access_token`,
`id_token`, `code_verifier`, `phone`, `name`, `relay`, `relay_address`).

## Why

A single "helpful" `log.Info("user", email)` silently breaks Harbor's core
trust promise (§2.2). The safe path is the **deny-by-default** wrapper
[`internal/telemetry`](../../../internal/telemetry), which redacts any key that
is not explicitly allow-listed. This analyzer catches direct `slog`/`log` calls
that bypass that wrapper.

## Exemptions

`_test.go` files, `internal/gen/**` (generated), `internal/telemetry/**` (the
wrapper itself), and `tools/lint/**` (self) are not scanned.

## Invocation

```bash
go run ./tools/lint/piifields ./...      # scan the repo
go run ./tools/lint/piifields internal   # scan a subtree
```

Exits non-zero with one `path:line: PII-FIELD: …` line per finding. Wired into
`make agent-check` (Foundation F6).
