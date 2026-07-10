> **DESIGN §1.11** · [↑ DESIGN index](../../DESIGN.md) · prev: [skills-and-small-files](skills-and-small-files.md)

# Error Handling

## 1.11 Explicit error handling — every error must be dealt with

**Core principle: no error may be silently discarded.** Every function that returns an error must have that error explicitly handled by its caller: returned up the call stack, converted to a typed user-visible failure, or handled with deliberate recovery logic. There is no silent discard, no `_ = someFunc()` without justification.

### The swallow anti-pattern (forbidden)

```go
// BAD — the error is gone forever; the caller behaves as if the call succeeded.
_ = s.revocations.RevokeCodeFamily(ctx, code)
return nil, invalidGrant("code already used")

// BAD — logging as a fig leaf to continue on the happy path.
if err != nil {
    log.Warn("revocation failed", "error", err)
    // falls through — pretends the error never happened
}
```

"Logging is not error handling." A `log.Warn` followed by a `return nil` (or no return at all) swallows the error: the caller continues on the primary path as though the call succeeded. The log line disappears into a stream of events and produces no consequence.

### What "handled" means

| Scenario | Correct handling |
|---|---|
| Function calling an operation that can fail | Return the error (wrapped with context: `fmt.Errorf("doing X: %w", err)`) |
| HTTP handler receiving a business-logic error | Convert to a typed error response; log at ERROR if it's unexpected |
| Best-effort security side-effect (e.g. revocation signal after theft detection) | Log at `ERROR` via structured logger — this is NOT swallowing because the error is surfaced for operator action and creates an alertable signal |
| Write to an HTTP response body | Allowed to discard (see §Narrow exceptions below) |
| `defer`-ed `Close()` on a consumed body | Allowed to discard (see §Narrow exceptions below) |

The distinction between a logged side-effect and a swallow: a logged side-effect is surfaced at a level that triggers alerting, creates an operator-actionable event, and does NOT pretend to the rest of the code that the call succeeded. A swallow produces nothing — it is invisible.

### Best-effort security side-effects

Some operations are fire-and-signal rather than request-scoped: when an authorization code is reused (theft detected), the system must still return `invalid_grant` to the caller regardless of whether the downstream revocation sink is reachable. But the revocation failure must not be silent:

```go
// GOOD — best-effort side-effect: primary response is independent of revocation
// success, BUT the failure is surfaced at ERROR for operator alerting.
if err := s.revocations.RevokeCodeFamily(ctx, code); err != nil {
    s.logger.ErrorContext(ctx, "code-family revocation failed after reuse detected",
        slog.String("client_id", code.ClientID),
        slog.Any("error", err))
    // TODO(security): route through a durable outbox so transient failures are
    // retried, not just alerted.
}
return nil, invalidGrant("authorization code has already been used")
```

**PII constraint (§6.5.7):** only `client_id` and the error value may appear in the structured log line. Never log `Subject` (PPID), `Code` (a secret), or `Nonce` — those are the denied fields the piifields linter guards.

The `TODO(security)` comment is deliberate: a best-effort in-process signal is itself a smell for a security-critical action. The eventual fix is a durable outbox so revocation survives transient failures. The ERROR log is the correct *interim* handling.

### Wrapping errors with context

Errors crossing a layer boundary must carry context:

```go
// BAD — caller can't tell where the failure came from.
return nil, err

// GOOD — context without hiding the original cause.
return nil, fmt.Errorf("persisting authorization code: %w", err)
```

Use `%w` (not `%v`) so the wrapped error participates in `errors.Is`/`errors.As` chains.

### `errors.Is` / `errors.As`, not `==`

Sentinel comparisons must use `errors.Is`:

```go
// BAD — breaks if the error is wrapped.
if err == ErrUserNotFound { ... }

// GOOD — works through the wrap chain.
if errors.Is(err, ErrUserNotFound) { ... }
```

The `errorlint` linter (§CI enforcement below) flags `==` comparisons against error values.

### A linter that can't see the code isn't enforcing anything

A build-tagged file (`//go:build sometag`) is invisible to `golangci-lint run ./...` unless that tag is listed in `.golangci.yml`'s `run.build-tags`. An unlisted tag means the linter silently reports "0 issues" for a file it never analyzed — the same silent-failure shape this principle exists to prevent, just at the tooling layer instead of the code layer. When adding a new `//go:build <tag>` file, add `<tag>` to `run.build-tags` in the same change (see `e2e/flow_test.go` / the `e2e` tag for the precedent).

### Narrow exceptions: where `_ =` is acceptable

Two patterns are explicitly permitted and need no further comment:

1. **HTTP response body writes** (`w.Write(...)`, `json.NewEncoder(w).Encode(v)`) — if the TCP connection is gone there is nowhere to deliver the error; the OS reclaims the socket. Any other error handling would mask or double-write.

2. **Deferred `Close()` on a consumed body** (`defer func() { _ = res.Body.Close() }()`) — the response has already been consumed; close errors are benign and handled by the runtime's connection-pool recycling.

Both of these are excluded from the `errcheck` linter (see `.golangci.yml`). Any other `_ =` that silently discards a non-error value is still fine; it is only error-typed returns that must be handled.

### `panic` is never used for recoverable errors

`panic` is reserved for bugs that mean the process is in an inconsistent state (nil interface violations, impossible enum values). It is not a substitute for returning an error from a recoverable operation. The application has no recovery middleware; a panic in a goroutine crashes the process.

### CI enforcement (§1.8)

The following linters are active in `.golangci.yml`:

| Linter | What it catches |
|---|---|
| `errcheck` (with `check-blank: true`) | Every unchecked error return, including explicit `_ = f()` blanks |
| `nilerr` | `if err != nil { return nil }` — returning nil despite holding an error |
| `errorlint` | `err == sentinel` comparisons; `%v` formatting of wrapped errors instead of `%w` |

The `errcheck` exclusion list in `.golangci.yml` documents the two permitted discard patterns above. Any proposed addition to that list is a code-review trigger: if it can't be justified against the two permitted patterns, it must be fixed instead.
