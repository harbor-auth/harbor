# Task 6: Key-rotation proxy handler with a second internal admin credential

## Scope (per tasks.md §6 + assigned task)

1. `internal/oidcapi/admin_auth.go`: extend `AdminAuthConfig`/`AdminAuthMiddleware`
   to accept a set of independently-labeled Bearer credentials instead of one
   `Token`. Log which label matched on every accepted/rejected request.
   Preserve constant-time comparison (compare against every configured
   credential, no early exit) and fail-closed behavior (empty credential set
   => always 401).
2. `cmd/harbor-hot/main.go`: wire a second, optional `MGMT_HOT_PROXY_TOKEN`
   credential (label "cloud-proxy") alongside the existing required
   `ADMIN_API_TOKEN` (label "operator") — needed for the "operator vs
   cloud-proxy" audit-log distinction to actually work end-to-end. Optional
   because harbor-hot runs standalone without Harbor Cloud integration.
3. `internal/cloudapi/keys.go`: `KeysHandler.PostKeysRotate` —
   - verifies the caller's `cloudServiceAuth` bearer via `ServiceAuthVerifier`
   - requires `keys:rotate` scope (403 `insufficient_scope` otherwise)
   - proxies to harbor-hot's unmodified `POST /admin/keys/rotate` using
     `MGMT_HOT_PROXY_TOKEN` (never `ADMIN_API_TOKEN`)
   - relays harbor-hot's response status/body; maps transport failures to
     500 `server_error` per `api/openapi/harbor-cloud.yaml`.
4. Tests: `admin_auth_test.go` (multi-credential accept/reject + label
   logging), `keys_test.go` (scope enforcement, correct credential used in
   the proxy call, cross-package check that harbor-hot's
   `AdminAuthMiddleware` logs `credential=cloud-proxy` vs `credential=operator`).

## Out of scope

- Binary wiring of `internal/cloudapi` into `cmd/harbor-mgmt` (task 7).
- Namespace/session handler changes (tasks 4/5, other agents — task 4's
  `namespaces.go` landed on this branch in parallel with its own `Server`
  type; `sessions.go` (task 5) and `keys.go` (this task) are both
  self-contained handler types instead. Reconciling `Server` /
  `SessionsHandler` / `KeysHandler` into one type satisfying
  `cloudopenapi.ServerInterface` is task 7's job, not this task's).
- Helm/k8s deploy config (task 7).

## Notes

- No router.go exists yet wiring `cloudapi` handlers via the generated
  `cloudopenapi.ServerInterface` — task 5's `sessions.go` establishes the
  convention of hand-rolled request/response structs + plain
  `http.HandlerFunc`-shaped methods, not the generated stubs. `keys.go`
  follows the same convention.
- `internal/gen/openapi/cloud/harbor_cloud.gen.go` has generated
  `KeysRotateRequest`/`KeysRotateResponse` types but they aren't used by
  `sessions.go` either — staying consistent, not introducing them here.
- Pre-existing golangci-lint findings in `internal/cloudapi/serviceauth.go`/
  `serviceauth_test.go` (task 3, already completed) block a clean
  `make agent-check`; filed as a follow-on task
  (`ftask_756c88f2-a5c0-4c2e-bf5a-f557efefee54`) rather than fixed here since
  those files are outside this task's scope.

## Task 13: Fix golangci-lint findings in internal/cloudapi/serviceauth.go

Ran `golangci-lint run ./internal/cloudapi/...` (v2.12.2, go1.25 — installed
locally since the pinned toolchain version couldn't type-check go1.25
modules) to get ground truth rather than trust the task's line numbers
verbatim, since prior commits on this branch could have shifted them.

- errcheck (serviceauth_test.go:82,157,267): `t.Cleanup(func() { _ =
  client.Close() })` on a `*redis.Client`. `.golangci.yml` already lists
  `(*...v9.Client).Close` in errcheck's `exclude-functions`, but that
  exclusion doesn't suppress `check-blank: true` findings on blank
  (`_ = `) assignments in this golangci-lint version. Matched the repo's
  existing convention (`internal/bff/session_redis_test.go`,
  `internal/webauthn/store_redis_test.go`, etc.): added
  `//nolint:errcheck // test cleanup` to each line instead of relying on
  the config exclusion.
- errorlint (serviceauth.go): the task named lines 274/279/284 (header/
  payload/signature decode), but the *same* `fmt.Errorf("%w: ...: %v",
  Sentinel, err)` double-wrap pattern was also live at lines 290, 302, and
  338 (header parse, claims parse, replay-guard error) — not mentioned in
  the task but flagged by the actual linter run. Fixed all six to
  `fmt.Errorf("%w: ...: %w", Sentinel, err)`, matching the repo's
  established double-`%w` convention (`internal/relay/store.go`,
  `internal/oidc/jwt_verifier.go`, `internal/region/resolve.go`).

`golangci-lint run ./internal/cloudapi/...` now reports one remaining
issue, `namespaces.go:281` (`json.Marshal` error unchecked) — pre-existing,
outside this task's file scope (task 4's output), suggested as a follow-on
task rather than fixed here.

`go build ./...`, `go vet ./internal/cloudapi/...`, `go test
./internal/cloudapi/...` all pass.
