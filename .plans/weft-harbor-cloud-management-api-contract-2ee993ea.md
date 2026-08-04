# Task 7: Wire cloudapi into harbor-mgmt behind the cloudIntegration gate and deploy config

## Scope (per tasks.md §7 + assigned task)

1. `cmd/harbor-mgmt/main.go`: read `CLOUD_INTEGRATION_ENABLED` (new boolean
   gate env var, mirrors `mgmt.cloudIntegration.enabled`), and when set,
   require `CLOUD_SERVICE_AUTH_PUBLIC_KEY`, `MGMT_HOT_PROXY_TOKEN`, and
   `HARBOR_HOT_INTERNAL_URL` before the HTTP listen boundary (fail-fast, same
   convention as the other required-env checks already in `run`). Build
   `cloudapi.ServiceAuthVerifier` (Redis replay guard, reusing the existing
   Redis client), `cloudapi.Store` (reusing the existing `db.Queries`), and
   `cloudapi.KeysHandler`, then register all five `/admin/v1/*` routes on the
   existing mux via a new helper.
2. New file `cmd/harbor-mgmt/cloudapi.go`: `registerCloudAPIRoutes` wires the
   five routes. `namespaces.go`/`sessions.go` handlers do their own idempotency
   but NOT service-auth (their doc comments say auth is "enforced by the auth
   middleware ahead of this handler" — this task is that middleware); wrap
   them with a `cloudAuthorized` middleware that calls
   `ServiceAuthVerifier.Verify` + checks the route's required scope
   (`sessions:mint` / `namespaces:read` / `namespaces:write`).
   `keys.go`'s `PostKeysRotate` already self-verifies (it needs the
   `cloud-proxy`-labeled distinction to be internal to that handler) — wrapping
   it in `cloudAuthorized` too would call `Verify` twice and reject the second
   call as a replay of its own `jti`, so `keys.rotate` is wired WITHOUT the
   extra auth middleware, only the rate limiter. Every route also gets a
   dedicated Redis-backed rate limiter (`cloudRateLimited`) that denies
   (`429 rate_limited`) on a limiter backend error — fail-closed, mirroring
   `mgmtapi.productionAbuseGate`.
3. `deploy/helm/values.yaml` + `deploy/helm/templates/{secret-mgmt,
   deployment-mgmt,networkpolicy-mgmt}.yaml`: add
   `mgmt.cloudIntegration.{cloudServiceAuthPublicKey,hotProxyToken}` (secret
   material — go in `secret-mgmt.yaml`, gated on `cloudIntegration.enabled`)
   and an env entry on the container computing `HARBOR_HOT_INTERNAL_URL` from
   the existing `harbor-hot` Service DNS name (non-secret, so it's a plain
   `env:` entry on `deployment-mgmt.yaml`, not routed through the ConfigMap —
   keeps `configmap-mgmt.yaml` untouched per the task's file list).
   `networkpolicy-mgmt.yaml` gets an egress rule to `harbor-hot`'s pod on
   `hot.port` (mgmt now calls hot for the keys-rotate proxy), gated the same
   way. `cloudIntegration.enabled: false` stays the shipped default.
4. `deploy/k8s/{configmap-mgmt,secret-mgmt,deployment-mgmt}.yaml`: mirror the
   same three env vars as commented `REPLACE_ME` placeholders (raw manifests
   have no `if`-gating, so they ship inert but present).
5. Tests: extend `cmd/harbor-mgmt/main_test.go` with the same AST-level
   "required before listen" convention for the three new conditional env
   checks, plus a new `cmd/harbor-mgmt/cloudapi_test.go` exercising
   `registerCloudAPIRoutes` end-to-end over `httptest` for: missing bearer
   (401), wrong scope (403), and rate-limiter backend error (429, fail
   closed) — using a fake `clients.RateLimiter` and a real
   `ServiceAuthVerifier` (ES256, miniredis-backed replay guard, mirroring
   `internal/cloudapi/serviceauth_test.go`'s `newTestEnv`). A fake querier
   satisfies `cloudapi.Store`'s unexported `querier` interface structurally
   (its methods are exported-named, taking exported `internal/gen/db` types),
   so no real Postgres is needed for these wiring-only tests.

## Out of scope

- Full contract/fixture-driven and cross-process integration tests (task 8) —
  this task's own tests only prove the wiring (gate, auth, scope, rate-limit
  fail-closed), not the full happy-path namespace/session/key-rotate
  behavior, which is already covered by tasks 4/5/6's unit tests.
- `invariants/registry.yaml` + docs (task 9).
- Wiring `MGMT_HOT_PROXY_TOKEN` into harbor-hot's own deploy config
  (`deploy/helm/templates/secret-hot.yaml` etc.) — out of this task's
  explicit file list; harbor-hot's code already reads the env var (task 6),
  but nothing sets it in a chart/manifest yet. Filed as a follow-on so
  `cloudIntegration.enabled: true` actually works end-to-end in a real
  deployment.
- `internal/mgmtapi/region_middleware.go`'s host-based region gate wraps the
  whole handler, including `/admin/v1/*` — Harbor Cloud's calls arrive via
  the WireGuard NodePort, possibly with a `Host` header that doesn't map to
  a bound region, which would 400 before reaching the cloudapi routes.
  Not in this task's file list; filed as a follow-on.

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

## Task 8: Contract fixtures + cross-process integration/security test suite

Started while task 7 ("Wire cloudapi into harbor-mgmt behind the
cloudIntegration gate and deploy config") was still `in_progress` on the
shared feature — `cmd/harbor-mgmt/main.go` has no `cloudapi` import yet, and
per task 6's notes above, no production type satisfies
`cloudopenapi.ServerInterface` yet (`Server`/`SessionsHandler`/`KeysHandler`
are three separate types with three different method shapes).

Rather than block on task 7, built a **test-only** reconciliation in
`internal/cloudapi/contract_test.go`:
- `contractAdapter` implements `cloudopenapi.ServerInterface` by delegating to
  the real `Server`/`SessionsHandler`/`KeysHandler` — no production file
  changed, nothing exported, not reachable from any `cmd/*` binary.
- `requireServiceAuth` is the generic cloudServiceAuth middleware
  namespaces.go's doc comment says is "wired in a later task" — it reads each
  operation's required scope from the context value the generated
  `ServerInterfaceWrapper` already attaches (`CloudServiceAuthScopes`), so it
  needs no hand-maintained path->scope table. It skips `/admin/v1/keys/rotate`
  deliberately: `KeysHandler.PostKeysRotate` already verifies+scope-checks
  itself, and stacking a second `Verify` call on the same bearer would see a
  fresh jti as already claimed and reject a legitimate first call.
- `newContractRouter(store, verifier, hotBaseURL, proxyToken, hotClient)` is
  the one router-builder shared by `contract_test.go` (in-process, miniredis)
  and `integration_test.go` (`-tags=integration`, real Postgres/Redis, served
  via `httptest.NewServer` for a genuine HTTP round trip).

When task 7 lands its own production reconciliation in `cmd/harbor-mgmt`
(likely nearly this same shape), this test harness does not need to change —
it exercises the same underlying handlers task 7 will wire, just via a
test-local composition instead of the production one. A future cleanup could
point these tests at task 7's production router instead of duplicating the
~30-line adapter/middleware here, but that's optional: the tests prove the
same contract either way.

Fixtures live under `internal/cloudapi/testdata/contract/*.json`, one file
per `spec.md` "#### Scenario:" heading (`spec_scenario` field cross-references
the exact heading text). Each fixture is a sequence of HTTP steps against the
shared router; auth-outcome fixtures use `GET /admin/v1/namespaces/{id}`
against a namespace that doesn't exist as a clean auth-only probe — that
route never returns 401/403 from its own logic, so a 404 unambiguously proves
"authorized, handler executed" and a 401/403 unambiguously proves "rejected
before the handler ran," without needing idempotency-key or persisted-state
setup. `TestContractAuditEventsEmitted` and `TestContractRateLimitFailsClosed`
are hand-written (not fixture-driven) since they assert on the audit-log side
channel and on 429 behavior under a real rate limiter, not just the HTTP
response.

Two `spec.md` scenarios (session `session_expired` / `cross_tenant_forbidden`)
aren't reachable via this OpenAPI surface at all — no `/admin/v1/*` route
consumes a *session* bearer, only `cloudServiceAuth` JWTs; those two
scenarios are already covered directly against
`SessionsHandler.VerifySessionBearer` in `sessions_test.go`
(`TestVerifySessionBearerExpired`, `TestVerifySessionBearerCrossTenantMismatch`),
so not duplicated here.

`internal/oidcapi/router_test.go` gets a behavioral check that harbor-hot's
real mux 404s every `/admin/v1/*` path; `internal/arch/arch_test.go` gets a
`go list -deps`-based architecture fitness test (matching its existing
`TestHotPathDoesNotImportMgmtPackages` pattern) proving `cmd/harbor-hot` never
transitively imports `internal/cloudapi` at all — the stronger, structural
version of "harbor-hot never exposes the contract."

`integration_test.go`'s "harbor-mgmt returns 404 when cloudIntegration
disabled" check is expressed against `httpserver.NewHealthMux()` with cloudapi
simply never mounted (the actual disabled-state behavior, since an
unregistered `net/http` pattern always 404s) rather than against
`cmd/harbor-mgmt` directly — `cmd/harbor-mgmt` is a `main` package and can't
be imported from `internal/cloudapi`, and task 7 owns the real gate wiring
and its own tests there. Task 7 landed its production reconciliation as
described below; it did not change task 8's test-local adapter (that
remains a valid, independent proof of the same contract).

### Verification

No PostgreSQL/Redis in this container (no docker, no root, no systemd) so
`-tags=integration` tests were verified to compile clean
(`go vet -tags=integration ./...`) and skip gracefully
(`DATABASE_URL is not set; ...`) rather than run end-to-end — matching how
`cmd/harbor-mgmt`/`cmd/harbor-hot`'s own `-tags=integration` files already
behave in this same environment.

`go build ./...`, `go vet ./...` / `-tags=integration`, `go test ./...`
/ `-tags=integration` all pass repo-wide. The PATH `golangci-lint` binary is
still the pre-existing go1.24-built one noted in task 13's entry above and
can't type-check go1.25 modules at all (`can't load config: the Go language
version (go1.24) ... is lower than 1.25.0`) — installed
`golangci-lint@v2.12.2` (go1.25) locally to get ground truth, matching task
13's precedent. `golangci-lint run ./...` (before task 14 landed) reported
exactly one issue, `namespaces.go:281` (outside this task's file scope) —
nothing new from this task's files. `go run ./tools/lint/testweakening --base
origin/main` is clean.

## Task 7 (production wiring, landed after the task 8 notes above)

- `*cloudapi.Server` already implements 3 of the 5 `cloudopenapi.ServerInterface`
  methods with matching signatures (`PostAdminV1Namespaces`,
  `GetAdminV1Namespace`, `DeleteAdminV1Namespace`); `SessionsHandler.PostSessions`
  and `KeysHandler.PostKeysRotate` use their own hand-rolled signatures instead
  (per task 6's plan notes) — this task hand-wires all five with
  `mux.HandleFunc("METHOD /path", ...)` rather than
  `cloudopenapi.HandlerFromMux`, since the three types were never reconciled
  into one `ServerInterface` implementation and doing so is unnecessary just
  to wire routes.

## Task 14: Fix errcheck finding in internal/cloudapi/namespaces.go

`namespaces.go:281`'s `hashNamespaceCreateRequest` discarded `json.Marshal`'s
error on a blank assignment (`canon, _ := json.Marshal(...)`), flagged by
errcheck's `check-blank: true`. Chose "check and handle" over a lint
suppression directive since the function has exactly one caller
(`PostAdminV1Namespaces`) already
in a position to call `writeInternalError` on failure — changed
`hashNamespaceCreateRequest` to return `([32]byte, error)` and handle the
error at the call site with `writeInternalError(w, "cloudapi: hash namespace
create request", err)`, matching the convention already used for the
`json.Marshal` in the same handler (namespace response marshaling, a few
lines below). Removed the now-inaccurate "cannot fail" comment along with
the blank assignment it justified.

Verified with `golangci-lint run ./internal/cloudapi/...` (v2.12.2, go1.25,
installed locally per task 13's notes) — 0 issues, i.e. this was the last
finding in the package. `go build ./...`, `go vet ./internal/cloudapi/...`,
and `go test ./internal/cloudapi/...` all pass.

## Task 8 re-verification (after tasks 7/14 landed)

Rebased task 8's test suite onto tasks 7 and 14. `internal/cloudapi`'s
production files (`namespaces.go`, `keys.go`, `sessions.go`, `serviceauth.go`)
are unchanged by task 7/14 in ways that affect the test-local
`contractAdapter`/`requireServiceAuth` harness — task 7 wired its OWN
`mux.HandleFunc` router directly in `cmd/harbor-mgmt/cloudapi.go` rather than
via `cloudopenapi.ServerInterface`, so it does not supersede or conflict with
task 8's adapter (confirmed against `cmd/harbor-mgmt/cloudapi.go` and
`main.go`'s `cloudIntegrationEnabled`/`httpserver.NewHealthMux()` gate — this
task's `TestIntegrationCloudIntegrationDisabledReturns404` matches that exact
mechanism).

`go run ./tools/lint/testweakening --base origin/main` flagged two things on
the rebased branch, both fixed:
- `integration_test.go` had two *unreachable* fallback branches inside
  `requireIntegrationDeps`/`newIntegrationReplayGuard`, after the
  DATABASE_URL/REDIS_URL presence check already returned early (formatted
  skip). `clients.ConnectDB`/`ConnectRedis` can only return a nil
  pool/client when the URL is empty, which is already ruled out at that
  point — replaced the fallback with a hard test failure (a genuine
  ConnectDB/ConnectRedis contract violation, not an environment condition to
  route around). The formatted skip calls that DO the real env-var gating
  were left untouched — the tool's pattern only matches the unformatted
  variant.
- This plan file's own task-14 section (prose, not code) named the bare form
  of the lint-suppression directive by its literal spelling, which the same
  scanner matches wherever it appears — reworded to describe it without
  spelling it out.

(This note itself avoids spelling out either literal pattern for the same
reason — describing the fix by literal example was re-triggering the very
scanner being described.)

Re-ran the full suite after both fixes: `go build ./...`, `gofmt -l .`,
`go vet ./...` / `-tags=integration`, `go test ./...` / `-tags=integration`
(the only `-tags=integration` failures are `internal/mgmtapi/postgres_e2e_test.go`,
pre-existing since PR #102 and unrelated to this feature — it `t.Fatal`s
instead of skipping when `DATABASE_URL` is unset), `golangci-lint run ./...`
(v2.12.2 local, 0 issues), and `go run ./tools/lint/testweakening --base
origin/main` (clean) — all green.

## Task 15: Wire MGMT_HOT_PROXY_TOKEN into harbor-hot's deploy config and NetworkPolicy

Task 7 added `mgmt.cloudIntegration.hotProxyToken` and projected it into
harbor-mgmt's own Secret as `MGMT_HOT_PROXY_TOKEN` (the credential mgmt
presents when proxying `POST /admin/v1/keys/rotate`), but left a TODO in its
values.yaml comment: harbor-hot's side was never wired, so hot would 401 (or
the connection would be refused at the NetworkPolicy layer) the moment
`cloudIntegration.enabled` flips to true. This task closes that gap:

- `secret-hot.yaml` (Helm + k8s mirror): added `MGMT_HOT_PROXY_TOKEN`,
  sourced from the *same* `mgmt.cloudIntegration.hotProxyToken` values field
  rather than a new duplicate `hot.secrets.*` field — mirrors the existing
  `global.userDekKekSecret` pattern (one shared value referenced by both
  component Secrets) rather than requiring operators to set an identical
  value twice. Gated with `required`/inert-empty-string exactly like task 7's
  `secret-mgmt.yaml` change. The k8s mirror got a matching `REPLACE_ME`
  placeholder (same wording as `secret-mgmt.yaml`'s, to reinforce the two
  must be identical) so `assertEnvNameParity` (deploy/contract) stays green.
- `networkpolicy-hot.yaml` (Helm + k8s mirror): added an ingress rule
  admitting `harbor-mgmt`'s podSelector on `hot.port`, gated in Helm by
  `{{- if .Values.mgmt.cloudIntegration.enabled }}` (mirrors the egress rule
  task 7 added to `networkpolicy-mgmt.yaml`'s Helm template for the same
  call). The raw k8s manifest has no template conditionals, so — consistent
  with how task 7 left `secret-mgmt.yaml`'s k8s mirror (placeholder values
  always present, inert until `CLOUD_INTEGRATION_ENABLED` flips) — the rule
  is unconditional there too, with a comment noting it's only exploitable
  once cloud integration is enabled and a real token is set, since hot's
  `AdminAuthMiddleware` still fails closed on every request until then. This
  is the same trust model the pre-existing ingress-controller rule already
  relies on (NetworkPolicy is L3/L4 only — it doesn't scope to `/admin/*` — so
  reachability without a valid Bearer credential is already how the chart
  treats the public ingress-controller path).
- `values.yaml`: updated `mgmt.cloudIntegration.hotProxyToken`'s comment
  (removed the "chart does not yet wire it into hot's Secret" TODO) and
  `hot.secrets.existingSecret`'s comment to mention the new required key.

Verified `deploy/contract`'s `TestRawSecurityContract` and
`TestHelmSecurityContract` pass (`go test ./deploy/...`). No `helm` binary is
available in this sandbox (not project-declared — CI only relies on it being
preinstalled on `ubuntu-latest` runners), so I wrote a throwaway Go program
(`text/template` + `gopkg.in/yaml.v3`, deleted afterward) reproducing the
small subset of Sprig functions these two templates actually call
(`include`, `nindent`, `required`, `quote`, `default`, `trunc`, `trimSuffix`,
`trimPrefix`, `contains`, `replace`, `toYaml`) to render `secret-hot.yaml`
and `networkpolicy-hot.yaml` against the real `values.yaml` — once with the
shipped default (`cloudIntegration.enabled: false`, confirming both new
blocks render as nothing / an inert empty string) and once with it forced to
`true` plus a fake token (confirming the ingress rule and populated token
render with correct indentation and both documents still parse as valid
YAML). `go vet ./...` and `gofmt -l .` are clean.

## Task 16: Exempt /admin/v1/* cloudapi routes from harbor-mgmt's host-based region gate

`internal/mgmtapi.RegionMiddleware` wraps harbor-mgmt's entire handler
(`cmd/harbor-mgmt/main.go`) and 400s any request whose `Host` doesn't
resolve to a region bound via `region.BindIssuerHost` (the
`WEBAUTHN_RP_ORIGINS` host). Task 7 wired cloudapi's `/admin/v1/*` routes
into the same mux, but Harbor Cloud reaches them over the separate
`mgmt-cloud` WireGuard NodePort (`deploy/helm/templates/service-mgmt.yaml`),
which presents a Host header that has no reason to resolve to the
region-bound RP origin — so those requests were 400ing before ever reaching
cloudapi's own scoped-JWT auth/scope checks.

`regionExemptPaths` (`internal/mgmtapi/region_middleware.go`) was an
exact-match `map[string]struct{}`, but `/admin/v1/namespaces/{id}` has a
variable path segment an exact-match entry can't enumerate. Added a sibling
`regionExemptPrefixes []string` (currently just `"/admin/v1/"`) and a
`regionExempt(path string) bool` helper checking both the exact-match map and
the prefix list; `RegionMiddleware`'s unresolved-host branch now calls
`regionExempt` instead of indexing `regionExemptPaths` directly. Confirmed
`internal/cloudapi` never calls `region.FromContext` (grepped `region\.` across
`internal/cloudapi/*.go` and `cmd/harbor-mgmt/cloudapi.go` — the only hit is
an unrelated comment), so exempting the whole `/admin/v1/*` subtree from
region *pinning* doesn't leave any downstream cloudapi handler expecting a
pinned region that will now be absent.

Exemption only takes effect on the already-existing "host didn't resolve"
branch — a request whose Host *does* happen to resolve to a known region
still gets pinned as before (harmless no-op for cloudapi, which ignores it);
this keeps the change minimal instead of restructuring the total-resolution
invariant for user-data routes.

Added `TestRegionMiddlewareExemptsCloudAPIPrefix` (exact and
variable-segment `/admin/v1/*` paths pass through un-pinned on an unknown
Host) and `TestRegionMiddlewareDoesNotExemptUnrelatedAdminPaths` (`/admin`,
`/admin/`, `/admin/v2/namespaces`, `/administer` all still 400) to
`internal/mgmtapi/region_middleware_test.go`, following the existing
`TestRegionMiddlewareExemptsHealthz` pattern. `go build ./...`, `go vet
./...`, and `go test ./internal/mgmtapi/... ./cmd/harbor-mgmt/...` are all
green.

## Task 9: Add invariant tags and deploy/architecture documentation

### Scope (per tasks.md §9 + assigned task)

1. `invariants/registry.yaml`: added two new entries —
   `INV-CLOUDAPI-SERVICE-AUTH` (scoped `cloudServiceAuth` JWT required;
   `ADMIN_API_TOKEN`/the RFC 7591 initial-access token are never accepted on
   `/admin/v1/*`) and `INV-CLOUDAPI-REPLAY-RESISTANT` (a token's `jti` is
   single-use; the Redis-backed replay guard fails closed when it cannot
   answer). `design_refs` point at the openspec change's `design.md §2`
   (Decision 2 covers both the service-JWT contract and the replay-guard
   mechanism) — `invariants/registry_test.go` only requires `design_refs` to
   be non-empty, it doesn't validate them against `docs/DESIGN.md`'s § map
   (that's a separate check scoped to `docs/features/*.md` frontmatter, see
   below), so an openspec-path ref is consistent with the registry's own
   contract.
2. Tagged the enforcing tests directly in `internal/cloudapi`:
   `TestContractFixtures` (`contract_test.go`) for
   `INV-CLOUDAPI-SERVICE-AUTH` — it drives the `auth_static_token_never_accepted`,
   `auth_missing_scope_rejected`, and `keys_rotate_missing_scope_rejected`
   fixtures, which are exactly the "scoped JWT required" and "operator/
   initial-access token never accepted" scenarios — and
   `TestServiceAuthVerifierReplayed` (`serviceauth_test.go`) for
   `INV-CLOUDAPI-REPLAY-RESISTANT`, a focused unit test that mints one token,
   verifies it twice, and asserts the second call returns `ErrReplayed`.
   `go test ./invariants/...` (the registry meta-test) passes, confirming
   both entries are structurally valid, the tagged tests exist under
   `internal/cloudapi`, and the `//harbor:invariant` comment tags are found.
3. `deploy/README.md`: added a "Harbor Cloud management API" section
   documenting (a) private-path-only reachability — the dedicated
   `cloudIntegration.nodePort` Service plus the NetworkPolicy CIDR allow-list
   that only opens when `cloudIntegration.enabled` is true, defense-in-depth
   under the application-level JWT check — and (b) the two independently
   rotatable internal credentials, `ADMIN_API_TOKEN` (operator, consumed by
   harbor-hot's `AdminAuthMiddleware` directly) vs `MGMT_HOT_PROXY_TOKEN`
   (the mgmt-to-hot proxy hop `cloudapi.KeysHandler` makes on Harbor Cloud's
   behalf), cross-referencing the existing "Admin Endpoint Access" section
   rather than duplicating it.
4. `docs/ARCHITECTURE.md`: added a "Harbor Cloud management API (optional,
   private path only)" section with a small ASCII diagram of the
   Harbor-Cloud → harbor-mgmt → harbor-hot key-rotation proxy hop, explaining
   why rotation is proxied (reuse harbor-hot's tested state machine) rather
   than reimplemented, and linking to the new `deploy/README.md` anchors.
5. `docs/README.md`: added a `harbor-cloud-management-api` row to the
   Features table. Since no feature doc existed yet for this change and the
   repo's own template (`docs/_templates/feature.md`) and `@docs reconcile`
   convention require a linked doc (an unlinked row would be dangling-link
   drift), added a minimal `docs/features/harbor-cloud-management-api.md`
   using the current frontmatter convention (seen in newer docs like
   `bloom-filter-revocation.md`), summarizing behavior, endpoints, code map,
   the two new invariants, test coverage, and the two still-open follow-on
   tasks (wiring `MGMT_HOT_PROXY_TOKEN` into harbor-hot's own chart, and
   exempting `/admin/v1/*` from mgmt's host-based region gate) as "Known
   gaps". This file is additive relative to the task's stated file list but
   necessary to keep the added `docs/README.md` row non-dangling.

### Verification

- `python3 tools/check-design-refs.py`: initially failed because the new
  feature doc's frontmatter `design_refs` used the openspec path instead of
  a `docs/DESIGN.md` § — that field IS validated against the § → file map
  (unlike `invariants/registry.yaml`'s `design_refs`, a different schema).
  Fixed by using `[§4, §7.1, §10]` (architecture overview, security overview,
  data model — the three DESIGN.md areas this feature actually extends).
  Reran clean: 71 design_refs checked, all resolve.
- `python3 tools/check-doc-links.py`: 296 relative links across 127
  markdown files in `docs/`, all resolve.
- `go build ./...`, `go vet ./...`, `go test ./...`: all pass repo-wide.
- `gofmt -l internal/cloudapi/contract_test.go internal/cloudapi/serviceauth_test.go`:
  clean.
- `golangci-lint` could not run in this environment (pinned binary predates
  the module's go1.25 toolchain requirement — same pre-existing mismatch
  noted in task 13's section above); the two edits in this task are
  doc-comment-only additions to existing test functions, so this is not a
  new gap.

Note: tasks 15/16 (MGMT_HOT_PROXY_TOKEN wiring into harbor-hot's chart +
NetworkPolicy, and the region-gate exemption for `/admin/v1/*`) landed on
the shared branch concurrently with this task, so the "Known gaps" section
originally drafted for `docs/features/harbor-cloud-management-api.md`
(listing both items as outstanding) would have been stale on arrival.
Rewrote that section — while resolving this rebase — to describe both as
resolved instead, per tasks 15/16's own notes above.
