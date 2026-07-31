# Tasks: fix-bff-session-binding

## Prerequisites

- `internal/bff/` familiar with `BFFSessionRecord`, `BFFSessionStore`, `LoginHandler`
- `internal/oidcapi/authorize.go` `authorizeWithBFFSession` function
- `cmd/harbor-mgmt/main.go` startup logic
- `deploy/README.md` and Helm chart

## Implementation

### Task 1: Add `BrowserNonceHash` to `BFFSessionRecord` and stores

Files: `internal/bff/session.go`, `internal/bff/session_redis.go`, `internal/bff/session_test.go`, `internal/bff/session_redis_test.go`

- Add `BrowserNonceHash []byte` field to `BFFSessionRecord` (exported for JSON)
- In-memory store: no code change needed (field rides on struct)
- Redis store: additive JSON field, existing sessions get zero value on read (safe)
- Update Redis store tests to verify round-trip of `BrowserNonceHash`

### Task 2: Add nonce helpers to `cookie.go`

Files: `internal/bff/cookie.go`, `internal/bff/cookie_test.go`

- Add `NonceCookieName = "__Host-harbor-bff-nonce"`
- Add `NewBrowserNonce() ([]byte, error)` — 32-byte CSPRNG
- Add `HashNonce(nonce []byte) []byte` — `sha256.Sum256`
- Add `SetBFFNonceCookie(w, nonce []byte, maxAge time.Duration)`
- Add `ReadBFFNonceCookie(r *http.Request) []byte`
- Add `ClearBFFNonceCookie(w http.ResponseWriter)`
- Add `NonceMatches(cookieNonce, storedHash []byte) bool` — `subtle.ConstantTimeCompare(sha256(cookieNonce), storedHash) == 1`
- Unit tests for all helpers

### Task 3 (test-first): Write failing fixation regression test

Files: `internal/bff/security_test.go`

Add `TestSecurity_SessionFixation_AttackerMintedRequestID`: attacker creates session with `BrowserNonceHash` set; victim browser has NO nonce cookie (or wrong one); `BeginLogin` MUST return 400 with no `Location` header. Name must make the fixation regression obvious.

Also add:
- `TestSecurity_MissingNonceCookie_BeginLogin` — missing nonce → 400
- `TestSecurity_WrongNonceCookie_BeginLogin` — wrong nonce → 400
- `TestSecurity_MissingNonceCookie_FinishLogin` — missing nonce → 400 (no SetUser)
- `TestSecurity_WrongNonceCookie_FinishLogin` — wrong nonce → 400 (no SetUser)
- `TestSecurity_NonceCookieNeverInResponseBody` — nonce absent from all response bodies

These tests fail before implementation tasks 4-5 are done.

### Task 4: Mint nonce at `/authorize` (harbor-hot)

Files: `internal/oidcapi/authorize.go`, `internal/oidcapi/authorize_bff_test.go`

- In `authorizeWithBFFSession`: generate nonce via `bff.NewBrowserNonce()`; compute `bff.HashNonce(nonce)`; set `record.BrowserNonceHash` before `bffSessions.Create`; call `bff.SetBFFNonceCookie(w, nonce, s.bffSessionTTL)` BEFORE the redirect
- CSPRNG failure → `writeAuthorizeErrorPage(w)` (no redirect, no session)
- Update `TestAuthorize_BFFFlow_RedirectsToLogin`: assert `__Host-harbor-bff-nonce` cookie is present and non-empty; assert the stored session's `BrowserNonceHash` is set

### Task 5: Enforce nonce gate in `BeginLogin` and `FinishLogin`

Files: `internal/bff/login.go`, `internal/bff/login_test.go`, `internal/bff/security_test.go`

- **`BeginLogin`**: remove the `SetBFFCookie(w, requestID, DefaultCookieMaxAge)` call; add nonce read + `NonceMatches` check BEFORE the WebAuthn ceremony; refuse 400 on mismatch/absence
- **`FinishLoginWithParsedData`**: add nonce read + `NonceMatches` check BEFORE `h.sessions.SetUser`; refuse 400 on mismatch/absence
- Update `TestLoginHandler_BeginLogin_HappyPath`: seed a `BrowserNonceHash` and matching nonce cookie
- Update `TestLoginHandler_FinishLogin_HappyPath`: same
- Makes Task 3 tests pass

### Task 6: Enforce nonce gate in `GetAuthorizeComplete`

Files: `internal/oidcapi/authorize.go`, `internal/oidcapi/authorize_bff_test.go`

- In `GetAuthorizeComplete`: read nonce cookie; `NonceMatches` check before `AuthorizeWithUser`; failure → `writeAuthorizeErrorPage` (no Location)
- On success: call `bff.ClearBFFNonceCookie(w)` alongside existing `bff.ClearBFFCookie(w)`
- Add `TestAuthorizeComplete_MissingNonce_ErrorPageNoCode`
- Add `TestAuthorizeComplete_WrongNonce_ErrorPageNoCode`
- Update existing `TestAuthorizeComplete_*` tests to seed `BrowserNonceHash` + matching nonce cookie

### Task 7: Absolute redirect (M2) in `LoginHandler`

Files: `internal/bff/login.go`, `internal/bff/login_test.go`, `cmd/harbor-mgmt/main.go`, `cmd/harbor-mgmt/bff.go`

- Add `authorizeCompleteURL string` field to `LoginHandler`
- Update `NewLoginHandler` to accept `authorizeCompleteURL string` as parameter
- In `FinishLoginWithParsedData`: use `authorizeCompleteURL` (+ `?request_id=` + requestID) instead of the relative string
- In `cmd/harbor-mgmt/main.go`: read `AUTHORIZE_COMPLETE_URL` env; validate it is a non-empty valid URL; pass to `NewLoginHandler`; fail closed with logged error + `os.Exit(1)` if unset in production (when `DATABASE_URL` is set)
- Update `TestLoginHandler_FinishLogin_HappyPath` to verify the Location is an absolute URL

### Task 8: Deploy documentation and config

Files: `deploy/README.md`, `deploy/helm/values.yaml`, `deploy/helm/templates/configmap-mgmt.yaml`, `deploy/k8s/configmap-mgmt.yaml`, `e2e/docker-compose.yml`

- Add a **BFF Topology** section to `deploy/README.md` explaining: single public hostname, path-routed ingress (`/login*` → mgmt, rest → hot), why split-host is unsupported
- Add `mgmt.authorizeCompleteURL` to Helm values and wire it as `AUTHORIZE_COMPLETE_URL` in `configmap-mgmt.yaml`
- Add `AUTHORIZE_COMPLETE_URL` to the k8s `configmap-mgmt.yaml`
- Set `AUTHORIZE_COMPLETE_URL` in `e2e/docker-compose.yml` pointing at harbor-hot's `/authorize/complete`

## Tests

### Task 9: E2E happy path with nonce

Files: `e2e/bff_login_test.go` (or `flow_test.go` if BFF e2e already exists)

- Verify the full BFF login flow (authorize → login → login/complete → authorize/complete → token) completes end-to-end
- Assert the `__Host-harbor-bff-nonce` cookie is cleared after `authorize/complete`
- Assert the raw nonce value never appears in any response body throughout the flow

## Validation

```bash
# Build and vet
go build ./...
go vet ./...

# Unit tests (all must pass)
go test ./internal/bff/... -v -run TestSecurity_SessionFixation_AttackerMintedRequestID
go test ./internal/bff/...
go test ./internal/oidcapi/...

# Full suite
go test ./...

# Agent check (docs integrity, arch tests)
make agent-check

# OpenSpec verification (mandatory)
openspec validate fix-bff-session-binding-baf9dff1 --strict
```
