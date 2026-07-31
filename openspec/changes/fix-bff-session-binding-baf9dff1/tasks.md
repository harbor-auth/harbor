# Tasks: BFF login session fixation fix (C3 + M2)

> Plan: `docs/plans/fix-bff-session-binding.md`  
> Audit: `docs/plans/audit-2026-07-30-wiring-and-auth.md` findings C3 + M2

## Prerequisites

- [ ] `internal/bff/session.go` — `BFFSessionStore` and `BFFSessionRecord` types exist
- [ ] `internal/bff/cookie.go` — `SetBFFCookie`, `ReadBFFCookie`, `ClearBFFCookie` exist
- [ ] `internal/oidcapi/authorize.go` — `authorizeWithBFFSession` and `GetAuthorizeComplete` exist
- [ ] `internal/bff/login.go` — `LoginHandler` with `BeginLogin` and `FinishLogin` exists

## Implementation

### 1. BFFSessionRecord — add BrowserNonceHash field

- [ ] `internal/bff/session.go`: add `BrowserNonceHash []byte` field to `BFFSessionRecord`
- [ ] `internal/bff/session_redis.go`: verify JSON round-trip of `[]byte` field (automatic via `encoding/json`)

### 2. Browser nonce helpers — cookie.go

- [ ] `internal/bff/cookie.go`: add `NonceCookieName`, `NewBrowserNonce()`, `HashNonce()`,
      `SetBFFNonceCookie()`, `ReadBFFNonceCookie()`, `ClearBFFNonceCookie()`, `NonceMatches()`
- [ ] Use `crypto/sha256` + `crypto/subtle.ConstantTimeCompare` in `NonceMatches`

### 3. Mint nonce at /authorize (oidcapi/authorize.go)

- [ ] In `authorizeWithBFFSession`: call `bff.NewBrowserNonce()` after minting `requestID`
- [ ] Store `bff.HashNonce(nonce)` as `BFFSessionRecord.BrowserNonceHash`
- [ ] Call `bff.SetBFFNonceCookie(w, nonce, s.bffSessionTTL)` before the login redirect
- [ ] Fail closed with error page on CSPRNG failure

### 4. Nonce gate at BeginLogin and FinishLogin (bff/login.go)

- [ ] `BeginLogin`: after `Get` session, if `len(session.BrowserNonceHash) > 0`, read nonce
      cookie via `ReadBFFNonceCookie`, check `NonceMatches`; refuse 4xx on mismatch
- [ ] `FinishLoginWithParsedData`: same gate before `SetUser`
- [ ] M2 fix: `LoginHandler` accepts `authorizeCompleteURL string`; build absolute redirect
      `authorizeCompleteURL + "?request_id=" + requestID` in `FinishLoginWithParsedData`

### 5. Nonce gate at /authorize/complete (oidcapi/authorize.go)

- [ ] `GetAuthorizeComplete`: after `Get` session, if `len(session.BrowserNonceHash) > 0`,
      check nonce cookie; on mismatch, render error page (no redirect)
- [ ] Clear both `__Host-harbor-bff` and `__Host-harbor-bff-nonce` after code issuance

### 6. Wire AUTHORIZE_COMPLETE_URL (cmd/harbor-mgmt/main.go)

- [ ] Read `authorizeCompleteURL := os.Getenv("AUTHORIZE_COMPLETE_URL")`
- [ ] Fail closed at boot if empty
- [ ] Pass to `bff.NewLoginHandler(sessions, webauthn, resolver, authorizeCompleteURL)`

### 7. Document topology (deploy/README.md)

- [ ] Document the single-public-host / path-routed ingress requirement
- [ ] Explain `__Host-` prefix constraint and why split-host is not supported

## Tests

- [ ] `TestSecurity_SessionFixation_AttackerMintedRequestID` — headline fixation regression:
      attacker session + victim browser (no nonce) → `BeginLogin` refuses; no code issued
- [ ] `TestSecurity_BeginLogin_RefusesWithMissingNonce` — missing cookie → 4xx, no Location
- [ ] `TestSecurity_BeginLogin_RefusesWithWrongNonce` — wrong cookie → 4xx, no Location
- [ ] `TestSecurity_FinishLogin_RefusesWithMissingNonce` — missing nonce at FinishLogin
- [ ] `TestSecurity_FinishLogin_RefusesWithWrongNonce` — wrong nonce at FinishLogin
- [ ] `TestSecurity_NonceNeverInResponseBody` — nonce not in response body or Location header
- [ ] `TestInMemory_BrowserNonceHashRoundTrip` — in-memory store round-trips BrowserNonceHash
- [ ] `TestRedis_BrowserNonceHashRoundTrip` — Redis store round-trips BrowserNonceHash
- [ ] `TestGetAuthorizeComplete_NonceMissing` — gate at /authorize/complete
- [ ] `TestGetAuthorizeComplete_NonceWrong` — gate at /authorize/complete
- [ ] E2E: happy path with AUTHORIZE_COMPLETE_URL set completes end-to-end

## Validation

- [ ] `gofmt -l ./internal/bff/...` — clean
- [ ] `go build ./...`
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate fix-bff-session-binding-baf9dff1 --strict`
