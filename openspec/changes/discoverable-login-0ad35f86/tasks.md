# Tasks: Discoverable Login

**Change ID:** discoverable-login-0ad35f86

## Prerequisites

- go-webauthn v0.17.4 confirmed (has `BeginDiscoverableLogin`, `ValidatePasskeyLogin`, `DiscoverableUserHandler`)
- BFF login flow landed (`bff-session-middleware`)
- No DB migrations required

## Implementation

- [ ] Add `BeginDiscoverableLogin(ctx) (*protocol.CredentialAssertion, string, error)` to `internal/webauthn/service.go`
- [ ] Add `FinishDiscoverableLogin(ctx, sessionKey, body io.Reader) (userID string, cred *Credential, err error)` to `internal/webauthn/service.go`
  - Use `s.wa.ValidatePasskeyLogin` with a `DiscoverableUserHandler` that calls `s.store.GetUser(ctx, userHandle)`
  - Preserve clone detection (`CloneWarning` check + `UpdateCredential`)
  - Return `base64.RawURLEncoding.EncodeToString(user.WebAuthnID())` as userID
- [ ] Extend `bff.WebAuthnService` interface with `BeginDiscoverableLogin` and `FinishDiscoverableLogin` in `internal/bff/login.go`
- [ ] Add `ErrDiscoverable` sentinel error in `internal/bff/login.go`
- [ ] Add `DiscoverableUserResolver` struct implementing `UserResolver` in `internal/bff/login.go`
- [ ] Branch `LoginHandler.BeginLogin` on `errors.Is(err, ErrDiscoverable)` → call `BeginDiscoverableLogin`
- [ ] Branch `LoginHandler.FinishLoginWithParsedData` to call `FinishDiscoverableLogin` when resolver is discoverable
- [ ] Delete `devUserResolver` from `cmd/harbor-mgmt/bff.go`
- [ ] Remove `byKey map[string][]byte` and `mu sync.Mutex` from `bffWebAuthnAdapter`
- [ ] Add `BeginDiscoverableLogin` and `FinishDiscoverableLogin` to `bffWebAuthnAdapter` in `cmd/harbor-mgmt/bff.go`
- [ ] Wire `bff.DiscoverableUserResolver{}` in place of `devUserResolver{}` in `cmd/harbor-mgmt/main.go` or `bff.go`
- [ ] Add `WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired)` to `BeginRegistration` in `internal/webauthn/service.go`

## Tests

- [ ] `internal/webauthn/service_test.go`: `TestService_BeginDiscoverableLogin` — verify empty `allowCredentials`, no userHandle in session
- [ ] `internal/webauthn/service_test.go`: `TestService_FinishDiscoverableLogin_UnknownHandle` — verify unknown handle returns error
- [ ] `internal/webauthn/service_test.go`: `TestService_FinishDiscoverableLogin_NoSession` — verify missing session returns `ErrSessionNotFound`
- [ ] `internal/bff/login_test.go`: `TestLoginHandler_BeginLogin_Discoverable` — verify `BeginDiscoverableLogin` is called, not `BeginLogin(userID)`
- [ ] `internal/bff/login_test.go`: `TestLoginHandler_BeginLogin_UserIDParamIgnored` — verify `?user_id=` has no effect
- [ ] `internal/bff/login_test.go`: `TestLoginHandler_FinishLogin_Discoverable` — verify `FinishDiscoverableLogin` is called, user resolved from response

## Validation

- [ ] `go build ./internal/webauthn/... ./internal/bff/... ./cmd/harbor-mgmt/...`
- [ ] `go vet ./internal/webauthn/... ./internal/bff/... ./cmd/harbor-mgmt/...`
- [ ] `go test ./internal/webauthn/... ./internal/bff/... ./cmd/harbor-mgmt/...`
- [ ] `make agent-check`
- [ ] `openspec validate discoverable-login-0ad35f86 --strict` (if openspec CLI available)
