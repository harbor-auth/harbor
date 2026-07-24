# Design: Discoverable Login

**Change ID:** discoverable-login-0ad35f86

## Architecture

### go-webauthn v0.17.4 API used

```go
// Begin — no user, empty allowCredentials
func (w *WebAuthn) BeginDiscoverableLogin(opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)

// Finish — callback resolves user from userHandle returned by authenticator
type DiscoverableUserHandler func(rawID, userHandle []byte) (User, error)
func (w *WebAuthn) ValidatePasskeyLogin(handler DiscoverableUserHandler, session SessionData, parsed *protocol.ParsedCredentialAssertionData) (User, *Credential, error)
```

### Service layer (`internal/webauthn/service.go`)

```go
// BeginDiscoverableLogin starts a user-less assertion ceremony.
func (s *Service) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)

// FinishDiscoverableLogin validates the assertion and returns the resolved
// user's base64url-encoded handle as userID.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, sessionKey string, body io.Reader) (userID string, cred *gowebauthn.Credential, err error)
```

The `FinishDiscoverableLogin` handler passed to `ValidatePasskeyLogin` calls
`s.store.GetUser(ctx, userHandle)`. An unknown handle maps to the same generic
error path as any other validation failure (§6.5 — no enumeration).

Clone detection is preserved: `cred.Authenticator.CloneWarning` check +
`store.UpdateCredential` after a successful finish (identical to the existing
`FinishLogin` path).

### BFF layer (`internal/bff/login.go`)

```go
// Extended interface — adapter must implement all four methods.
type WebAuthnService interface {
    BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error)
    FinishLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error)
    BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
    FinishDiscoverableLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error)
}

// ErrDiscoverable is returned by DiscoverableUserResolver.ResolveUser to signal
// that BeginDiscoverableLogin should be called instead of BeginLogin.
var ErrDiscoverable = errors.New("bff: use discoverable login")

// DiscoverableUserResolver implements UserResolver for the discoverable path.
type DiscoverableUserResolver struct{}

func (DiscoverableUserResolver) ResolveUser(_ context.Context, _ *http.Request, _ BFFSessionRecord) ([]byte, error) {
    return nil, ErrDiscoverable
}
```

`LoginHandler.BeginLogin` branches on `errors.Is(err, ErrDiscoverable)`:
calls `h.webauthn.BeginDiscoverableLogin(ctx)` instead of
`h.webauthn.BeginLogin(ctx, userID)`.

`LoginHandler.FinishLoginWithParsedData` checks whether the resolver is a
`DiscoverableUserResolver` (via interface type assertion or a `IsDiscoverable()`
method) and calls `h.webauthn.FinishDiscoverableLogin` instead of
`h.webauthn.FinishLogin`.

### Adapter (`cmd/harbor-mgmt/bff.go`)

- **Remove** `devUserResolver` struct and its `ResolveUser` method entirely.
- **Remove** the `byKey map[string][]byte` and `mu sync.Mutex` from
  `bffWebAuthnAdapter` — no longer needed for the discoverable path.
- **Add** `BeginDiscoverableLogin` and `FinishDiscoverableLogin` methods to
  `bffWebAuthnAdapter` that delegate to `a.svc`.
- Wire `bff.DiscoverableUserResolver{}` instead of `devUserResolver{}`.

## Security invariants preserved

| Invariant | How preserved |
|-----------|--------------|
| No client-supplied user identity (§9, §11.1) | `user_id` query param removed; user handle comes only from authenticator assertion |
| No enumeration (§6.5) | Unknown `userHandle` in handler collapses to generic `invalid_request`; same error as bad ceremony |
| Clone detection (§3.1) | `CloneWarning` check + `UpdateCredential` in `FinishDiscoverableLogin` |
| Resident key required | `BeginRegistration` passes `WithResidentKeyRequirement(ResidentKeyRequirementRequired)` |
