# Design: End-session / RP-Initiated Logout

## Handler pipeline

```
GET /end_session
  ?id_token_hint=<jwt>
  &post_logout_redirect_uri=<uri>
  &state=<opaque>
       │
       ▼
  1. Parse id_token_hint
     └── oidc.JWTVerifier.Verify(ctx, tokenString)
         ├── invalid/missing → 400 invalid_request
         └── valid → extract sub (userID), azp (clientID)
       │
       ▼
  2. Validate post_logout_redirect_uri
     └── registry.Get(ctx, clientID).LogoutURIs.Contains(uri)
         ├── not registered → 400 invalid_request
         └── ok → continue
       │
       ▼
  3. Revoke grant family
     └── SessionRevoker.RevokeSessionsByUserClient(ctx, userID, clientID)
       │
       ▼
  4. Redirect
     ├── post_logout_redirect_uri set → redirect to uri + "?state=" + state
     └── not set → redirect to issuer + "/logged-out"
```

## New types

### `internal/oidcapi/end_session.go`

```go
// SessionRevoker is the narrow interface end_session needs over SessionStore.
type SessionRevoker interface {
    RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error
}

func (s *Server) GetEndSession(w http.ResponseWriter, r *http.Request, params openapi.GetEndSessionParams)
func (s *Server) PostEndSession(w http.ResponseWriter, r *http.Request)
```

### Discovery update (`internal/oidcapi/discovery.go`)

```go
EndSessionEndpoint: strPtr(base + "/end_session"),
```

### Server config additions

```go
type Config struct {
    // ... existing ...
    SessionRevoker SessionRevoker  // drives grant revocation on logout
    ClientRegistry ClientLookup    // to validate logout_uri
}
```

## Cross-binary note

The `end_session_endpoint` is on `harbor-hot`. Grant revocation via
`RevokeSessionsByUserClient` writes to the DB (sessions table) and feeds the
revocation outbox — both accessible from `harbor-hot` with a DB pool.
BFF session cookies are `harbor-mgmt`-scoped and expire naturally (5-min TTL).
