# Design: Fail-closed browser nonce gates

## Decision

At each of the three existing checkpoints, reject the session immediately when
`len(session.BrowserNonceHash) == 0`. For a populated hash, continue to call
`ReadBFFNonceCookie` and `NonceMatches` exactly as today. This preserves the
cookie decoder and `crypto/subtle.ConstantTimeCompare` path while eliminating
the fail-open branch.

## Checkpoints

- `LoginHandler.BeginLogin` rejects before resolving a user or setting cookies.
- `LoginHandler.FinishLoginWithParsedData` rejects before WebAuthn completion or
  writing an authenticated user to the session.
- `Server.GetAuthorizeComplete` renders the existing no-redirect error page
  before authorizing a user or issuing a code.

## Testing strategy

Add a regression case at each checkpoint using a valid, unexpired session whose
`BrowserNonceHash` is absent. Assert the handler refuses and that downstream
security-sensitive work does not occur. Keep the full BFF happy-path test, which
starts at `/authorize`, as evidence that newly created sessions receive a hash,
carry the matching cookie through all three gates, and still issue a code.

No visual QA is required because this is backend authorization logic with no
rendered-output change.
