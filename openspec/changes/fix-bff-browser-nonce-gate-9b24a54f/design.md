# Design: Required browser nonce hash at BFF flow gates

Each browser-nonce gate performs two sequential checks:

1. Refuse the request when `BrowserNonceHash` is absent.
2. Read the existing nonce cookie and use `NonceMatches` to compare it with the
   stored hash, refusing a missing, malformed, or mismatched cookie.

The absence check occurs before any WebAuthn action, session mutation,
authorization-code issuance, or redirect. The normal `/authorize` path remains
unchanged: it generates the nonce, stores `HashNonce(nonce)` in the session, and
sets the nonce cookie used by subsequent login and completion requests.
