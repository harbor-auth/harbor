# Proposal: Fix BFF login session fixation and cross-host redirect (C3 + M2)

> Paired plan: `docs/plans/fix-bff-session-binding.md`

## Problem

Two critical audit findings (audit-2026-07-30-wiring-and-auth.md) in the BFF login flow:

**C3 — Session fixation → account takeover.** `internal/bff/login.go` sets the
browser `__Host-harbor-bff` cookie to whatever `request_id` arrives in the URL
query string. An attacker mints their own `request_id=R` at `/authorize`, lures
the victim to `/login?request_id=R`, and the victim's browser is bound to session
R. After the victim authenticates, `GetAuthorizeComplete` reads `request_id` from
the query string with no cookie comparison, issues a code for the victim, and
redirects it to the attacker's `redirect_uri`.

**M2 — Absolute redirect required.** `internal/bff/login.go:294` builds a
relative `/authorize/complete?...` redirect, which resolves against the
harbor-mgmt origin. The `/authorize/complete` endpoint is registered on
harbor-hot, so this 404s at the last step of every login unless both binaries
share one public hostname.

## Proposed Solution

Introduce a **browser nonce** minted at `/authorize` and proven at every
subsequent step. The nonce binds the BFF session to the specific browser that
initiated the flow:

1. **Mint at `/authorize`**: generate a 256-bit CSPRNG nonce, store its SHA-256
   hash as `BFFSessionRecord.BrowserNonceHash`, set the raw nonce in the
   `__Host-harbor-bff-nonce` cookie before redirecting to `LOGIN_URL`.
2. **Require at `BeginLogin` and `FinishLogin`**: constant-time compare the
   cookie against the stored hash; refuse on mismatch or absence.
3. **Require at `/authorize/complete`**: same gate before `AuthorizeWithUser`.
4. **M2 fix**: absolute `AUTHORIZE_COMPLETE_URL` env var; fail closed at boot.
5. **Document topology**: `__Host-` prefix enforces a single public host.

## Non-Goals

- Changing the WebAuthn ceremony cookie (`harbor_webauthn_session` is already
  one-time-use via `SessionStore.Take`).
- Supporting harbor-hot and harbor-mgmt on separate public hosts with this design
  (the `__Host-` prefix cannot span two different origins).
- Changing token issuance, PPID derivation, or any other auth-code flow steps.

## Success Criteria

- [ ] Attacker-minted `request_id` + victim browser → `/login` refuses; no code issued.
- [ ] Missing cookie / wrong cookie / expired session → uniform refusal, no `Location` header.
- [ ] Happy path completes end-to-end through the e2e harness.
- [ ] Nonce never logged and never appears in a response body.
- [ ] M2: `AUTHORIZE_COMPLETE_URL` is absolute and validated at boot.
- [ ] `make agent-check` clean; `openspec validate fix-bff-session-binding-baf9dff1 --strict` passes.
