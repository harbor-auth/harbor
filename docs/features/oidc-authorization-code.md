---
title: OIDC Authorization Code + PKCE Flow
status: implemented
design_refs: [§3.1, §11.2, §11.7, §1.2]
code:  [internal/oidc/, internal/oidcapi/, cmd/harbor-hot/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/oidc/, internal/oidcapi/]
depends_on: [ppid-identity]
plan: null
last_reconciled: 2026-07-08
---

# OIDC Authorization Code + PKCE Flow

## Summary

Harbor's OpenID Provider hot path: the standard OAuth 2.1 **Authorization Code +
PKCE (S256)** flow (docs/DESIGN.md §3.1, §11.2) with the §11.7 error/security
semantics enforced. The security-critical logic in `internal/oidc` is a **pure
core** (no `net/http`, no DB) — `ValidateAuthorize`, PKCE, and the `/token`
exchange are exhaustively unit-testable without mocks (§1.7). The thin HTTP layer
`internal/oidcapi` satisfies the spec-generated `openapi.ServerInterface`
(`api/openapi/harbor.yaml` is the source of truth, §1.2), and `cmd/harbor-hot`
wires it together. The ID-token `sub` is *intended* to be the per-RP **PPID**
(see [ppid-identity](ppid-identity.md)); today the subject comes from the stubbed
session seam (see Known gaps), so PPID derivation is not yet on the hot path.

## Behavior (as-built)

**`GET /authorize`** — `ValidateAuthorize` runs checks in a deliberate order that
*is* the open-redirect defense and must not be reordered:

1. Unknown `client_id`, **or** a `redirect_uri` that is missing / not an **exact**
   registered match → `ChannelErrorPage`: an HTML error page with **no `Location`
   header** (never redirect to an unproven URI).
2. Only after the redirect target is proven trusted do the rest run, all via
   `ChannelRedirect` (safe 302 back to the RP): `response_type=code` only; scope
   must include `openid` and every scope must be in the client allow-list
   (deny-by-default); **PKCE mandatory, `S256` only** (`code_challenge` required,
   `plain`/empty rejected); `state` required (so it can be echoed).

On success the (stubbed) login/consent step resolves a subject, a **single-use**
authorization code (~60s TTL) is issued and stored, and the browser is 302'd back
with `code` + echoed `state`.

**`POST /token`** — the ordering is the auth-code-DoS defense (§11.7): a request
that fails binding/PKCE must **never burn a valid one-time code**.

1. `ValidateTokenParams` — `grant_type=authorization_code` + required-field
   presence.
2. **Peek** the code (no mutation): not found → `invalid_grant`; already consumed
   → **theft signal** (revoke the code family) + `invalid_grant`.
3. `ValidateTokenExchange` against the *stored* code — client/redirect binding,
   expiry, and PKCE (constant-time S256 compare). On failure it returns
   **without consuming**, so the code stays valid for its real owner.
4. Only then **Consume** (single-use). A lost race on the tombstone still surfaces
   as reuse (revoke + `invalid_grant`). Success mints tokens.

The body is capped at **64 KB** before parsing; every response sets
`Cache-Control: no-store`; error descriptions are generic/PII-free (no
account/client existence disclosure). Every token-phase failure is
`invalid_grant` (400) — expiry, PKCE mismatch, and wrong client are not
distinguished, so nothing leaks which check failed. The `invalid_client` case is
handled as a 401 with `WWW-Authenticate: Basic`, though the current stubbed
client-auth path does not yet exercise it.

**PKCE** — `S256` only; `code_verifier` length is bounded to RFC 7636's 43–128
characters; the compare is constant-time. At `/token` both the length guard and
the mismatch collapse to `invalid_grant`.

**Discovery** — `GET /.well-known/openid-configuration` returns the spec-generated
metadata built from the issuer, baking in Harbor's invariants: **pairwise**
subjects only (§3.2), **ES256/EdDSA** signing only (§7), `code` + `refresh_token`
grants (no implicit/ROPC), and `S256` only. Cached `public, max-age=3600`.
`GET /healthz` is the liveness probe.

## Interfaces / Endpoints

- `GET /authorize` → 302 to the RP (`code`+`state`) or a no-`Location` HTML error
  page.
- `POST /token` (form-encoded) → 200 JSON `TokenResponse`, or a 400/401
  `OAuthError` body.
- `GET /.well-known/openid-configuration` → `OpenIDProviderMetadata`.
- `GET /healthz` → `200 ok`.
- Contract: `api/openapi/harbor.yaml` (`internal/oidcapi` implements the generated
  `openapi.ServerInterface`, compile-time asserted).
- Env vars (`cmd/harbor-hot`): `PORT`, `ISSUER`.

## Code map

| Path | Role |
|---|---|
| `internal/oidc/errors.go` | Package doc, exact OAuth error-code strings, the two error channels, `AuthorizeError`/`TokenError`. |
| `internal/oidc/authorize.go` | Pure `ValidateAuthorize` — open-redirect-safe check ordering + scope validation. |
| `internal/oidc/pkce.go` | S256-only PKCE: challenge compute, constant-time verify, RFC 7636 length guard. |
| `internal/oidc/token.go` | Pure `ValidateTokenParams` / `ValidateTokenExchange` (binding, expiry, PKCE). |
| `internal/oidc/service.go` | `Service` orchestration — `Authorize` + `Token` (peek→validate→consume), session/revocation seams. |
| `internal/oidc/store.go` | `Client`/`AuthCode` values, client registry + tombstoning single-use code store (`Peek`/`Consume`). |
| `internal/oidc/issuer.go` | `TokenIssuer` seam + **SCAFFOLD** unsigned placeholder issuer. |
| `internal/oidc/doc.go` | Package marker. |
| `internal/oidcapi/server.go` | `Server` implementing the spec-generated `openapi.ServerInterface`. |
| `internal/oidcapi/authorize.go` | `GET /authorize` glue — the two-channel error rule (302 vs error page). |
| `internal/oidcapi/token.go` | `POST /token` glue — form parse, 64 KB cap, `no-store`, OAuth error body. |
| `internal/oidcapi/discovery.go` | Discovery document (pairwise / ES256+EdDSA / S256 invariants). |
| `internal/oidcapi/health.go` | `GET /healthz` liveness. |
| `cmd/harbor-hot/main.go` | Wires the flow into harbor-hot (scaffold registry/resolver/issuer/store). |

## Security & privacy invariants

- **Exact `redirect_uri` match; never redirect to an unproven URI (§11.7, §7.4)** —
  enforced by check ordering + `Client.HasRedirectURI` (exact string match).
- **Single-use codes; reuse ⇒ revoke the code family (§11.7, §3.5)** —
  tombstoning store + theft signal at both peek and consume-race.
- **Failed exchange never burns a valid code (§11.7)** — peek → validate →
  consume ordering (auth-code-DoS defense).
- **PKCE mandatory, S256 only, constant-time compare (§3.1, §11.7)** — `plain`
  rejected; verifier length bounded (RFC 7636).
- **`state` echoed verbatim (§11.7)** on both success and redirect-channel error.
- **PII-free, non-enumerating errors (§11.7, §6.5)** — generic descriptions;
  every token failure is `invalid_grant`.
- **`Cache-Control: no-store` on token responses; short code TTL (§11.7).**
- **Discovery advertises only pairwise subjects + asymmetric signing (§3.2, §7)** —
  no `alg:none`/symmetric path is offered.

## Tests

- `internal/oidc/` — pure-core negative tests: authorize check ordering /
  open-redirect defense, scope + PKCE validation, `ValidateTokenExchange`
  (binding/expiry/PKCE), the PKCE length guard, and the CRITICAL
  "failed exchange does not burn the code" + reuse/theft-revocation cases.
- `internal/oidcapi/` — HTTP wire tests: `/authorize` error page carries **no**
  `Location`, state echo, PKCE mismatch → `invalid_grant`, code reuse →
  `invalid_grant`, unsupported grant/response types, discovery document shape,
  `/healthz`, and router wiring.

## Known gaps / TODOs

- **Token signing is a SCAFFOLD** — `placeholderIssuer` returns
  obviously-unsigned tokens; replace with the HSM-backed ES256/EdDSA JWT signer
  published via JWKS (§3.3, §7.3) before any real deployment.
- **Login/consent is stubbed** — `stubSessionResolver` auto-approves a fixed
  subject; the real seam runs passkey login ([webauthn-passkeys](webauthn-passkeys.md)),
  MFA/step-up, the consent screen, and derives the per-RP PPID
  ([ppid-identity](ppid-identity.md)) (§11.2).
- **Stores are in-memory** — the region-local, shared code store and the
  sqlc-backed client registry (§4.4, §10) are not yet wired.
- **Not yet implemented:** `/jwks.json`, `/userinfo`, `/introspect`, `/revoke`,
  and the `refresh_token` grant (advertised in discovery; §3.5).
