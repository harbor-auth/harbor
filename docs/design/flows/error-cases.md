> **DESIGN §11.7** · [↑ DESIGN index](../../DESIGN.md) · prev: [overview](overview.md) · next: [compliance-and-roadmap](../governance/compliance-and-roadmap.md)

# OIDC Error Cases & Security Validations

Every step of the Authorization Code + PKCE flow (§11.2) has failure modes, and OAuth/OIDC prescribe **exactly** how to signal each one. Getting this right is security-critical: sloppy error handling leaks whether accounts/clients exist, or worse, opens redirect-based token-exfiltration. Harbor follows RFC 6749 (§4.1.2.1, §5.2), OIDC Core, and RFC 6750 to the letter.

## Two error channels

Errors surface on one of two channels depending on *where* they're detected:

- **(a) Authorization-endpoint errors** (`/authorize`) → **302 redirect** back to the RP's **registered** `redirect_uri` with `error`, `error_description`, and the echoed `state` as query parameters.
  - **Critical exception:** if `client_id` is unknown **or** `redirect_uri` is missing/doesn't exactly match a registered URI, Harbor **MUST NOT redirect**. It renders an **error page** in the browser instead. Redirecting an error to an unvalidated URI would let an attacker aim Harbor's response (and any leaked parameters) at a URI they control — an open-redirect / exfiltration vector. The redirect target must be *proven trusted* before it's ever used, even for errors.
- **(b) Token-endpoint errors** (`/token`) → **HTTP 400** (or 401 for client-auth failures) with a JSON body `{ "error": …, "error_description": … }`. No redirect is involved (this is a back-channel call).

A third, RP-side channel exists for **ID-token validation** (`state`, `nonce`, signature): these are enforced by the *RP*, not Harbor — Harbor's job is only to *supply* the bindings correctly (echo `state`, embed `nonce`, sign with a JWKS-published key).

## Authorize phase (`/authorize`)

| Error case | Harbor validation | Response (code · HTTP · channel) |
|---|---|---|
| Unknown `client_id` | Client exists in registry | **Error page**, no redirect (channel a exception) |
| Missing / mismatched `redirect_uri` | **Exact-match** against registered allowlist | **Error page**, no redirect (channel a exception) |
| Missing/invalid `response_type` (not `code`) | Only `code` supported | `unsupported_response_type` · 302 · redirect |
| Client not allowed this flow/scope combo | Client policy check | `unauthorized_client` · 302 · redirect |
| Unknown / disallowed `scope` (missing `openid`, etc.) | Validate against `scopes_allowed` | `invalid_scope` · 302 · redirect |
| Malformed request (missing `state`/`nonce` where required, bad `code_challenge_method`) | Param presence/shape; **PKCE required** (`S256`) | `invalid_request` · 302 · redirect |
| User rejects the consent screen | User action | `access_denied` · 302 · redirect |
| `prompt=none` but no session / consent / interaction needed | Silent-auth check | `login_required` / `consent_required` / `interaction_required` · 302 · redirect |
| Internal fault | — | `server_error` · 302 · redirect |
| Overloaded / maintenance | — | `temporarily_unavailable` · 302 · redirect |

Example authorize-phase error redirect (note the echoed `state`):

```
302 https://app.example.com/callback
      ?error=invalid_scope
      &error_description=The%20requested%20scope%20is%20unknown%20or%20not%20permitted
      &state=xyz789
```

## Token phase (`/token`)

| Error case | Harbor validation | Response (code · HTTP · channel) |
|---|---|---|
| Bad client authentication (confidential client) | Verify `client_secret` / client-auth JWT | `invalid_client` · **401** · JSON (add `WWW-Authenticate` if the client used the `Authorization` header) |
| Expired authorization code | Code TTL (~30–60s) | `invalid_grant` · 400 · JSON |
| **Reused** authorization code | Code is **single-use** | `invalid_grant` · 400 · JSON — **and revoke all tokens minted from that code** (theft signal, see §3.5) |
| **PKCE mismatch** — `SHA256(code_verifier) != code_challenge` | Recompute & compare (constant-time) | `invalid_grant` · 400 · JSON |
| `redirect_uri` / `client_id` don't match the authorize request | Bind code to original params | `invalid_grant` · 400 · JSON |
| Unsupported `grant_type` | Only `authorization_code` / `refresh_token` | `unsupported_grant_type` · 400 · JSON |
| Revoked / unknown / rotated-away refresh token | Lookup + rotation/reuse detection | `invalid_grant` · 400 · JSON (reuse ⇒ revoke the token family) |
| Missing/malformed params | Param validation | `invalid_request` · 400 · JSON |

Example token-endpoint error (single-use code reused):

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "error_description": "Authorization code is invalid, expired, or already used"
}
```

## ID-token / RP-side validation

These are enforced by the **RP** on the tokens Harbor returns; Harbor's responsibility is to make them *verifiable*.

| Error case | Who validates | Harbor's role |
|---|---|---|
| **`state` mismatch** (CSRF) | **RP** compares returned `state` to the value it stored | Harbor **echoes `state` verbatim** on every authorize response (success *and* error); it never interprets it. A mismatch ⇒ the RP drops the response. |
| **`nonce` mismatch** (replay) | **RP** compares the ID token's `nonce` claim to the value it sent in step 1 | Harbor **binds the request `nonce` into the ID token**. This defeats token replay/injection: an attacker can't reuse an old ID token because its `nonce` won't match a fresh request. |
| Bad signature / wrong `kid` | **RP** verifies against `/jwks.json` | Harbor signs with an asymmetric key (ES256/EdDSA) whose public half is published in JWKS (§3.5). |
| `iss` / `aud` / `exp` wrong | **RP** | Harbor sets `iss` = the regional issuer, `aud` = the `client_id`, and a short `exp`. |

## Resource-server / UserInfo (RFC 6750)

When a token is presented to `/userinfo` or an RP's own resource server:

| Error case | Validation | Response |
|---|---|---|
| **Missing** `Authorization` header (no credentials) | Bearer scheme check | `401` + plain `WWW-Authenticate: Bearer` (no `error` code) |
| **Malformed** `Authorization` header | Bearer scheme check | `400` + `WWW-Authenticate: Bearer error="invalid_request"` |
| Expired / revoked / bad-signature token | JWKS verify (or introspection for opaque) | `401` + `WWW-Authenticate: Bearer error="invalid_token"` |
| Token lacks the required scope | Scope check | `403` + `WWW-Authenticate: Bearer error="insufficient_scope"` |

Example `401` for an invalid/expired access token:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  error_description="The access token is expired or has been revoked"
```

## Security invariants (non-negotiable)

- **Exact `redirect_uri` match** against a pre-registered allowlist — and **never** send an error (or anything else) to an unvalidated URI.
- **Authorization codes are single-use**; reuse ⇒ `invalid_grant` **and** revoke every token minted from that code (assume theft, §3.5).
- **PKCE verification is mandatory** for every client — `SHA256(code_verifier)` must equal the stored `code_challenge`.
- **`state` (CSRF) and `nonce` (replay)** are enforced by the RP; Harbor guarantees the bindings (echo `state`, embed `nonce`) on every response.
- **Generic `error_description`s** — never reveal whether a *user account* or *client* exists, or *why* auth failed beyond the standard code (defeats enumeration).
- **Constant-time comparisons** for codes, PKCE challenges, secrets, and tokens.
- **`Cache-Control: no-store`** on all token responses; short code TTLs (~30–60s).
