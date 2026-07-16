# Proposal: OIDF OP Conformance Suite Compliance

## Problem

The OpenID Foundation (OIDF) OP conformance suite validates that an OpenID
Provider correctly implements the OIDC Core specification. Harbor's id_tokens
were missing several required/recommended claims (`jti`, `auth_time`, `azp`,
`acr`, `amr`), the `/userinfo` endpoint was unimplemented, and the discovery
document lacked fields the suite checks (`userinfo_endpoint`,
`claims_supported`, `token_endpoint_auth_methods_supported`).

These gaps caused the OIDF Basic OP certification plan to fail, blocking
conformance certification and creating an honest-red release gate (§1.8).

## Proposed Solution

- Add missing id_token claims: `jti` (unique token ID), `auth_time` (when user
  authenticated), `azp` (authorized party), `acr`/`amr` (authentication context
  and methods).
- Implement `GET /userinfo` endpoint that validates Bearer access tokens and
  returns the pairwise `sub` (PPID) plus scope-gated email claims.
- Update discovery metadata with `userinfo_endpoint`, `claims_supported`, and
  `token_endpoint_auth_methods_supported: ["none"]` (public-client PKCE).
- Update `conformance/assert-pass.sh` with required-modules gate to ensure core
  OIDF modules are present AND passing.

## Non-Goals

- Dynamic Client Registration (Harbor uses curated registry, §3.1).
- Implicit/Hybrid/ROPC flows (OAuth 2.1: code+refresh only).
- JAR/PAR (`request`/`request_uri` parameters).
- `client_secret_*` token-endpoint auth (public-client provider).

## Success Criteria

- [ ] id_token contains `jti`, `auth_time`, `azp`, `acr`, `amr` claims.
- [ ] `GET /userinfo` returns verified PPID `sub` from Bearer token.
- [ ] Discovery document includes all OIDF-required metadata fields.
- [ ] `conformance/assert-pass.sh` gates on required OIDF modules.
- [ ] OIDC Basic OP certification plan expected to PASS.
