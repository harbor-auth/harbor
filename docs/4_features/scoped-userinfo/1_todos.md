# Scoped UserInfo and explicit account linking

Implement standard OIDC scopes with one canonical grant. Ship `openid`, `email`,
and `offline_access`; defer `profile`, phone and address until Harbor collects
and maintains those fields. Personal claims are returned by UserInfo only.

- [x] A. Canonical consent: remove the secondary consent authority; separate explicit approval from subject resolution; reconnect with a fresh grant ID and stable PPID; merge concurrent approvals atomically.
- [x] B. Bind codes, access tokens and refresh sessions to the exact grant lifetime. Persist the original refresh scope ceiling. Reject stale tokens after disconnect/reconnect.
- [x] C. Explicit verified real-email sharing. Old relay-worded consent never authorizes a real email. UserInfo checks live grant, client, account and home region before disclosure; no PII in ID/access tokens.
- [x] D. Persist application allowed scopes in Cloud, expose them in the API/portal, and carry them in every full configuration snapshot.
- [x] E. Document a complete website-owned account-linking reference using `(iss, sub)` and ownership proof; update privacy and integration docs.
- [x] F. Real PostgreSQL/Redis regression coverage, generated-contract checks, unit/race/lint/frontend checks and cumulative deep review.

User subsequently authorized: finish fixes, run another deep review and fix its findings, then push and deploy through CI/CD.

- [x] G. Publish reviewed PRs, pass CI, merge, promote signed immutable images and verify production scope configuration.
- [x] H. Fix the authenticated production UserInfo wiring: attach regional context, reuse enrollment's user-DEK provider, preserve the trusted internal management hostname, and cover the complete startup/HTTP chain with real PostgreSQL and Redis.

Production verified on 2026-11-04 UTC:

- Core source [#165](https://github.com/harbor-auth/harbor/pull/165), signed-image release [#166](https://github.com/harbor-auth/harbor/pull/166), deployed revision `ffe1b9d9059bd23c2f3272a6f83de1b589858346`; schema 27 clean.
- Cloud source [#161](https://github.com/harbor-auth/harbor-cloud/pull/161), published and explicitly promoted revision `4ef54e1ccc077a61917027602ce078e9f0ff8849`; schema 20 clean. Both Argo applications completed full syncs and reached Synced/Healthy with the expected immutable images.
- Production public and confidential application checks covered creation, callback updates, credential policy, permission narrowing/re-enabling, invalid-scope rejection and deletion. Temporary applications and the API key were removed; the existing application's settings were unchanged.
- Public HTTP checks verified discovery's email scope, UserInfo's authentication requirement and credentialless Bearer CORS. These used curl because Cloudflare blocks the default Python urllib user agent. Live passkey approval and real-email disclosure were not exercised by the operator smoke test; their regression coverage uses the migrated PostgreSQL/Redis integration suite.
