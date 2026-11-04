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

- [ ] G. Publish reviewed PRs, pass CI, merge, promote signed immutable images and verify production scope configuration.
