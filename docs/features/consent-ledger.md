# Consent grants

**Status:** implemented in the canonical `grants` table.
**Code:** `internal/oidc/{grants,consent,resolver,service}.go`, `internal/clients/grants.go`.
**Schema:** migrations 0018 and 0027.

Authentication resolves a pairwise subject without approving permissions. The
bound browser consent action explicitly approves standard scopes on the active
canonical grant. Concurrent approvals merge atomically. Scope expansion keeps
its ID; disconnect revokes it and its refresh sessions; reconnect creates a new
ID with the same pairwise subject and retains revoked grant history.

`Service` has no separate consent store or fallback ledger. The `consent_grants`
compatibility view still reads the same table. Old adapter fixtures compile only
in test files and do not describe a second production authority. Pure consent
checks implement scope coverage and OIDC prompt behavior; production integration
tests use real PostgreSQL and Redis.

This is a current grant plus retained revoked records, rather than an immutable
event log of every scope approval. Email sharing additionally requires explicit
real-address consent; old relay-worded grants do not provide it. Codes, access
and logout tokens, and refresh sessions bind the exact grant lifetime. Refresh
sessions retain their original scope ceiling.

See [UserInfo](userinfo-endpoint.md) for disclosure policy and the real-store
regressions, and [account linking](../guides/account-linking.md) for the website
integration reference.
