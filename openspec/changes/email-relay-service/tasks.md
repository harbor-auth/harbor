# Tasks: Email relay service (per-RP Hide-My-Email)

## Prerequisites

- [ ] **Gate 4** — depends on the shipped `consent-ledger` ✅ (per-(user, RP)
  grant taxonomy) and `client-grant-persistence` ✅ (the persisted client/grant a
  relay maps to). Inherits the Gate-1 guardrails
  (`regional-data-residency-routing` region-pinning, `observability-metrics`
  aggregate-only). Its per-RP toggle is soft-surfaced by
  `consent-management-ui`.
- [ ] **Migration prefix `0014` is reserved** for this change
  (`db/migrations/0014_relay_addresses.up.sql` / `.down.sql`). Do not reuse
  `0014` elsewhere (consent-ledger 0011, dynamic-client-registration 0012,
  user-audit-trail 0013, user-account-recovery 0015).

## Implementation

_Data / control plane first:_

- [ ] Migration `0014_relay_addresses` (up/down): `relay_addresses(relay_token,
  user_id, client_id, state, enc_mapping, region, created_at, deactivated_at)`;
  unique `(user_id, client_id)`; index on `relay_token`.
- [ ] `db/queries/relay_addresses.sql` + `make codegen`: mint-one-per-(user,
  client), region-pinned lookup-by-token, deactivate, list-for-user.
- [ ] `internal/relay/address.go`: opaque **unlinkable** token generation (not
  user-id-derived) + `(user, RP)` uniqueness + state lifecycle
  (`Active`/`Deactivated`/`BYO-domain`).
- [ ] `internal/relay/store.go`: envelope-encrypted, region-pinned mapping store
  (reuse `internal/crypto/` + region seam); never replicated cross-region.
- [ ] `internal/mgmtapi/relay.go`: list addresses, deactivate (hard-bounce kill
  switch **independent** of the login grant), aggregate-only per-RP volume.
- [ ] Region DNS scaffolding: `relay.<region>.harbor.id` MX subdomain + SPF/DKIM
  records for the relay domains (records only).
- [ ] Wire the mint/lookup seam behind the consent grant path in
  `cmd/harbor-hot/main.go` (single call-site).

_Inbound mail plane second:_

- [ ] `internal/relay/mta.go` on **`emersion/go-smtp`**: lookup mapping (unknown
  ⇒ reject) + `Active` check.
- [ ] SPF/DKIM/DMARC **alignment** via **`emersion/go-msgauth`**; reject on
  failure.
- [ ] **ARC-seal** on forward + forward to the real inbox; correct SPF/DKIM for
  the relay domains.
- [ ] **No content retention** — bodies never logged or stored; ephemeral
  routing/rate-limit state only.
- [ ] **Per-address rate limiting**; meter aggregate-only accept/bounce/forward
  counts.

_Phase 2:_

- [ ] Reply-through outbound rewrite (egress from the relay address).
- [ ] BYO-domain: TXT-challenge verification + MX/SPF/DKIM; region-pinned.

## Tests

- [ ] Address is unlinkable (not user-id-derived); two RPs' addresses for one
  user are uncorrelated.
- [ ] Mapping is region-pinned + envelope-encrypted; not readable cross-region.
- [ ] Unknown address is rejected; SPF/DKIM/DMARC-failing mail is rejected.
- [ ] Forwarded mail is ARC-sealed; **no** body is logged or stored.
- [ ] A deactivated address **hard-bounces**; deactivation does **not** revoke
  login and login-revoke does not deactivate.
- [ ] Per-address rate limiting engages; per-RP volume is aggregate-only.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate email-relay-service --strict`
