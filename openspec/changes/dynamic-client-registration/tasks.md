# Tasks: Dynamic client registration (RFC 7591 / 7592)

## Prerequisites

- [ ] A **root** — no hard prerequisites. Builds on the shipped, persisted
  client registry (`client-grant-persistence`, `internal/clients/`) and lives
  entirely on the cold path (`harbor-mgmt`), so it does not contend with the
  hot-path router chain.
- [ ] **Migration prefix `0012` is reserved** for this change
  (`db/migrations/0012_client_registration.up.sql` / `.down.sql`). Do not reuse
  `0012` elsewhere (consent-ledger holds 0011, user-audit-trail 0013).

## Implementation

- [ ] Migration `0012_client_registration` (up/down): hashed
  `registration_access_token` (per-client, single-scope) + registration metadata
  columns, `created_at`.
- [ ] `db/queries/client_registration.sql` + `make codegen`: create-with-reg-token,
  get-by-id, update, delete, verify-reg-token.
- [ ] Extend `internal/clients/` store: create/update/delete client with
  registration metadata; verify hashed reg-token (constant-time compare).
- [ ] `POST /register` (RFC 7591) handler in `internal/mgmtapi/`: validate
  metadata (redirect URIs, grant/response types, `token_endpoint_auth_method`);
  mint `client_id` (+ `client_secret` for confidential); persist; return `201`
  + metadata + `registration_access_token` + `registration_client_uri`.
- [ ] Optional **initial access token** gate on `POST /register` (configurable)
  to prevent anonymous client-spam.
- [ ] `GET/PUT/DELETE /register/{client_id}` (RFC 7592): authorise via the
  per-client reg-token; `GET` returns config; `PUT` re-validates + replaces
  mutable metadata; `DELETE` removes the client and cascade-revokes its grants
  via the shipped revocation stack.
- [ ] Store `client_secret` and `registration_access_token` **hashed only**
  (never plaintext at rest); return the plaintext once, at creation.
- [ ] If `harbor-mgmt` has an OpenAPI contract, add the four operations there
  and regenerate; otherwise fix the shapes per RFC 7591 §2/§3.

## Tests

- [ ] Register → `201` with a usable `client_id`/secret/reg-token; the new
  client can complete an authorize/token flow.
- [ ] `GET/PUT/DELETE` succeed with the correct reg-token.
- [ ] Invalid redirect URI / unsupported grant type → `400 invalid_client_metadata`.
- [ ] Security: a reg-token for client A cannot read/modify/delete client B
  (`401`/`403`, no metadata leak); missing/invalid reg-token → `401`.
- [ ] `POST /register` without a required initial access token → `401`.
- [ ] Hashed-at-rest verified (no plaintext `client_secret` / reg-token column).

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate dynamic-client-registration --strict`
