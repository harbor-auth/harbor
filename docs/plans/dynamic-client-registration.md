---
title: Dynamic client registration (RFC 7591 / 7592 — POST /register + client management)
status: completed
design_refs: [§3.1, §8, §10]
targets: [internal/mgmtapi/, internal/clients/, db/migrations/, db/queries/]
promoted_to: null
openspec: changes/dynamic-client-registration
created: 2026-07-21
---

# Dynamic client registration (plan)

> **Dependency order:** a **root** — no hard prerequisites. It builds on the
> shipped, persisted client registry (`client-grant-persistence`,
> `internal/clients/`) and lives entirely on the cold path (`harbor-mgmt`), so
> it does not contend with the hot-path router chain
> (`token-introspection`/`rate-limiting`/`token-revocation-endpoint`).
>
> **Migration prefix `0012` is reserved** for this plan
> (`db/migrations/0012_client_registration.up.sql` / `.down.sql`). Do not reuse
> `0012` elsewhere — the reservation prevents the historical
> migration-collision failure mode.

## Problem

Harbor's clients are currently **seeded** — registered out-of-band into the
persisted registry — which makes it a closed OP: an RP cannot onboard itself.
RFC 7591 (Dynamic Client Registration) + RFC 7592 (Client Configuration
Management) are the standard way for an RP to register and then manage its own
client record. Adding them turns Harbor from a fixed-client demo into a **real,
self-service OpenID Provider** and closes a conformance gap. The registry itself
is already persisted (`client-grant-persistence`); what's missing is the
**standard write/management API** on top of it, plus the credentials that
govern who may edit a registered client afterwards.

## Proposed approach

### Endpoints (RFC 7591 + 7592)

```
POST   /register                 (7591) create a client → 201 + client metadata
GET    /register/{client_id}     (7592) read client config
PUT    /register/{client_id}     (7592) update client config
DELETE /register/{client_id}     (7592) delete the client
```

1. **Contract-first** — if `harbor-mgmt` has an OpenAPI contract, add these
   operations there and regenerate; otherwise author a net-new handler set with
   the request/response shapes fixed by RFC 7591 §2/§3 (redirect URIs, grant
   types, response types, token-endpoint auth method, client name, etc.).
2. **Registration (`POST /register`)** — validate the submitted metadata
   (redirect-URI syntax/scheme, allowed grant/response types, supported
   `token_endpoint_auth_method`), mint a `client_id` (and a `client_secret` for
   confidential clients), persist via the shipped `internal/clients/` registry,
   and return `201` with the registered metadata **plus** a
   `registration_access_token` and `registration_client_uri` (RFC 7592).
3. **Registration access token (`0012` migration)** — the
   `registration_access_token` is the bearer credential that authorises
   subsequent 7592 GET/PUT/DELETE on that specific client. Store it **hashed**
   (never plaintext) alongside the client, scoped to that single `client_id`.
4. **Management (`GET/PUT/DELETE /register/{client_id}`)** — authorise via the
   per-client registration access token; `GET` returns current config, `PUT`
   replaces the mutable metadata (re-validated), `DELETE` removes the client
   (and SHOULD cascade-revoke its outstanding grants via the shipped revocation
   stack). A token that doesn't match the target `client_id` gets `401`/`403`
   with no metadata leak.
5. **Abuse controls** — registration is a write endpoint; note that open
   registration needs a gate (software-statement / initial-access-token, or an
   admin allow-list) so it isn't an anonymous client-spam vector. This plan
   supports an **initial access token** requirement (configurable) for
   `POST /register`.

**Alternatives considered.** *Keep clients seed-only* — rejected: blocks
self-service onboarding and leaves a standards gap. *Put registration on the
hot path* — rejected: registration is a rare, cold-path administrative write;
it belongs on `harbor-mgmt` next to enrolment, not on `harbor-hot`. *Reuse the
client's `client_secret` to authorise 7592 management* — rejected: RFC 7592
mandates a distinct `registration_access_token` so client credentials and
configuration-management credentials have independent blast radii.

## DESIGN alignment

Realises §3.1 (OIDC/OAuth client model), §8 (backend stack / API surface), and
§10 (the client registry data model — extended with registration-access-token
and registration metadata). It does **not** change `DESIGN.md` — a client
registry already exists; this plan adds the standard registration/management
API and its credential. Registration is a cold-path, regional administrative
operation (no global client lookup), consistent with §5.

## Target code paths

- `db/migrations/0012_client_registration.up.sql` / `.down.sql` — hashed
  `registration_access_token` + registration metadata columns/table
  (**reserved prefix 0012**).
- `db/queries/client_registration.sql` — sqlc queries (create with reg-token,
  get-by-id, update, delete, verify reg-token).
- `internal/clients/` — extend the registry store: create/update/delete with
  registration metadata; hashed reg-token verify.
- `internal/mgmtapi/` — `POST /register` + `GET/PUT/DELETE /register/{client_id}`
  handlers; metadata validation; reg-token auth; initial-access-token gate.
- `api/openapi/` (if harbor-mgmt has a contract) — the four operations;
  regenerate.

## Implementation checklist

- [ ] Migration `0012_client_registration` (up/down): hashed `registration_access_token` (per-client, single-scope), registration metadata columns, `created_at`. **Prefix 0012 is reserved for this plan.**
- [ ] `db/queries/client_registration.sql` + `make codegen`: create-with-reg-token, get-by-id, update, delete, verify-reg-token.
- [ ] Extend `internal/clients/` store: create/update/delete client with registration metadata; verify hashed reg-token (constant-time compare).
- [ ] `POST /register` (RFC 7591): validate metadata (redirect URIs, grant/response types, `token_endpoint_auth_method`); mint `client_id` (+ `client_secret` for confidential); persist; return `201` + metadata + `registration_access_token` + `registration_client_uri`.
- [ ] Optional **initial access token** gate on `POST /register` (configurable) to prevent anonymous client-spam.
- [ ] `GET/PUT/DELETE /register/{client_id}` (RFC 7592): authorise via the per-client reg-token; `GET` returns config; `PUT` re-validates + replaces mutable metadata; `DELETE` removes the client and cascade-revokes its grants via the shipped revocation stack.
- [ ] Store `client_secret` and `registration_access_token` **hashed only** (never plaintext at rest); return the plaintext once, at creation.
- [ ] Tests: register → `201` with usable `client_id`/secret/reg-token; the new client can complete an authorize/token flow; GET/PUT/DELETE succeed with the correct reg-token; invalid redirect URI / unsupported grant type → `400 invalid_client_metadata`.
- [ ] Tests (security): a reg-token for client A cannot read/modify/delete client B (`401`/`403`, no metadata leak); missing/invalid reg-token → `401`; `POST /register` without a required initial access token → `401`; hashed-at-rest verified (no plaintext secret/reg-token column).
- [ ] Author & verify paired OpenSpec change: `openspec validate dynamic-client-registration --strict`
- [ ] Reconcile & promote: `@plan promote dynamic-client-registration`

## Risks & open questions

- **Migration-number collision** — **0012 is reserved**; parallel plans must
  take other prefixes (consent-ledger holds 0011, user-audit-trail 0013).
- **Open-registration abuse** — anonymous `POST /register` is a spam/DoS vector.
  This plan supports an initial-access-token requirement; the default posture
  (open vs gated) needs a product decision — recommend **gated by default**.
- **Metadata validation surface** — redirect-URI validation is security-
  critical (open-redirect / SSRF risk); validation must be strict (exact-match
  registration, https-only except loopback, no wildcards).
- **Secret/reg-token handling** — plaintext is shown exactly once at creation
  and stored hashed; a `PUT` that rotates the secret must follow the same
  show-once discipline.
- **7592 completeness** — full RFC 7592 includes reg-token rotation on update;
  decide whether `PUT` rotates the reg-token or preserves it (RFC allows
  either — document the choice).

## Definition of done

`go build/vet/test ./...` green; `POST /register` (7591) and
`GET/PUT/DELETE /register/{client_id}` (7592) served on `harbor-mgmt`, writing
the shipped client registry (migration 0012); registration mints hashed
client-secret + per-client registration-access-token; management operations are
authorised by that token with no cross-client leakage; a freshly-registered
client can complete an OIDC flow; open registration is gatable by an initial
access token; `make agent-check` clean. Ready to `@plan promote`.
