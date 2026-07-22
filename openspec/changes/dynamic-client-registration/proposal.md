# Proposal: Dynamic client registration (RFC 7591 / 7592)

## Problem

Harbor's clients are currently **seeded** — registered out-of-band into the
persisted registry — which makes it a closed OP: an RP cannot onboard itself.
RFC 7591 (Dynamic Client Registration) + RFC 7592 (Client Configuration
Management) are the standard way for an RP to register and then manage its own
client record. Adding them turns Harbor from a fixed-client demo into a **real,
self-service OpenID Provider** and closes a conformance gap. The registry itself
is already persisted (`client-grant-persistence`); what's missing is the
**standard write/management API** on top of it, plus the credential that governs
who may edit a registered client afterwards.

## Proposed Solution

Endpoints (RFC 7591 + 7592), on `harbor-mgmt`:

```
POST   /register                 (7591) create a client → 201 + client metadata
GET    /register/{client_id}     (7592) read client config
PUT    /register/{client_id}     (7592) update client config
DELETE /register/{client_id}     (7592) delete the client
```

1. **Contract-first** — if `harbor-mgmt` has an OpenAPI contract, add these
   operations there and regenerate; otherwise author a net-new handler set with
   the request/response shapes fixed by RFC 7591 §2/§3 (redirect URIs, grant
   types, response types, `token_endpoint_auth_method`, client name, etc.).
2. **Registration (`POST /register`)** — validate the submitted metadata
   (redirect-URI syntax/scheme, allowed grant/response types, supported
   `token_endpoint_auth_method`), mint a `client_id` (and a `client_secret` for
   confidential clients), persist via the shipped `internal/clients/` registry,
   and return `201` with the registered metadata **plus** a
   `registration_access_token` and `registration_client_uri` (RFC 7592).
3. **Registration access token (`0012` migration)** — the
   `registration_access_token` is the bearer credential that authorises
   subsequent 7592 GET/PUT/DELETE on that specific client. Store it **hashed**
   (never plaintext), scoped to that single `client_id`.
4. **Management (`GET/PUT/DELETE /register/{client_id}`)** — authorise via the
   per-client registration access token; `GET` returns current config, `PUT`
   re-validates + replaces the mutable metadata, `DELETE` removes the client and
   cascade-revokes its outstanding grants via the shipped revocation stack. A
   token that doesn't match the target `client_id` gets `401`/`403` with no
   metadata leak.
5. **Abuse controls** — `POST /register` is a write endpoint; support an
   **initial access token** requirement (configurable) so open registration is
   not an anonymous client-spam vector.

## Non-Goals

- Placing registration on the hot path — it is a rare, cold-path administrative
  write on `harbor-mgmt`, next to enrolment.
- Reusing the client's `client_secret` to authorise 7592 management — RFC 7592
  mandates a distinct `registration_access_token` so the two credentials have
  independent blast radii.
- Full reg-token rotation policy on every `PUT` (the RFC allows either
  preserving or rotating) — the choice is documented, not mandated.
- Any cross-region client lookup — registration is regional.

## Success Criteria

- [ ] `POST /register` (7591) and `GET/PUT/DELETE /register/{client_id}` (7592) served on `harbor-mgmt`.
- [ ] Registration validates metadata (redirect URIs, grant/response types, `token_endpoint_auth_method`); invalid → `400 invalid_client_metadata`.
- [ ] Registration mints `client_id` (+ `client_secret` for confidential) and a per-client `registration_access_token` + `registration_client_uri`.
- [ ] `client_secret` and `registration_access_token` stored **hashed only** (migration 0012), returned in plaintext exactly once at creation.
- [ ] 7592 operations are authorised by the per-client reg-token; a token for client A cannot read/modify/delete client B (`401`/`403`, no leak).
- [ ] `DELETE` removes the client and cascade-revokes its grants via the shipped revocation stack.
- [ ] `POST /register` supports an optional required initial access token (configurable) to gate open registration.
- [ ] A freshly-registered client can complete an authorize/token flow.
- [ ] `make agent-check` clean.
