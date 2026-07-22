# dynamic-client-registration

Turn Harbor from a seed-only OP into a self-service OpenID Provider by adding
RFC 7591 Dynamic Client Registration (`POST /register`) and RFC 7592 Client
Configuration Management (`GET/PUT/DELETE /register/{client_id}`) on
`harbor-mgmt`, writing the shipped, persisted client registry. Registration
validates submitted metadata (strict redirect-URI checks, allowed grant/response
types, `token_endpoint_auth_method`), mints a `client_id` (and a
`client_secret` for confidential clients), and returns a
`registration_access_token` + `registration_client_uri`. That per-client token —
stored **hashed** (migration 0012), shown once at creation — authorises the 7592
management operations, with a token for one client unable to read/modify/delete
another (`401`/`403`, no leak). `POST /register` supports an optional
initial-access-token gate to prevent anonymous client-spam, and `DELETE`
cascade-revokes the client's outstanding grants via the shipped revocation
stack. Registration is a cold-path, regional administrative operation.
