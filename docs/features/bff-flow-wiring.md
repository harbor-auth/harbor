# bff-flow-wiring

**Status:** planned  
**DESIGN §:** §11.2  
**Code:** `internal/bff/` (planned)

Backend-for-Frontend (BFF) flow wiring between the hot-path (harbor-hot) and
cold-path (harbor-mgmt) surfaces: brokers the browser session and the OIDC
Authorization Code + PKCE login handoff so the SPA never handles tokens
directly.
