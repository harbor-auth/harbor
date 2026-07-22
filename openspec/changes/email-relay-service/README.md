# email-relay-service

Give every RP a **unique, per-app, random relay address** that forwards to the
user's real inbox, so the user's real email is **never shared by default** and
can be **cut off individually** (§7.5). Mints one
`<opaque-token>@relay.<region>.harbor.id` per `(user, RP)` grant — the token is
**unlinkable** (not derived from the user id, so two RPs' addresses for one user
are uncorrelated) — and stores the `relay_address → user → client_id` mapping
**envelope-encrypted at rest** in the user's **home region**, never replicated
cross-region (§5). A regional inbound MTA (built Go-native on the **MIT-licensed**
`emersion/go-smtp` + `emersion/go-msgauth`, **not** an AGPL SaaS or a
PII-processing managed API) looks up the mapping, authenticates the sender via
**SPF / DKIM / DMARC** alignment, **ARC-seals**, and forwards — with **no content
retention** (bodies are never logged or stored). Deactivating an address is an
instant **hard-bounce kill switch**, **independent** of the RP login grant.
Abuse is contained with **per-address rate limiting** and users see only
**aggregate-only** per-RP volume. Reserves migration prefix `0016`.
