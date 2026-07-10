> **DESIGN §5** · [↑ DESIGN index](../../DESIGN.md) · prev: [overview](overview.md) · next: [performance](performance.md)

# Multi-Jurisdiction Routing

**Goal:** every user's PII physically lives in one region; requests reach that region **without a global database lookup**; nothing sensitive is globally replicated.

### 5.1 Region encoded in identifiers (the "static prefix")

Every user-facing identifier carries its home region so routing is a **pure string operation** at the edge:

- **Issuer per region:** `https://eu.harbor.id`, `https://us.harbor.id`, …
- **Login hint / handle:** region-prefixed, e.g. `eu_ab12cd…` or a handle like `alice@eu.harbor.id`. The `eu` prefix is the routing key.
- **Tokens:** the `iss` claim (`https://eu.harbor.id`) *is* the region signal for anyone verifying.
- **RP integration:** when an RP starts a login, it either (a) points at a specific regional issuer, or (b) hits a thin global `harbor.id` "region resolver" that, given only a region-prefixed `login_hint`, 302-redirects to the right regional issuer. **The resolver reads only the prefix — it holds no PII.**

### 5.2 Edge routing mechanics

1. **Anycast + GeoDNS** puts users on a nearby PoP for TLS termination and static/JWKS caching.
2. The **region prefix** (in the hostname `eu.harbor.id` or the `login_hint` prefix) deterministically selects the **home-region cluster**. A user physically in the US signing into their `eu` account is still routed to EU for the actual auth/data operations — only static assets are served locally.
3. Because the region is in the hostname/`iss`, **k8s ingress routing needs no lookup** — it's host-based routing to the correct regional cluster.

### 5.3 Control plane vs data plane

| Plane | Scope | Contents | PII? |
|---|---|---|---|
| **Regional data plane** | per jurisdiction | users, credentials, MFA, pairwise secrets, grants, sessions, audit, KMS/HSM | **Yes** — never leaves region |
| **Global control plane** | thin, global | RP/client *registry metadata* (client_id, redirect URIs, sector ids — no user data), region directory, billing, status, resolver routing table | **No PII** |

The global control plane is intentionally starved of anything sensitive. If it's breached, **no user data leaks**. RP registry is arguably even better kept regional + published as signed static config; start global for simplicity, keep it PII-free either way.

### 5.4 No cross-region PII

- No cross-region DB replication of user tables.
- Pairwise secrets, DEKs, and KMS keys are **region-local**.
- Inter-region calls are avoided on the auth path entirely (a user's operations happen in their home region).
