# Harbor Docs — The Feature & Plan Index

The single entry point (TOC) for everything Harbor **does** and **plans to do**. This index exists so agents (and humans) can find the right doc fast, then reconcile it against the code. If you're building a feature, **start here**.

> **New to Harbor?** Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — a one-page, high-level map (hot/cold path, regions, KMS, the PII-free global plane) that's a gentler on-ramp than [`DESIGN.md`](DESIGN.md). [`DESIGN.md`](DESIGN.md) is now a **navigable index** into a tree of focused files under [`design/`](design/) (each ≤ ~2,000 words, per the small-files principle §1.10). Then see [`OIDC-LOGIN-FLOW.md`](OIDC-LOGIN-FLOW.md) for a step-by-step ASCII sequence diagram of the most complex sequence in the system (the Authorization Code + PKCE login flow, §11.2), backed by [`oidc-flow/`](oidc-flow/) sub-files.

> Managed by two skills: **[`@docs`](../.agents/docs.md)** (create / query / reconcile feature docs) and **[`@plan`](../.agents/plan.md)** (author future work and graduate it into feature docs).

## The knowledge hierarchy

```
DESIGN.md          → WHY + system-level WHAT — the design index (§0–§15)
   └─ design/       → topic-focused design files, each ≤ ~2,000 words
        └─ principles/, product/, protocol/, architecture/,
           security/, backend/, flows/, governance/, threat-model/
docs/plans/         → future WHAT — intent not yet built
   └─ docs/features/ → as-built WHAT + HOW — realized capabilities
        └─ code      → the ground truth for as-built behavior
```

**Source-of-truth rule:** for a **feature doc, the code is reality** — on drift, reconcile the *doc* to the *code* (`@docs reconcile`). Docs **never contradict `DESIGN.md`**; a genuine divergence from the design is a **DESIGN change**, surfaced explicitly (edit `DESIGN.md`, don't quietly document the deviation). This is the same anti-drift philosophy as `@validate`/`@codegen` (which keep *code ↔ spec* honest, §1.5) — one layer up, keeping *doc ↔ code* honest.

## Features (as-built)

| Doc | Status | DESIGN § | Code | Last reconciled |
|---|---|---|---|---|
| [ppid-identity](features/ppid-identity.md) | implemented | §3.2 | `internal/identity/` | 2026-07-08 |
| [webauthn-passkeys](features/webauthn-passkeys.md) | implemented | §3.1 | `internal/webauthn/`, `cmd/harbor-mgmt/` | 2026-07-08 |
| [oidc-authorization-code](features/oidc-authorization-code.md) | implemented | §3.1, §11.2, §11.7 | `internal/oidc/`, `internal/oidcapi/` | 2026-07-08 |
| [hippo-usage](features/hippo-usage.md) | implemented | §1.9 | `.agents/hippo.md`, `.agents/hippo.ts` | 2026-07-08 |
| [agentic-foundations](features/agentic-foundations.md) | implemented | §1.9, §A.8 | `invariants/`, `tools/`, `.github/`, `flake.nix` | 2026-07-08 |
| [real-token-issuance](features/real-token-issuance.md) | implemented | §3.3, §3.4, §7.3 | `internal/crypto/`, `internal/oidc/`, `internal/oidcapi/` | 2026-07-20 |
| [signing-key-rotation](features/signing-key-rotation.md) | implemented | §7.3, §3.5, §3.3 | `internal/crypto/`, `internal/oidcapi/`, `cmd/harbor-hot/` | 2026-07-20 |
| [revocation-outbox](features/revocation-outbox.md) | implemented | §3.5, §10 | `internal/oidc/`, `internal/clients/`, `db/migrations/` | 2026-07-20 |
| [grant-id-fk](features/grant-id-fk.md) | implemented | §3.5, §10, §11.3 | `db/migrations/`, `internal/clients/`, `internal/oidc/` | 2026-07-20 |
| [bloom-filter-revocation](features/bloom-filter-revocation.md) | implemented | §3.5, §7.4 | `internal/oidc/`, `internal/oidcapi/`, `cmd/harbor-hot/` | 2026-07-20 |
| [client-grant-persistence](features/client-grant-persistence.md) | implemented | §10, §3.2, §11.3 | `internal/clients/`, `internal/oidc/`, `db/queries/` | 2026-07-20 |
| [user-enrollment](features/user-enrollment.md) | implemented | §11.1, §10, §4.4 | `internal/identity/`, `internal/webauthn/`, `internal/mgmtapi/`, `cmd/harbor-mgmt/` | 2026-07-20 |
| [session-ppid-seam](features/session-ppid-seam.md) | implemented | §3.2, §11.2 | `internal/oidc/`, `internal/clients/`, `cmd/harbor-hot/` | 2026-07-20 |
| [refresh-token-rotation](features/refresh-token-rotation.md) | implemented | §3.5, §10, §11.7 | `internal/oidc/`, `internal/clients/`, `cmd/harbor-hot/` | 2026-07-20 |
| [webauthn-session-store](features/webauthn-session-store.md) | implemented | §4.1, §4.4, §9 | `internal/webauthn/`, `cmd/harbor-mgmt/` | 2026-07-20 |
| [bff-session-middleware](features/bff-session-middleware.md) | implemented | §9, §11.1, §11.2 | `internal/bff/`, `internal/oidcapi/`, `internal/oidc/`, `cmd/harbor-mgmt/` | 2026-07-20 |
| [userinfo-endpoint](features/userinfo-endpoint.md) | implemented | §3.3, §11.4, §3.1 | `internal/oidcapi/`, `api/openapi/harbor.yaml` | 2026-07-20 |
| [oidf-conformance](features/oidf-conformance.md) | implemented | §1.8, §11.7, §3.1 | `internal/oidc/`, `internal/oidcapi/`, `conformance/` | 2026-07-20 |
| [auth-code-persistence](features/auth-code-persistence.md) | implemented | §4.1, §10 | `internal/oidc/`, `internal/clients/`, `cmd/harbor-hot/` | 2026-07-21 |
| [token-introspection](features/token-introspection.md) | implemented | §3.3, §3.5 | `internal/oidcapi/`, `api/openapi/harbor.yaml` | 2026-07-21 |
| [kms-provider-integration](features/kms-provider-integration.md) | implemented | §4.4, §7.3, §A.4 | `internal/crypto/` | 2026-07-21 |
| [consent-ledger](features/consent-ledger.md) | implemented | §2.1, §10, §11.3 | `internal/oidc/`, `internal/mgmtapi/`, `db/migrations/` | 2026-07-21 |
| [dynamic-client-registration](features/dynamic-client-registration.md) | implemented | §3.1, §8, §10 | `internal/mgmtapi/`, `internal/clients/`, `db/migrations/` | 2026-07-21 |
| [token-revocation-endpoint](features/token-revocation-endpoint.md) | implemented | §3.5, §3.5.2, §7.4 | `internal/oidcapi/`, `api/openapi/harbor.yaml` | 2026-07-21 |
| [rate-limiting](features/rate-limiting.md) | implemented | §4.1, §6.1, §11.7 | `internal/oidcapi/`, `cmd/harbor-hot/` | 2026-07-21 |
| [bff-flow-wiring](features/bff-flow-wiring.md) | implemented | §9, §11.2 | `internal/bff/`, `internal/oidc/`, `cmd/harbor-hot/` | 2026-07-22 |
| [redis-enrollment-session](features/redis-enrollment-session.md) | implemented | §9, §4.1 | `internal/clients/`, `internal/webauthn/`, `cmd/harbor-mgmt/` | 2026-07-22 |

## Plans (future / in progress)

> See **[`plans/README.md`](plans/README.md)** for the full dependency graph (ASCII DAG), build phases, critical paths, and the edge list in machine-readable form.

| Plan | Status | DESIGN § | Promotes to |
|---|---|---|---|
| [regional-data-residency-routing](plans/regional-data-residency-routing.md) | building on Weft (`feat_8ec115c6`) | §5, §4, §11.2 | `internal/region/`, `internal/oidcapi/`, `internal/mgmtapi/`, `cmd/harbor-hot/` |
| [observability-metrics](plans/observability-metrics.md) | building on Weft (`feat_6bfb679c`) | §6.5, §5, §11.2 | `internal/telemetry/`, `internal/oidcapi/`, `internal/mgmtapi/` |
| [user-audit-trail](plans/user-audit-trail.md) | building on Weft (`feat_c2d5e191`, proposed) | §2.1, §4.4, §10, §11.6 | `internal/identity/`, `internal/mgmtapi/`, `db/migrations/` |
| [discoverable-login](plans/discoverable-login.md) | building on Weft (`feat_12ee5a09`, in_progress) | §9, §11.1, §11.2 | `internal/bff/`, `internal/webauthn/`, `cmd/harbor-mgmt/` |
| [user-account-recovery](plans/user-account-recovery.md) | building on Weft (blocked) | §11.7, §11.6, §4 | `db/migrations/`, `internal/identity/`, `internal/webauthn/`, `internal/mgmtapi/` |
| [consent-management-ui](plans/consent-management-ui.md) | building on Weft (`feat_28ba9372`, proposed) | §2.1, §11.4, §9 | `internal/bff/`, `internal/mgmtapi/`, `web/` |
| [compliance-export](plans/compliance-export.md) | building on Weft (`feat_04c21ab3`, proposed) | §11.5, §11.6, §11.2 | `internal/mgmtapi/`, `internal/identity/`, `internal/crypto/` |
| [email-relay-service](plans/email-relay-service.md) | building on Weft (in_progress) | §7.5, §5, §11.2 | `db/migrations/`, `internal/relay/`, `internal/mgmtapi/`, `cmd/harbor-hot/` |
| [webauthn-db-wiring](plans/webauthn-db-wiring.md) | ❌ failed on Weft (`feat_ac6b4036`) — needs re-launch | §4.1, §4.4, §9 | `cmd/harbor-mgmt/` |
| [production-readiness](plans/production-readiness.md) | audit doc | — | see [`plans/production-readiness.md`](plans/production-readiness.md) |

> **Wave 6 — Phase-0 Critical Fixes** (from the [production-readiness audit](plans/production-readiness.md)): `webauthn-db-rewire`, `fix-auth-bypass`, `admin-endpoint-auth`, `client-secret-auth` (all **P0**), plus `hsm-signing-key`, `totp-mfa`, `end-session-logout` (**P1**) and `acr-amr-dynamic` (**P2**). These block production launch and take priority over finishing Wave 5. See [`plans/README.md`](plans/README.md#wave-6--phase-0-critical-fixes-2026-07-production-readiness-audit) for the gate order.

> A plan appears here until it's implemented, then **`@plan promote`** moves its row into the **Features** table above. Author the next one with **`@plan new <slug>`**.

## How to use this index

- **Query starts here.** `@docs query <topic>` always reads this file first, then narrows into `docs/features/` (see the `@docs` skill).
- **`@docs reconcile` keeps it honest.** It verifies every doc's code/spec/test paths still exist, flags stale claims, lists undocumented code, and enforces that this table and `docs/features/*.md` stay in sync.
- **`@plan promote` moves a plan into Features.** When planned work ships, its row graduates from the Plans table to the Features table (bidirectional provenance is recorded in each doc's frontmatter).

## Templates

New docs are copied from [`docs/_templates/`](_templates/):

- [`_templates/feature.md`](_templates/feature.md) — an as-built feature doc.
- [`_templates/plan.md`](_templates/plan.md) — a future-work plan.

> **Update this index:** whenever a feature or plan doc is added, removed, or changes status, update the tables above **in the same change**. `@docs reconcile` treats an out-of-sync index as a drift bug.
