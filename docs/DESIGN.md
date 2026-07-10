# Harbor — Privacy-First, Ethical SSO

> **Design Document (v0.1)**
> A privacy-preserving, tracking-free replacement for "Sign in with Google/Facebook".
> Core in Go, multi-jurisdiction, engineered for millions of verifications per second.

---

## 0. TL;DR

Harbor is an **OpenID Provider (OP)** that lets people sign in to third-party apps ("Relying Parties" / RPs) **without being tracked**. We are a neutral identity + auth broker: we manage credentials, passkeys, and MFA, and we authenticate users only with the RPs they've explicitly configured.

The three pillars that shape every decision:

1. **Verifiable privacy** — We technically constrain *ourselves* (the operator) from tracking users. No cross-RP correlation, minimal logging, pairwise pseudonymous identifiers, user-owned audit trail, open-source + third-party audited.
2. **Data sovereignty** — Each user lives in exactly **one jurisdiction** (their home region). Their PII never leaves that region. Region is encoded in identifiers so requests route at the edge with **no global lookup**.
3. **Extreme performance & low cost** — The sign-in / token-verification hot path is **stateless and edge-cacheable** (asymmetric-signed tokens verified via JWKS, no DB hit), separated from the slower management path, so we can serve **millions of verifications/sec** cheaply.

A fourth, cross-cutting commitment shapes *how* we build rather than *what* we build: **standards-first, contract-first, codegen-everywhere** (see §1).

---

## 1. Engineering Principles

These principles govern *how* we build Harbor. They are as binding as the product pillars: an implementation that violates them is wrong even if it "works". The through-line is simple — **the specification is the source of truth, and as much as possible is generated from it.**

### 1.1 Standards & protocols first

We **never invent what an open standard already solves.** Identity, auth, crypto, and interchange are adversarial, high-stakes domains where rolling our own is how you get breached. For every capability we first ask *"what is the ratified standard, and is there a certified/compliant implementation?"* and adopt it.

The standards Harbor commits to:

| Domain | Standard(s) | Notes |
|---|---|---|
| Federation / SSO | **OpenID Connect (OIDC)**, **OAuth 2.1** | We are a certified OP; Authorization Code + PKCE only. |
| Authentication | **FIDO2 / WebAuthn / passkeys** | Primary, phishing-resistant factor. |
| MFA | **RFC 6238 TOTP** | Secondary factor. |
| Tokens / crypto | **JOSE**: JWT (RFC 7519), JWS, JWK/JWKS, JWA | ES256/EdDSA signing. |
| Verifiable claims (later) | **SD-JWT VC**, **W3C Verifiable Credentials 2.0**, **ISO/IEC 18013-5 mDL**, **eIDAS 2.0** | For the age-proof add-on. |
| REST interfaces | **OpenAPI 3.1** (a JSON Schema dialect) | Every REST surface. |
| Data schemas | **JSON Schema 2020-12** | Shared models; OpenAPI 3.1 reuses these. |
| Internal RPC | **Protobuf (proto3) + gRPC** | Typed service-to-service contracts. |
| Async / events (later) | **AsyncAPI** + schema registry | Event contracts. |
| Provisioning (enterprise, later) | **SCIM 2.0** | If/when we support directory sync. |
| Persistence | **SQL** | The query *is* the contract (via `sqlc`). |

Where a standard has an official **conformance/certification suite** (OIDC, WebAuthn), passing it is a release gate — not an afterthought.

### 1.2 Contract-first: every interface has a machine-readable spec

**Every interface in the system — external *and* internal — is defined by a versioned, machine-readable contract that is the single source of truth.** The contract is written or amended **before** the implementation, reviewed like code, and lives in-repo under `/api`.

- "Interface" means: the RP-facing protocol surface, the dashboard/BFF REST API, the RP-management and admin APIs, every internal gRPC service, every shared data model, every async event, and the DB access layer.
- Contracts are **heavily specified**: every field typed, constrained (formats, enums, ranges, required/optional), documented, and given examples. Vague `object`/`any` payloads are not allowed.
- Contracts are **versioned** (semver) and **backward-compatibility-checked** in CI. A breaking change is a deliberate, reviewed, major-version event.
- The contract, not the code, is authoritative. If code and spec disagree, the code is the bug.

### 1.3 Codegen everywhere

**Anything that can be generated from a spec (or from other code) is generated — never hand-written and never hand-maintained in parallel.** Hand-written code is reserved for genuine business logic that no generator can produce.

From each contract we generate, as applicable:

- **Server side:** request/response models, routing/handler stubs, input validation, and OpenAPI/proto-derived interfaces the business logic implements.
- **Client side:** typed SDKs and API clients (Go, TypeScript) so no consumer hand-writes request/response types.
- **Data layer:** typed, compile-time-checked query functions from SQL (`sqlc`).
- **Docs:** human-readable API reference rendered directly from the specs.
- **Test assets:** mocks, fake servers, and contract/fixture data for consumer-driven contract testing.

Generated code is **reproducible and CI-verified**: regenerating in CI must produce a clean `git diff`. Drift between spec and generated code fails the build. Generated files are clearly marked and never edited by hand.

### 1.4 The right spec language per interface (a deliberate refinement)

We want **OpenAPI-style rigor for every interface**, but we use the **native contract language best suited to each interface type** rather than forcing OpenAPI onto surfaces where a stronger native contract exists. This preserves the intent — heavily-defined, codegen-driven contracts everywhere — while staying idiomatic and honest.

| Interface | Contract language | Codegen tooling | Rationale |
|---|---|---|---|
| Dashboard / BFF REST, RP-management API, admin API | **OpenAPI 3.1** | `oapi-codegen` (Go), `openapi-typescript` / `orval` (TS), Redoc (docs) | Public REST → OpenAPI is the lingua franca; JSON-Schema-based. |
| Internal service-to-service | **Protobuf + gRPC** | `buf` + `protoc-gen-go`/`-go-grpc` | Faster, strictly typed, better evolution semantics than REST for internal calls. |
| Shared data models / value objects | **JSON Schema 2020-12** | shared `$ref`s into OpenAPI + type generators | One schema → Go + TS types + validation. |
| Protocol edge (OIDC, OAuth, WebAuthn) | **The standards themselves are the contract** | certified libs + **conformance suites** | We *conform to* and *test against* these specs; we do not redefine them. We publish an OpenAPI *facade* for discoverability only. |
| Database access | **SQL** (`.sql` files) | **`sqlc`** → typed Go | The query is the contract; compile-time checked. |
| Async / events (later) | **AsyncAPI** | AsyncAPI generators + schema registry | Event payloads get the same rigor as sync APIs. |
| Service configuration | **JSON Schema / CUE** | validated at process boot | Config is an interface too — typed and validated, fail-fast. |
| Frontend ↔ backend types | *generated from the OpenAPI above* | `openapi-typescript` | The web app **never hand-writes API types.** |

**Net rule:** OpenAPI for REST, Protobuf for gRPC, standard OIDC/WebAuthn at the protocol edge, SQL+`sqlc` for data — but **all of them are spec-first, heavily-contracted, and code-generated.**

### 1.5 Contract governance & CI enforcement

Contracts are only trustworthy if they're enforced. In CI we:

- **Lint** specs (`spectral` for OpenAPI, `buf lint` for proto) against a shared style guide.
- **Check backward compatibility** on every change (`oasdiff` for OpenAPI, `buf breaking` for proto); breaking changes require an explicit major-version bump and reviewer sign-off.
- **Verify codegen is current** — regenerate from specs and fail if the working tree changes (no drift).
- **Run conformance suites** — OIDC OP certification and WebAuthn conformance are release gates.
- **Contract-test** consumers against provider specs (mocks generated from the same source of truth).

### 1.6 Consequences for the design

- The `/api` directory (see §8.2) is the **canonical home** of all contracts (`openapi/`, `proto/`, `json-schema/`) and is reviewed with the same rigor as source code.
- New features start by **editing a spec**, then regenerating, then filling in business logic — in that order.
- Because one schema fans out to Go types, TS types, validation, docs, and mocks, the system stays **DRY across the entire stack**: change the contract once, everything downstream regenerates.

### 1.7 Testing strategy (independently *and* as a system)

**Core principle: every unit is tested in isolation AND the whole system is tested end-to-end.** Both matter; neither substitutes for the other. Unit tests prove each piece is correct; system tests prove the pieces are wired together correctly. A green unit suite over a mis-integrated system is a false sense of safety — and vice versa.

We use a layered pyramid, tuned to Harbor's auth/crypto domain:

- **Unit tests** — fast (sub-ms to ms), **pure-logic-first**. Core logic — PPID derivation (§3.2), token minting/validation, the crypto envelope logic (§4.4) — is written as **pure functions separated from I/O**, so it is trivially unit-testable **without mocks**. Deterministic crypto (HMAC/JWT signing) is a perfect fit: fixed inputs → fixed outputs → exhaustive, fast assertions. If a unit needs elaborate mocks to test, that's a design smell (see the note below).
- **Contract tests** — **generated from the specs** (§1.2, §1.5). Consumers are tested against the provider's OpenAPI/proto contracts, and the mocks/fakes are generated from the *same source of truth*, so the TypeScript frontend client and the Go server **cannot silently drift**. A contract change that breaks a consumer fails here, not in production.
- **Integration tests (per system)** — each service/module is tested against **real dependencies**: real Postgres, real Redis. Only *true external* boundaries are stubbed (the KMS/HSM, outbound mail). **Anti-pattern to forbid:** stubbing internal services or authorization inside integration tests. That is security theater — it hides exactly the bugs integration tests exist to catch. This mirrors the §2.2/§7 posture: **never stub the thing that would catch a security regression** (e.g., a missing authorization check or a cross-region leak).
- **End-to-end / system tests** — the **full OIDC flow (§11.2)** exercised across the real hot *and* cold paths: passkey auth, code exchange + PKCE, token issuance, JWKS verification, and revocation (§3.5). The **§11.7 error/security cases are explicit negative tests** (bad `redirect_uri`, reused code, PKCE mismatch, nonce/state failures) — we assert the *exact* error responses.
- **Conformance suites as release gates** — **OIDC OP certification** and **WebAuthn conformance** (§1.1, §1.5) **must pass to ship**. This is a hard gate, not advisory: a build that fails conformance does not release.
- **Security & abuse tests** — authorization tests proving **no cross-region / cross-RP leakage**, PKCE/nonce/state negative tests, **PPID non-correlation** checks (two RPs get unrelated `sub`s), fuzzing of the protocol edge, and SAST / dependency / secret scanning.
- **Performance / load tests** — the hot path is load-tested toward the **millions/sec** target (§6.1), with regression budgets on p99 latency. These run **pre-release** (not on every commit) because they're expensive.

| Test layer | What it covers | Speed | Runs when |
|---|---|---|---|
| Unit | Pure logic (PPID, token, crypto) | sub-ms–ms | every commit / pre-commit |
| Contract | Spec conformance of producers & consumers | ms | every commit |
| Integration (per system) | A service against real Postgres/Redis | ms–s | every commit / PR |
| End-to-end / system | Full OIDC flow across hot+cold paths | s | every PR / pre-merge |
| Conformance (gate) | OIDC OP + WebAuthn certification | s–min | pre-release (**blocking**) |
| Security & abuse | Authz, non-correlation, fuzzing, SAST | s–min | every PR + scheduled |
| Performance / load | Hot-path throughput & p99 | min | pre-release |

**Testability is a design constraint.** If something is hard to test, that is a signal to refactor toward a **pure core + thin I/O layer**, not to reach for more mocks. Ease of testing is treated as evidence of good design.

### 1.8 CI/CD, fast builds & fast local validation

**Core principle: fast feedback at every level.** Sub-second local syntax/lint feedback, fast per-system builds, and fast *independent* deploys — because velocity and safety **compound** (quick feedback catches mistakes while they're cheap, and small, frequent, reversible deploys make each change low-risk).

#### Fast local validation (the inner loop)

Developers get near-instant feedback **before** CI ever runs:

- **Editor/LSP (`gopls`)** surfaces syntax and type errors *as you type*.
- Fast local commands: `gofmt`/`goimports`, `go vet`, `golangci-lint`, spec-lint (`spectral` for OpenAPI, `buf lint` for proto), and the **codegen-drift check** (§1.5) — all runnable in seconds.
- **Pre-commit hooks** run the *fast subset* (format, vet, lint, secret-scan) on **changed files only**, so obviously-broken code never reaches CI. **Changed-files-only + caching** is the rule — the inner loop must stay sub-second-ish to be used.

#### Fast, independent per-system builds

- The modular monolith (§4.2) compiles into small, separately-deployable binaries — `harbor-hot`, `harbor-mgmt` (§8.2) — that build and ship **independently**.
- **Build caching** everywhere: Go build/test cache, Docker layer caching, and a shared remote cache in CI.
- **Affected-only builds:** only rebuild/redeploy the systems whose inputs actually changed. A dashboard change **does not** rebuild or redeploy the hot path.
- Small **static Go binaries** → tiny images → fast push/pull and fast rollouts.

#### CI pipeline stages (fast → slow, fail fast)

Cheap, high-signal checks run first and gate the expensive ones:

| # | Stage | Checks | Typical speed | Gates |
|---|---|---|---|---|
| 1 | Static | format · `go vet` · lint · spec-lint · **codegen-drift** | seconds | blocks all |
| 2 | Contract compat | breaking-change checks (`oasdiff`/`buf breaking`, §1.5) | seconds | blocks build |
| 3 | Fast tests | unit + contract (parallel, sharded) | seconds | blocks build |
| 4 | Build | compile binaries + images (cached) | seconds–min | blocks integration |
| 5 | Integration | per-system, real Postgres/Redis (service containers) | min | blocks merge |
| 6 | Security | SAST · dependency · secret scans | seconds–min | blocks merge |
| 7 | Conformance | OIDC OP + WebAuthn suites | s–min | blocks **release** |
| 8 | Load (pre-release) | hot-path throughput & p99 budgets | min | blocks release |

#### Independent, progressive deploys

- Each system deploys **independently** to Kubernetes (§6).
- **Per-region progressive delivery** (canary → progressive rollout) with **automated health checks** and **fast automated rollback** on regression.
- **DB migrations** run as a **gated, backward-compatible** step using **expand/contract**, so schema changes are decoupled from code deploys and each is independently reversible.
- **Region isolation (§5)** means a bad rollout is **contained to one jurisdiction** — never a global outage.

#### Trunk-based & always-releasable

- Short-lived branches, **small PRs**, `main` always green and deployable; **feature flags** hide incomplete work. This is the delivery cadence assumed by the phased roadmap (§14).

### 1.9 Skills & agents (a living toolkit)

**Core principle: capture repeated work.** If we do something more than a couple of times, we turn it into a reusable **skill** (a documented workflow/checklist, invoked `@skill-name`) or, once it's frequent and stable, a **dedicated agent** (a specialized doer). This keeps our process fast, consistent, and hard to get wrong — the same way §1.7/§1.8 keep our *code* fast and consistent.

- **Modifying skills is first-class.** When we find an error, discover a better way, or the toolchain changes, we **update the skill immediately** — ideally in the same PR as the fix. Skills are versioned in-repo and reviewed like code. **A stale skill is a bug.**
- **When to create one:** a task repeated ≥3 times, a multi-step workflow that's easy to get wrong, or a checklist tied to these principles (privacy invariants, spec-first, testing, security).
- **Lifecycle:** identify repetition → draft skill → use it → refine on every friction → (optionally) promote to a dedicated agent.

The toolkit lives in **`.agents/`** (see `.agents/README.md` for the index and philosophy). Initial skills:

| Skill | Purpose |
|---|---|
| `go-build` | Build the Go binaries (`harbor-hot`, `harbor-mgmt`). |
| `go-test` | Go unit/integration tests, race detector, coverage (§1.7). |
| `frontend-test` | Next.js/TS typecheck, lint, unit tests (§9). |
| `validate` | Fast changed-files inner loop: fmt/vet/lint/spec-lint/codegen-drift (§1.8). |
| `db-migrate` | Postgres expand/contract migrations — backward-compatible, reversible (§1.8). |
| `codegen` | Regenerate all code from the `api/` contracts — spec-first, zero drift (§1.2–§1.5). |
| `code-review` | Review against Harbor's privacy/security/spec-first principles. |
| `oidc-conformance` | Run the OIDC OP + WebAuthn conformance suites as a hard release gate (§1.7, §1.8 Stage 7). |
| `load-test` | Hot-path throughput & p99 latency load tests as a pre-release gate (§1.8 Stage 8, §6.5.5). |

**First graduation in practice:** the `code-review` skill has already been promoted into a dedicated **`harbor-reviewer`** agent (`.agents/harbor-reviewer.ts`) — the privacy/security checklist baked in, delegating the general pass to `@deep-code-reviewer`. The old `@code-review` skill is now a thin pointer, proving the lifecycle above is real, not aspirational.

More will be added as the project grows (e.g. `db-seed`, `release`, `chaos-test`).

### 1.10 Small, single-concern files

**Core principle: each file targets exactly one feature or concern, and stays small.** A file should have one reason to exist and one reason to change. When something new but distinct shows up, it gets its own file — not another section bolted onto an existing one.

**Why (the practical reason):** small, focused files keep *both* humans and AI agents fast and accurate. A large file forces reading thousands of tokens of unrelated code just to touch one thing — wasting context and, for an agent, risking **context loops**: re-reading the same big file over and over without making progress. One concern per file means precise reads and precise edits.

- **Use packages to group, not bigger files.** Don't grow a file to hold related things — split by concern and let the **package** (Go package / TS module / directory) provide the grouping and boundary. This dovetails with §8's `internal/<domain>` layout, where each domain is a package of small, single-purpose files.
- **One primary responsibility per file.** Prefer one primary type/function-family per file; when a file starts mixing concerns or grows long, split it and reach for a **package boundary** rather than a larger file.
- **Co-locate focused tests.** Keep a file's test beside it (`ppid.go` ↔ `ppid_test.go`). Small, single-concern units are trivially testable without mocks — the same property §1.7 relies on (pure logic separated from I/O).

This is **enforced in review**: the `@harbor-reviewer` agent flags files that mix multiple concerns or grow large and suggests splitting them along a package boundary.

---

## 2. Product Positioning & Trust Model

### 2.1 What we sell: a trust guarantee

The product is not "another login button" — it's a **promise that is technically enforced and independently verifiable**:

- We **never** build a profile of you.
- We **never** *persistently* tell RP-A that you also use RP-B (no stored cross-RP correlation). *(Honest footnote: during SSO Harbor must transiently resolve which user you are in order to issue the correct per-RP PPID — see §3.2.4 and §3.2.7 for what this means and doesn't mean.)*
- We **never** sell, share, or mine your data.
- We authenticate you **only** with RPs you have explicitly connected.
- Your **audit log is yours** — you can see, export, and (subject to fraud/legal retention windows) delete every authentication event.

### 2.2 How we make privacy *verifiable*, not just a promise

| Technique | What it guarantees |
|---|---|
| **Pairwise Pseudonymous Identifiers (PPID)** | Each RP gets a *different* `sub` for the same user. **RP-unlinkability is verifiable by construction** (two colluding RPs comparing `sub`s see unrelated HMAC outputs — provable from the code alone). **Operator non-correlation is attestation-dependent**: Harbor is technically constrained (per-user key, no global secret, no bulk-decrypt) but proving the *deployed binary* matches the published source requires reproducible builds + a transparency log (planned, §2.2 and §3.2.7). See §3.2.4 for the full honest framing. |
| **Data minimization** | We store the minimum needed to authenticate. Claims released to an RP are per-grant and consented. |
| **No behavioral logging** | The hot auth path emits only aggregate, non-identifying metrics. No per-user analytics, no ad SDKs, no third-party trackers. |
| **User-owned audit log** | Every `AuthEvent` is visible to the user in their dashboard and exportable. |
| **Envelope encryption w/ per-user keys** | Even with DB access, records aren't readable without the KMS/HSM-held keys; supports crypto-shred on erasure. |
| **Open source + reproducible builds** | The OP core is auditable. Anyone can verify what the code does. |
| **Third-party security audits + transparency reports** | Periodic external audits; published transparency reports on legal requests. |
| **(Later) Transparency log** | Append-only, publicly-verifiable log of *policy* events (e.g., key rotations, RP registrations) — never user data. |

### 2.3 Threat model

| Adversary | Concern | Mitigation |
|---|---|---|
| **The operator (us)** | We could be tempted (or compelled) to track users | PPID by construction; no profiling code paths; per-user encryption; minimal logs; open source so deviations are detectable |
| **Relying Parties** | RP tries to correlate users across apps, or over-collect | PPID; per-grant consented claims; no "email as universal ID" unless user opts in |
| **Network attackers** | MITM, token theft | TLS everywhere, HSTS, token binding/DPoP (phase 2), short-lived tokens |
| **Phishing / credential stuffing** | Account takeover | **Passkeys (WebAuthn) as primary factor** — phishing-resistant by design; passwords optional/deprecated |
| **Account takeover via recovery** | Recovery is the classic weak link | Multi-path recovery requiring possession + knowledge; no single email-reset backdoor (see §7.2) |
| **Legal / government requests** | Compelled disclosure | Per-jurisdiction data residency; we can only ever disclose what we hold (which is minimal); published transparency reports; PPID means we can't hand over a cross-service graph we don't have |
| **Insider threat** | Rogue employee | HSM-guarded keys, least privilege, audited admin actions, no bulk-decrypt capability |

### 2.4 Competitive & privacy positioning (Google vs Apple vs Harbor)

Harbor's north star for *user-facing* privacy UX is **Sign in with Apple**; our differentiator is extending that same protection to cover **the provider itself** and adding **sovereignty + openness** that neither Google nor Apple offers.

**The one-liner:** *Apple protects you from the apps. Harbor protects you from the apps **and from Harbor itself** — and doesn't lock you into a hardware ecosystem to get it.*

#### 2.4.1 The philosophical split

- **Google** monetizes identity: the login is a convenience that also feeds an advertising profile. Your **real Gmail address** is the durable cross-app key.
- **Apple** monetizes hardware/services and uses privacy as a *differentiator*: it deliberately severs the cross-app identifier (relay email, per-team `sub`, one-time data release). **But** Apple is still a central party that *sees* your logins — it just promises not to exploit them, and you're tied to the Apple ecosystem.
- **Harbor** monetizes the auth service directly (no ads, ever) and makes "we can't build a profile" a **technical property** (PPID, data-minimized logs, per-region residency, open source + audits), not merely a policy promise.

#### 2.4.2 The two Apple privacy features worth borrowing

1. **Private email relay** (`@privaterelay.appleid.com`): each app gets a *unique, per-app* random relay address that forwards to the user's real inbox; the user can deactivate any relay address as a per-app kill switch. Google has **no equivalent** — it hands apps the real Gmail address every time.
2. **Minimal, one-time data release**: Apple shares only name + email, and only on the *first* authorization; apps must capture it then. Google returns profile info (per requested scope) on **every** login.

#### 2.4.3 Technical differences at a glance

| Dimension | Sign in with Apple | Sign in with Google |
|---|---|---|
| Protocol | OIDC (OAuth 2.0) | OIDC (OAuth 2.0) |
| ID token | **JWT** (RS256) | **JWT** (RS256) |
| Client authentication | App generates a **signed JWT client secret** from a `.p8` key (ES256), ≤6 months | Static `client_secret` string |
| `sub` (subject) | Stable **per developer team**, opaque | Stable Google account id, paired with real email |
| Data returned | Name + email **once**; email may be a relay | Profile info per scope, **every** login |
| "Is it a relay?" signal | `is_private_email` claim | N/A |
| Provider's own use of the login graph | Sees it; promises not to exploit | Sees it **and actively uses it** |

#### 2.4.4 The privacy spectrum — where Harbor sits

| Property | Google | Apple | **Harbor (target)** |
|---|---|---|---|
| Per-app email masking | ❌ real email | ✅ relay email | ✅ relay **+ bring-your-own-domain** |
| Cross-app correlation **by RPs** | ❌ easy (real email) | ✅ blocked (per-team `sub`) | ✅ blocked (**PPID**, per-RP) |
| Cross-app correlation **by the provider** | ❌ Google does it | ⚠️ Apple *could* | ✅ **designed out** (PPID, minimal logs, verifiable) |
| Minimal data sharing | ❌ scope-hungry | ✅ name+email once | ✅ share *nothing* by default; selective-disclosure claims opt-in |
| Provider sees your login graph | ✅ yes & uses it | ✅ yes (promises not to) | ⚖️ minimized & technically constrained (sovereignty) |
| Ecosystem lock-in | Google account | Apple hardware | ✅ **none** — open, portable, standards-based |
| Data sovereignty / region pinning | Global | Global | ✅ **per-jurisdiction**, data never leaves region |
| Open / auditable | ❌ closed | ❌ closed | ✅ **open-source + third-party audited** |

#### 2.4.5 What we borrow, and where we deliberately go further

**Borrow from Apple:** (1) per-RP email relay (with optional bring-your-own-domain), (2) per-RP opaque identifier — our **PPID** (§3.2), (3) default-to-nothing / selective data release, (4) per-app kill switches in the dashboard.

**Beat Apple:** Apple's `sub` is stable **per developer team**, so a company with many apps *can* correlate you across all of them. Harbor's **PPID is per-RP registration**, tightening that boundary — and our data-minimization + sovereignty + open audit aim to make "we can't build a profile" a *technical* guarantee rather than a policy promise.

> **Note on the ID-token JWT:** all three providers use a **JWT for the ID token**, consumed by the RP exactly **once** at login (verified offline via JWKS), after which the RP creates its own session. Google's *access token*, by contrast, is **opaque** and server-side (instantly revocable, since Google is its own resource server). Harbor's token choices and why they differ are detailed in §3.5.

---

## 3. Protocol & Standards

### 3.1 Recommended stack

- **OpenID Connect (OIDC)** — we are a full **OpenID Provider (OP)**.
- **OAuth 2.1** semantics — Authorization Code flow **+ PKCE mandatory** for all clients (public and confidential). No implicit flow, no ROPC.
- **FIDO2 / WebAuthn / passkeys** — the **primary, phishing-resistant** authentication factor. Passwords are optional and, where used, always backed by a second factor.
- **SAML 2.0** — **deferred**. Only add when we pursue enterprise deals; it complicates the privacy story (SAML NameIDs, enterprise IdP semantics). Keep the core OIDC-clean; bolt SAML on as an isolated bridge later.
- **DPoP / token binding** — phase 2, to bind tokens to a client key and defeat token replay.

### 3.2 Pairwise subject identifiers (the anti-tracking core)

OIDC supports `subject_type = pairwise`. For each `(user, RP-sector)` pair we derive a stable, opaque `sub` — the **PPID** — that is the privacy linchpin of the whole system (see the positioning in §2.4). This section specifies exactly how it's derived, stored, and why it resists correlation *even by us*.

#### 3.2.1 Derivation

```
ppid = Base64URL( HMAC-SHA256( key = user_pairwise_secret,
                               msg = sector_identifier || user_id ) )
```

> **Implementation note:** the `||` concatenation is made **injective** by length-prefixing the sector (fixed-width big-endian length, then `sector`, then `user_id`), so distinct pairs can never encode to the same message (e.g. `("a","bc")` ≠ `("ab","c")`). See `internal/identity/ppid.go`.

| Input | What it is | Why |
|---|---|---|
| `user_pairwise_secret` | A high-entropy secret **generated per user** at signup, held **encrypted** in the user's home region | It is the HMAC **key**, not a message input, so the output is a keyed one-way function — irreversible and unforgeable without the secret. |
| `sector_identifier` | An identifier grouping an RP's redirect URIs (see §3.2.2) | Makes the `sub` **stable per RP** but **unrelated across RPs**. |
| `user_id` | The user's opaque internal id | Binds the `sub` to this specific user within the sector. |

**Why HMAC (not a plain hash or a stored random value):** HMAC-SHA256 is **keyed, deterministic, and one-way**. Deterministic ⇒ the same `(user, sector)` always yields the same `sub` (stable logins) without storing a row per pair up front. Keyed ⇒ nobody can compute or verify a `sub` without the secret. One-way ⇒ a leaked `sub` reveals nothing about the user or other RPs' `sub`s.

**Why a *per-user* secret key instead of a single global salt:** this is the crucial design choice. With a global salt/pepper, that one secret's compromise would let an attacker recompute **every** user's `sub` at **every** RP and deanonymize the entire population in one shot. With a **per-user** secret, there is **no single global secret** whose compromise breaks everyone — correlating a user across RPs requires *that specific user's* secret, which lives encrypted in their region behind the KEK/HSM (§4.4). The blast radius of any key compromise is one user, not the world.

> **KEK blast-radius footnote:** "one compromised key = one user" holds strictly **at the DEK layer** (the per-user pairwise secret is the DEK). The **regional KEK** that wraps every DEK in the region is a population-level single point: coercion or compromise of the KEK would allow bulk-unwrap of all per-user secrets in that region. The KEK must therefore be **HSM-bound, non-exportable, and incapable of bulk-unwrap in any API it exposes** (§7.3). This is a residual risk — see §A.7 (HSM vendor trust) and the explicit entry in §A.7 below.

#### 3.2.2 The `sector_identifier`

Per the OIDC spec, the sector groups an RP's redirect URIs so a single logical RP with many domains still sees **one** stable `sub`:

- By default the sector is derived from the host component of the RP's registered `redirect_uri`(s).
- An RP with multiple redirect hosts declares a **`sector_identifier_uri`** (a JSON array of its redirect URIs); Harbor uses that host as the sector so all of the RP's domains map to the same `sub`.
- **Two different RPs get different sectors**, hence **unrelated `sub`s** — they cannot join identities by comparing subjects.

**Sector granularity is a named design decision with product consequences:**

| Scenario | Consequence |
|---|---|
| `client_id` / `redirect_uri` rotation (RP rotates credentials) | As long as the `sector_identifier_uri` is stable, the `sub` is unchanged. RPs **must keep a stable sector**, not rotate it as they would a `client_secret`. |
| RP re-registration under a new sector | The `sub` changes — the RP sees a new user. This is intentional (a new sector = a new privacy context) but must be communicated clearly; migrating accounts requires an explicit **account-linking step** (see §3.2.6). |
| Vendor with many apps (multi-tenant RP) | Each app that registers as a separate RP with its own sector gets a different `sub`, blocking cross-app correlation even within one vendor — **tighter than Apple** (§2.4.5). A vendor that wants shared identity across its apps may share a `sector_identifier_uri`, but that is an explicit, deliberate opt-in. |

#### 3.2.3 Storage model

- `user_pairwise_secret` is **generated at signup**, **envelope-encrypted** (wrapped by the regional KEK per §4.4), stored **only in the user's home region**, **never logged**, and **never leaves the region**.
- The materialized `pairwise_sub` for each user↔RP grant is persisted in the **`grants` table** (§10, column `pairwise_sub`). At token-issuance time we read it from the grant (a cheap indexed lookup) rather than recomputing the HMAC on the hot path, and it also enables **reverse lookup** (`pairwise_sub → grant → user`) when an RP calls `/userinfo` or introspection.
- This `pairwise_sub` is exactly the value that appears as the ID-token **`sub`** in the §11.2 flow.

#### 3.2.4 Why even Harbor struggles to correlate users across RPs

This is a *strong-but-honest* guarantee, and it's worth being precise about it:

- There is **no plaintext `user → all RPs` table** exposed anywhere in the system. RPs only ever see their own per-sector `sub`.
- To join a single user across RPs, an operator would have to **decrypt that user's `pairwise_secret`** (KEK/HSM-gated, **audited**, with **no bulk-decrypt** capability) and recompute the HMAC per RP. That is **deliberately expensive, per-user, and auditable** — not a casual `SELECT`.
- **Honest framing:** Harbor-as-operator *could* compute a correlation *with* key access for a *specific* user — we don't claim mathematical impossibility. What we claim (and design for) is that it is **non-casual, one-user-at-a-time, audited, and detectable**, with **no global secret** that unlocks everyone. Contrast a naïve global-salt scheme, where one leaked secret silently deanonymizes the entire user base.

**Additional correlation surfaces that PPID does not close (and how they're handled):**

| Surface | Why it exists | How it's constrained |
|---|---|---|
| **SSO session (transient)** | Harbor *must* resolve browser session → real user in order to mint the right per-RP PPID. Transient cross-RP observation is structurally unavoidable for any SSO provider. | Hot-path **operational logs carry no per-user identifiers** (§6.5.3); session data is short-TTL and region-local; Harbor commits to not *persisting* or *building on* this transient signal. |
| **Relay email (persistent index)** | `relay_alias → real_email → user` is a co-equal correlation surface — in some ways larger than `sub`, since it maps to a real-world identifier. | Treated with **identical protection to `pairwise_secret`**: random, unlinkable per `(user, RP)`, envelope-encrypted, region-local, never logged (§7.5.1–§7.5.5). |
| **Grants reverse-index (deliberate capability)** | GDPR self-serve *requires* "show me all RPs I've connected" → a `user → all PPIDs` reverse lookup must exist. | This is a **controlled correlation point**: accessible only to the authenticated user themselves via the dashboard, and to audited admin ops. It is not a flaw; it is disclosed and access-controlled. |
| **Passkey credential (internal join key)** | Harbor is the WebAuthn RP; one credential authenticates the user across all downstream RPs — not leaked to RPs, but a Harbor-internal per-user handle. | Never exposed outside Harbor; region-local; covered by the same DEK/KEK envelope. |

**Net result:** RPs **cannot** join user identities across services at all; Harbor can only do so per-user, behind audited key access — a boundary that our open-source + third-party-audit posture (§2.2) makes verifiable. The residual surfaces above are disclosed, constrained, and access-controlled rather than absent. See §3.2.7 for the consolidated three-tier summary.

#### 3.2.5 Comparison: Apple vs Google vs Harbor subject identifiers

| Provider | `sub` scope | Correlation boundary |
|---|---|---|
| **Google** | Stable **per Google account**, paired with the real email | Trivial cross-app correlation (the real email is a universal key). |
| **Apple** | Stable **per developer team** | Blocks cross-*company* correlation, **but a single company with many apps can correlate you across *all* of them** (they share one team `sub`). |
| **Harbor (PPID)** | Stable **per RP registration / sector** | Tightest boundary: even two apps from the same company are separate RPs ⇒ **different `sub`s** (unless they deliberately share a `sector_identifier`). See §2.4 for positioning. |

#### 3.2.6 Edge cases

- **RP re-registration / sector change:** if an RP's `sector_identifier` changes (e.g., it re-registers under a new sector), the derived `sub` **changes**, which the RP will experience as a *new* user. This is the standard OIDC pairwise trade-off; RPs that need continuity must keep a **stable `sector_identifier_uri`**, and any intentional migration must be handled as an explicit **account-linking** step on the RP side.
- **The `sub` on the wire:** the `pairwise_sub` derived here is precisely what is emitted as the ID-token `sub` claim in the §11.2 walkthrough — RPs key their local account off it.
- **Result:** **RPs cannot join user identities across services**, and we deliberately keep no globally-joinable "one user id → all RPs" table exposed to RPs.

#### 3.2.7 Honest summary: three-tier privacy guarantee

Harbor's privacy promise bundles three guarantees of **different strength**. Being explicit about which tier is which keeps the claim honest and avoids the overclaiming that would undermine trust.

| Tier | Claim | Strength | How to verify |
|---|---|---|---|
| **1 — RP unlinkability** | Two colluding RPs comparing the `sub` they hold for the same user (identified out-of-band) see unrelated HMAC outputs — they cannot join identities by comparing subjects. | **Verifiable by construction.** Follows from the HMAC key being per-user and the sector being per-RP. Any third party can verify this from the source code alone. | Read `internal/identity/ppid.go`; run the non-correlation test vectors in `ppid_vectors_test.go`. |
| **2 — Operator technical constraint** | Harbor is architecturally constrained from *casual* or *bulk* correlation: no global secret, no bulk-decrypt API, per-user DEK, grants reverse-index is access-controlled + audited. Correlating one user requires per-user key access behind audited HSM ops. | **Strong, but trust-the-operator** until reproducible builds + transparency log ship (Phase 3, §2.2). The published source code is clean; the deployed binary must be verified to match it. | Reproducible builds (planned); third-party audits (planned); transparency log of key ops (planned). |
| **3 — Log / telemetry minimization** | Harbor commits to not persisting or building on the transient cross-RP signal it unavoidably touches during SSO. Hot-path logs carry no per-user identifiers; operational logs ≠ audit log; no behavioral profiling. Traffic/timing correlation (IP, geo) is **out of scope** — Harbor is not Tor; mitigation is log minimization only. | **Policy + design convention**, enforced by deny-by-default log field allow-listing (§6.5.3) and code review, but not cryptographically enforced. An insider could violate this without breaking the crypto. | Open-source audit; §6.5.7 privacy invariants for observability; `@harbor-reviewer` enforces in review. |

**Restatement of the headline:** *Harbor's stored identity model is unlinkable across RPs by construction (Tier 1 — independently verifiable). Harbor is architecturally constrained from casual or bulk operator correlation (Tier 2 — strong, attestation-dependent). Harbor commits to not persisting the cross-RP signal it must transiently touch during SSO (Tier 3 — policy + design convention, open to audit).*

This is stronger than Apple (Tier 1 is per-RP, not per-developer-team; §2.4.5) and stronger than any policy-only promise. It is honestly weaker than a claim of mathematical impossibility — which no SSO provider can make.

### 3.3 Token strategy — hybrid (this is the performance crux)

Two token classes, chosen deliberately for the privacy/perf trade-off:

| Token | Type | Verified by | Lifetime | Why |
|---|---|---|---|---|
| **ID Token** | Asymmetric-signed **JWT** (ES256/EdDSA) | RP, offline via **JWKS** | Short (~5 min) | RPs expect a JWT; standard OIDC. Contains only consented claims + PPID `sub`. (We deliberately pick **ES256/EdDSA** over RS256 for smaller tokens/signatures and faster verification.) |
| **Access Token** | **Asymmetric JWT** (default) *or* **opaque reference** (privacy-max mode) | Resource server via JWKS *or* introspection | Short (~5–15 min) | JWT = **zero DB hit on the hot path** → millions/sec cheaply. Opaque = revocable/introspectable for high-sensitivity RPs. RP chooses per-client. |
| **Refresh Token** | **Opaque, rotating**, one-time-use | Harbor only, DB-backed | Long, sliding | Enables revocation & session management; rotation detects theft. Not on the hot path. |

**Why JWT-by-default on the hot path:** verification is a signature check against a **cached JWKS** — no network call, no DB. This is what makes "millions/sec, low cost" achievable (see §6). Revocation of short-lived JWTs is handled by short TTLs + a small, edge-replicated **revocation bloom filter** for emergency kill.

**Privacy note on JWTs:** we keep ID/access token claims *minimal* (PPID `sub`, `aud`, `iss`, `exp`, and only consented claims). No email/name unless the RP's grant includes it.

### 3.4 Per-region issuer & discovery

Each region is its **own OIDC issuer**:

- `https://eu.harbor.id`, `https://us.harbor.id`, `https://au.harbor.id`, …
- Each publishes its own `/.well-known/openid-configuration` and `/.well-known/jwks.json`.
- The `iss` claim tells the RP (and any edge) exactly which region minted the token → routing and key discovery need **no global lookup**.

### 3.5 Token lifecycle & revocation

This section makes explicit the central tension behind the hybrid-token choice in §3.3.

#### 3.5.1 The core tension: a pure JWT cannot be revoked

A JWT is **self-contained and stateless**: the RP/resource server validates it by checking the signature against our public key (JWKS) and reading `exp` — **without ever calling back to Harbor**. That offline check is exactly what makes the hot path fast enough for millions/sec (§6.1). But it also means that **once issued, a JWT is valid until it expires** — there is no built-in "off switch". Speed *comes from* not talking to us; revocation requires talking to someone. These are in direct tension.

```
  1. sign in    ┌──────────┐  publishes public keys
  ────────────► │  Harbor  │  at /.well-known/jwks.json
                │   (OP)   │────────────┐
                └──────────┘            ▼
  2. JWT (signed, exp=+10m)      ┌──────────────┐
  ────────────────────────────► │ Relying Party │  verifies signature
                                 │  verifies     │  OFFLINE — no call
                                 │  LOCALLY  ⚡  │  back to Harbor.
                                 └──────────────┘
```

#### 3.5.2 The mechanisms, and what Harbor uses

| Mechanism | Revocation latency | Cost on hot path | Harbor usage |
|---|---|---|---|
| **Short-lived JWT + opaque refresh token** | ≤ access-token TTL | none (offline verify) | **Primary.** Access token ~5–15 min; "revoke" = delete the DB-backed refresh token, so no new access tokens are minted. |
| **Opaque access token + introspection** | instant | DB/network per call | **Opt-in per-RP** for high-security relying parties that need an instant kill. |
| **Revocation deny-list (bloom filter)** | near-instant | one in-memory lookup | **Emergency kill.** Compact, edge-replicated `jti`/session filter for compromised tokens; rare false positives fall back to introspection (§6.3). |
| **Signing-key rotation** | instant, mass | none | **Nuclear option** — suspected key compromise; rotate the regional JWKS `kid`. |

**The mental model:** with JWTs you don't revoke the *token*, you revoke the *ability to get a new one* — and keep the token short-lived enough that the difference doesn't matter.

#### 3.5.3 Harbor's concrete policy

| Scenario | Mechanism | Revocation latency |
|---|---|---|
| Default hot path (most RPs) | Short-lived JWT (~10 min) + opaque refresh token in regional DB | ≤ token lifetime |
| "Log out everywhere" / revoke app | Delete refresh token(s) for that user↔RP pairing | ≤ token lifetime |
| High-security RPs (opt-in) | Opaque access tokens + introspection (regional cache) | Instant |
| Compromised token(s) | Edge-replicated revocation bloom filter | Near-instant |
| Compromised signing key | Regional JWKS key rotation | Instant (that region) |

**Sovereignty-consistent:** the refresh-token store, introspection cache, and deny-list are all **per-region** (§5), so revocation never requires a cross-jurisdiction lookup.

#### 3.5.4 Reference: how Google does it

Google validates the same trade-off with a different mix, because *Google itself* is the resource server for its APIs:

- **ID token** = a **JWT**, read **once** by the RP at login, then discarded (the RP creates its own session). Nothing to revoke — it did its one job.
- **Access token** = **opaque** (`ya29.…`), validated server-side by Google → **instantly revocable**.
- **Refresh token** = **opaque**, long-lived, DB-backed → the real "off switch"; removing an app deletes it.

Harbor differs on the *access token*: because our resource servers are **third-party RPs** verifying tokens on their own infra, we default to **short-lived JWT access tokens** (offline-verifiable, for the millions/sec path) and reserve opaque+introspection as the opt-in. Google doesn't need that hot-path optimization because its API traffic is internal.

**Universal rule both designs share:** *never make the revocable, long-lived credential a JWT.* Keep the JWT short-lived and single-purpose; make the long-lived thing (refresh token / session) **opaque and server-side**.

---

## 4. High-Level Architecture

### 4.1 Guiding split: HOT path vs COLD path

```
                          ┌────────────────────────────────────────────┐
                          │              EDGE (per region)               │
        RP / Browser ───► │  Anycast + Ingress + CDN/edge cache          │
                          │   • /jwks.json         (cached, static-ish)  │
                          │   • /.well-known/*      (cached)             │
                          │   • token verify assets                     │
                          └───────────────┬───────────────┬─────────────┘
                                          │               │
                             HOT (stateless, cacheable)   COLD (stateful)
                                          │               │
                    ┌─────────────────────▼───┐   ┌───────▼────────────────────┐
                    │   auth-hot service       │   │   management plane          │
                    │   • /authorize (start)   │   │   • dashboard API (BFF)     │
                    │   • /token (code→token)  │   │   • RP/client registration  │
                    │   • /jwks, discovery     │   │   • consent management      │
                    │   • verify/introspect    │   │   • MFA/passkey enrollment  │
                    │   stateless + Redis cache │   │   • audit log query/export  │
                    └───────────┬──────────────┘   └───────────┬────────────────┘
                                │                              │
                    ┌───────────▼──────────────────────────────▼────────────┐
                    │   Regional data plane (this jurisdiction ONLY)          │
                    │   Postgres (primary + read replicas)  •  Redis          │
                    │   Regional KMS/HSM (per-region root keys)               │
                    └─────────────────────────────────────────────────────────┘
```

### 4.2 Modular monolith to start

One Go binary, **strong internal module boundaries** (packages with clear interfaces), deployable as separately-scaled processes via build tags / config so the **hot path scales independently** from the start:

- `oidc` — OP endpoints (authorize, token, jwks, discovery, introspect, userinfo).
- `webauthn` — passkey registration & assertion.
- `mfa` — TOTP, recovery codes, step-up.
- `identity` — users, credentials, pairwise-subject derivation.
- `clients` — RP registry & consent/grants.
- `audit` — append-only auth events.
- `crypto` — envelope encryption, key management, signing.
- `cache` — Redis + in-proc caches.
- `region` — region resolution & routing helpers.
- `addons/ageproof` — (future) verifiable-credential age proofs.

Split into separate services **only** where scale demands (the `oidc`/verify path first).

### 4.3 What we store — and what we deliberately DON'T

**We store (per region, encrypted at rest):**
- User account (opaque id, home region, status)
- Credentials: passkey public keys + WebAuthn metadata; optional password hash (Argon2id)
- MFA factors (encrypted TOTP secrets, hashed recovery codes)
- `user_pairwise_secret` (encrypted) for PPID derivation
- RP grants/consents (which RP, which scopes, when)
- Sessions & refresh tokens (opaque, hashed)
- Audit events (auth successes/failures the *user* can see)

**We deliberately DON'T store:**
- Any cross-RP behavioral profile
- RP-side activity ("what you did inside the app")
- Third-party tracking identifiers / ad data
- Plaintext secrets or recovery codes
- A globally-joinable "user → all RPs → real identity" table exposed to anyone

### 4.4 Encryption at rest

- **Envelope encryption**: per-user **Data Encryption Key (DEK)**, wrapped by a **regional Key Encryption Key (KEK)** held in that region's KMS/HSM.
- Sensitive columns (TOTP secrets, pairwise secret, recovery material, optional PII claims) are encrypted with the user DEK.
- **Crypto-shred on erasure**: destroy the user DEK → data is unrecoverable, satisfying GDPR erasure even against immutable backups.

---

## 5. Multi-Jurisdiction Routing Design

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

---

## 6. Kubernetes Deployment & Performance Engineering

**Target: millions of token verifications/sec, single-digit-ms, low cost.**

### 6.1 Why it's cheap: stateless verification

- Access/ID tokens are **asymmetric-signed JWTs**. Verification = fetch JWKS **once**, cache it, then do **signature checks in-memory**. **No DB, no Redis, no network** per verification.
- JWKS + discovery are **static-ish and edge/CDN-cached** with long TTLs (keyed by `kid`; rotate keys with overlap).
- Resource servers verify tokens **themselves** using our public keys — much of the verification load never even hits us.

### 6.2 Per-region cluster topology

- **`auth-hot` Deployment**: stateless, aggressively **HPA**-scaled on RPS/CPU, thin, in-proc LRU cache of JWKS + client metadata + revocation bloom filter. Runs many cheap replicas.
- **`management` Deployment**: dashboard/BFF, enrollment, consent, audit — modest scale, stickier, DB-heavy.
- **Postgres**: primary + read replicas; hot reads (client lookups, grants) served from replicas + Redis.
- **Redis**: short-TTL caches (auth codes, client config, rate-limit counters, session lookups), not on the JWT-verify path.
- **Internal transport**: **gRPC** between services; **REST/OIDC** at the protocol edge.

### 6.3 Emergency revocation without killing performance

- Short token TTLs (5–15 min) bound exposure.
- A compact, **edge-replicated revocation bloom filter** (token id / session id) lets us kill compromised tokens fast without a per-request DB lookup. False positives fall back to introspection (rare).

### 6.4 Observability & abuse-prevention WITHOUT tracking

- Metrics are **aggregate & non-identifying** (RPS, latency, error rates per region/RP — never per-user profiles).
- **Rate limiting / brute-force**: keyed on transient signals (IP hash + short window, RP, credential id) with short-lived counters in Redis, **not** durable per-user behavioral logs.
- **Anomaly detection**: velocity/geo-impossibility checks on ephemeral data only; nothing retained beyond the security window.

### 6.5 Observability & SLOs

This extends §6.4: it specifies *how* we observe the system while keeping the **no-tracking promise (§2.1–§2.2)** intact. The guiding rule is simple — **observability tells us how the *system* is doing, never what a *user* is doing.** Every telemetry signal is aggregate, PII-free, and region-scoped.

#### 6.5.1 Aggregate-only metrics

- Metrics are **counters/histograms with low-cardinality labels only**: `region`, `endpoint`, coarse `client_id`, `status`, `factor_type`. **Never** per-user labels — no `user_id`, no `email`, no `IP`, no PPID as a label. (`client_id` is **RP-level, not user, data** and is kept coarse enough to avoid RP-behavior profiling, so it stays "aggregate & non-identifying" per §2.2.)
- **The cardinality trap is also the privacy trap:** a user-identifying label would both explode metric cardinality (cost/perf) **and** violate the no-tracking promise. So it's **forbidden by construction**, not merely discouraged — the two failure modes reinforce each other, which is convenient.
- **RED** on the hot path (§6.1) — **R**ate, **E**rrors, **D**uration per endpoint/region; **USE** (Utilization/Saturation/Errors) for resources. Prometheus-style pull, aggregated at the regional collector.
- Consistent with §2.2, the **hot path emits only aggregate, non-identifying metrics** — no per-user analytics, ever.

#### 6.5.2 Tracing without PII

- **OpenTelemetry** distributed tracing for latency analysis and debugging — but spans carry **zero PII**: no user id, email, token contents, PPID, or relay address.
- Correlation is via **opaque request/correlation ids** that are **not linkable to a user** and are not persisted against user records.
- **Span attributes are deny-by-default allow-listed** (a scrubbing processor drops anything not explicitly permitted), so PII can't leak into a span even by accident.
- **Tail-based sampling** keeps tracing cheap on the millions/sec path (sample the interesting tails — errors, slow spans — not every request). Traces are **short-retention**.

#### 6.5.3 Structured logging (not the audit log)

- **Structured JSON logs at boundaries only** — log the **event *type*** and **coarse outcome** (e.g. `token_issue`, `ok`/`denied`), **not the subject**. **No request bodies, tokens, secrets, or PII.** Redaction is enforced via **deny-by-default field allow-listing**.
- **These are operational logs, not the user-facing audit log.** The **audit log** (§4.3, §11.6) is a *separate*, **user-owned**, per-region record the user can see and export; operational logs hold **no behavioral profile** and are not a shadow audit trail. Keeping them distinct is deliberate — operational logs are ephemeral diagnostics; the audit log is a durable, user-visible artifact.

#### 6.5.4 Per-region dashboards & telemetry residency

**Telemetry itself is region-scoped** — this is a first-class sovereignty property, not an afterthought:

- Metrics, traces, and logs are **collected and stored in the same jurisdiction** as the data plane they observe (§5). Raw per-user or region-local telemetry **never** flows into a global stack.
- A **global view** is built **only** from **aggregate, non-identifying rollups** (e.g. "EU hot-path p99 = 3ms, error rate = 0.01%") — no raw events, no cross-region PII.
- **Per-region dashboards** cover: the **hot path** (RPS, p50/p95/p99, error rate, saturation), the **cold path** (dashboard/mgmt latency & errors), and **dependencies** (Postgres, Redis, KMS/HSM health).

#### 6.5.5 SLOs & error budgets

We define explicit SLOs and let **error budgets drive release policy** (§1.8): when a service burns its budget, **feature deploys freeze** and effort shifts to reliability until the budget recovers.

| Service | SLI | SLO target | Notes |
|---|---|---|---|
| Hot path — token verify/issue | Successful, in-budget responses | **99.99%** availability | Statelessness (§6.1) makes this achievable cheaply. |
| Hot path — latency | Requests under the p99 budget | **p99 ≤ single-digit ms** | Offline JWKS verify keeps this flat under load (§6.1). |
| Cold path — dashboard/mgmt | Successful responses | **99.9%** availability | Looser; not on the auth critical path. |
| OIDC discovery / JWKS | Availability of `/.well-known/*`, `/jwks.json` | **99.99%** | Edge/CDN-cached (§6.1), so effectively static. |
| Refresh / revocation | Successful refresh & revoke ops | **99.95%** | DB-backed (§3.5); regional. |

**Alerting on budget burn** uses **multi-window, multi-burn-rate** logic: a **fast burn** (budget being consumed quickly) **pages**; a **slow burn** opens a **ticket**. This avoids both alert fatigue and silent slow degradation.

#### 6.5.6 Alerting

- **Alert on symptoms / SLO burn** (user-facing: error rate, latency, availability), **not** on noisy causes. **Page on fast burn, ticket on slow burn** (per §6.5.5).
- **Security-relevant alerts** fire on **aggregate** signals only — never per-user tracking: spikes in **auth failures**, **PKCE/nonce/state** validation failures (§11.7), **revocation-bloom** lookup rates, and **key-rotation** events (§7.3).
- **All alerts are per-region**, so an incident is attributed to and handled within its jurisdiction (§5).

#### 6.5.7 Privacy invariants for observability (non-negotiable)

- **No PII in metrics labels, trace spans, or logs** — ever (no user id/email/IP/PPID/relay/token).
- **Deny-by-default attribute allow-listing** for spans and log fields; redaction enforced in the pipeline.
- **Telemetry is region-scoped**; only aggregate, non-identifying rollups leave a region.
- **Short retention** for metrics/traces/logs; **no third-party analytics or SDKs** in any surface (§2.2, §9).
- **Ephemeral abuse-detection signals only** (§6.4) — nothing retained beyond the security window.
- **Operational logs ≠ audit log** (§4.3, §11.6): the audit trail is the *only* user-linked record, and it's user-owned.

---

## 7. Security Design

### 7.1 Passkeys / MFA

- **Passkeys (WebAuthn) are primary.** Phishing-resistant, no shared secret. Support platform + roaming authenticators; encourage 2+ passkeys per account.
- **TOTP** as a secondary/step-up factor for users without passkeys.
- **Step-up auth** for sensitive operations (adding a passkey, changing recovery, connecting a high-trust RP).

### 7.2 Account recovery (the hardest problem) — recommendation

A privacy-first product **cannot** have a simple "email a reset link" backdoor (it's the #1 ATO vector and undermines the security story). Recommended layered approach, **user picks at least two**:

1. **Multiple passkeys** (encouraged default) — losing one device ≠ lockout.
2. **One-time recovery codes** — generated at enrollment, shown once, stored **hashed**; user keeps them offline.
3. **Hardware security key** as a dedicated recovery authenticator.
4. **(Opt-in) Social recovery** — user designates M-of-N trusted guardians who jointly approve recovery; no single party (including us) can recover alone.

We **never** unilaterally reset an account. Recovery requires **possession + knowledge** the user pre-registered. This is a deliberate, communicated trade-off: stronger security, so recovery must be set up in advance.

### 7.3 Key management

- **Regional KMS/HSM** holds KEKs and token-**signing** keys. Signing keys are asymmetric (ES256/EdDSA); private key never leaves the HSM boundary.
- **Rotation with overlap**: publish new `kid` in JWKS, sign new tokens with it, keep old public key until all old tokens expire.
- **Per-user DEKs** wrapped by regional KEK; enables crypto-shred.

### 7.4 Secure defaults

- PKCE mandatory, exact redirect-URI matching, `state`/`nonce` enforced.
- Argon2id for any passwords; short token TTLs; rotating one-time refresh tokens with reuse-detection.
- Strict CSP, HSTS, secure cookies (`HttpOnly`, `SameSite`), no third-party scripts in auth UI.

### 7.5 Per-RP email relay (Hide-My-Email)

A core privacy feature borrowed from Apple (§2.4.2) and offered on the consent screen (§11.2, step 3): each RP gets a **unique, per-app random relay address** that forwards to the user's real inbox, so the user's **real email is never shared by default**. Apps can email the user; they never learn the user's real address, cannot use it as a cross-app identifier, and can be **cut off individually**.

#### 7.5.1 Address generation

- Format: `<opaque-token>@relay.<region>.harbor.id` (e.g. `x7f3q9a2@relay.eu.harbor.id`). The subdomain is **region-scoped** so inbound routing and data residency stay consistent with §5.
- The `<opaque-token>` is **randomly generated and unlinkable** — it is **not** derived from the user id in any way an RP could reverse or correlate. Two RPs' relay addresses for the same user look completely unrelated.
- **One relay address per `(user, RP)` grant.** A mapping row `relay_address → user → client_id` is stored **encrypted at rest** in the user's **home region** (never replicated cross-region, per §5).
- Because the address embeds only the region (not the user), the mapping table is the *only* thing that links a relay address back to a person — and it lives behind the same regional encryption as the rest of the user's PII.

#### 7.5.2 Forwarding infrastructure

Inbound MX for `relay.<region>.harbor.id` points at a **regional inbound mail service** that, per message:

1. **Looks up** the relay mapping (`relay_address → user + client_id`); unknown address ⇒ reject.
2. **Checks the address is active** and authenticates the sending domain via **SPF / DKIM / DMARC alignment** (anti-spoofing). Note this authenticates *who sent it*, not *that it's the paired RP*: a relay address accepts mail from **any authenticated sender**, so we lean on rate-limiting and per-address kill switches (§7.5.4, §7.5.6) — not sender allow-listing — to contain abuse.
3. **Rewrites and forwards** the message to the user's real address, **ARC-sealing** on forward so downstream inboxes still trust it after we've relayed it.
4. **(Phase 2) Reply-through:** outbound rewrite so a user can *reply* to the app without leaking their real address — the reply egresses from the relay address.

Operational notes:

- **We become a forwarder**, so deliverability is a first-class concern: correct SPF/DKIM for our relay domains, **ARC sealing**, per-address **rate limits**, and edge **spam filtering**.
- **No content retention / no tracking:** we keep only minimal routing metadata needed to forward and rate-limit; **message bodies are never logged or stored** (consistent with the no-tracking promise, §2.1–§2.2).

#### 7.5.3 Bring-your-own-domain (BYO-domain)

Advanced users can point **their own domain** (or a subdomain) at Harbor, so relay addresses become e.g. `x7f3q9a2@mail.alice.example`:

- Delivers **vanity + provider-independence** (the user isn't tied to `harbor.id` for their masked mail).
- Requires **DNS verification** (a TXT challenge) plus **MX / SPF / DKIM** setup; Harbor publishes the exact records to add.
- The domain is still **region-pinned** — inbound processing happens in the user's home region regardless of the vanity domain.

#### 7.5.4 Per-app deactivation (the email kill switch)

- The dashboard lets the user **deactivate any relay address** independently. Deactivated ⇒ inbound mail is refused with a **hard bounce** (recommended over silent-drop, so legitimate senders learn the address is gone rather than silently losing mail).
- This is an **instant, per-app email kill switch**: leaked/spammy app ⇒ kill its address; every other app is unaffected.
- **Independent of the RP grant:** deactivating the relay does **not** revoke the login, and revoking the login (§11.3) does not by itself require killing the relay — the user can cut email while keeping access, or vice versa.

#### 7.5.5 Data-sovereignty consistency

- The relay **mapping table and all inbound mail processing live entirely in the user's home region**; the MX subdomain is **region-scoped** (`relay.<region>.harbor.id`).
- **No cross-region replication** of relay mappings or mail contents — mail for an `eu` user is only ever processed in EU. Ties directly back to §5.

#### 7.5.6 Abuse & privacy safeguards

- **Per-address rate limiting** to contain spam/abuse without per-user behavioral logging.
- Users can see **aggregate-only** per-RP volume ("App X sent you 12 emails this week") — never message contents or sender-level tracking.
- **(Optional) tracking-pixel stripping** on forward, to blunt open-tracking by senders.
- **No content retention** — nothing beyond ephemeral routing/rate-limit state.

#### 7.5.7 Relay states

| State | Inbound behavior | Notes |
|---|---|---|
| **Active** | Forwarded to the user's real inbox (after SPF/DKIM/DMARC checks, ARC-sealed) | Default on first consent; one address per (user, RP). |
| **Deactivated** | **Hard bounce** (address refused) | Instant per-app kill switch; independent of the RP login grant. |
| **BYO-domain** | Forwarded via the user's own verified domain (`x@mail.alice.example`) | Region-pinned; requires DNS/MX/SPF/DKIM verification. |

---

## 8. Go Backend Design

### 8.1 Recommended libraries

| Concern | Choice | Why |
|---|---|---|
| **OIDC OP** | **`zitadel/oidc`** | Actively maintained, purpose-built for building an OP (not just a client), supports the flows we need. (`ory/fosite` is the main alternative — powerful but lower-level/more work.) |
| **WebAuthn** | **`go-webauthn/webauthn`** | De-facto standard Go passkey library. |
| **DB access** | **`pgx`** + **`sqlc`** | `pgx` = fast native Postgres driver; `sqlc` = compile-time-checked typed queries from SQL. No heavy ORM on the hot path. |
| **REST codegen** | **`oapi-codegen`** | Generates Go server stubs + models from OpenAPI 3.1 (spec-first, see §1). |
| **gRPC codegen** | **`buf`** + `protoc-gen-go`/`-go-grpc` | Lint, breaking-change checks, and typed stubs from Protobuf. |
| **Migrations** | **`golang-migrate`** (or `goose`) | Simple, versioned SQL migrations. |
| **Cache** | **`redis`** + in-proc LRU (`hashicorp/golang-lru`) | Redis for shared short-TTL state; in-proc for JWKS/client metadata. |
| **Crypto** | stdlib `crypto` + cloud KMS SDK | Keep crypto boring and standard. |
| **Config/DI** | plain constructors + `viper`/env | Avoid magic. |

### 8.2 Project layout

```
harbor/
├── cmd/
│   ├── harbor-hot/        # auth-hot binary (OIDC/verify)
│   └── harbor-mgmt/       # management/dashboard API binary
├── internal/
│   ├── oidc/              # OP endpoints, token issuance
│   ├── webauthn/          # passkey register/assert
│   ├── mfa/               # TOTP, recovery codes, step-up
│   ├── identity/          # users, credentials, PPID derivation
│   ├── clients/           # RP registry, grants, consent
│   ├── audit/             # append-only auth events
│   ├── crypto/            # envelope encryption, signing, KMS
│   ├── cache/             # redis + in-proc
│   ├── region/            # region resolution/routing
│   ├── addons/ageproof/   # (future) verifiable credentials
│   └── gen/               # ALL generated code (never hand-edited); internal/ hides it from importers
│       ├── openapi/       # Go server/client from OpenAPI
│       ├── proto/         # Go gRPC stubs from Protobuf
│       └── db/            # sqlc-generated typed queries
├── db/
│   ├── migrations/
│   └── queries/           # sqlc source (SQL = the contract)
├── api/                   # CANONICAL CONTRACTS (source of truth, see §1)
│   ├── openapi/           # REST specs: dashboard/BFF, RP-mgmt, admin
│   ├── proto/             # internal gRPC service + message contracts
│   └── json-schema/       # shared data models ($ref'd by OpenAPI)
├── deploy/                # k8s manifests / helm per region
└── docs/
```

### 8.3 API styles (spec-first, see §1)

- **Protocol endpoints**: standard **OIDC/REST** (must be spec-compliant for RPs); validated against OIDC/WebAuthn **conformance suites**.
- **Internal service-to-service**: **gRPC**, contract defined in Protobuf under `api/proto/` and code-generated.
- **Dashboard / RP-management / admin APIs**: **REST**, contract defined in OpenAPI 3.1 under `api/openapi/`; Go server stubs and the TypeScript client are **both generated** from it, so backend and frontend never drift.
- GraphQL is intentionally avoided for now: REST keeps the security-sensitive surface small, easy to audit, and trivially spec-first.

---

## 9. Frontend Design

**Recommendation: Next.js (React) + TypeScript.**

- Largest ecosystem for WebAuthn/passkey UX, easiest to hire for, mature security patterns.
- Use it as a **BFF**: browser talks to Next.js server routes; secrets/tokens stay server-side in `HttpOnly` cookies (no tokens in `localStorage`).
- **Typed API client is generated from the backend's OpenAPI spec** (`openapi-typescript` / `orval`); the frontend **never hand-writes request/response types** (see §1.3). Change the spec → regenerate → the compiler flags every affected call site.
- Screens:
  - **Auth UI** (hosted by Harbor): login, passkey prompt, consent screen (shows exactly which claims an RP requests), step-up.
  - **Dashboard**: connected apps (view/revoke per-RP grants), sessions & devices (revoke), passkeys (add/remove), MFA & recovery setup, **audit log viewer + export**, data export/delete (GDPR).
- Zero third-party trackers/analytics in the auth + dashboard surfaces (consistency with the promise).

*(SvelteKit is a fine lighter alternative; React chosen for ecosystem/hiring and passkey library maturity.)*

---

## 10. Data Model (sketch)

> Every user-owned table carries a `region` column; sensitive columns are **envelope-encrypted** (🔒). All lives in the user's home region only.

```sql
-- Region is encoded in ids and issuer; PII never crosses regions.

users (
  id            uuid pk,          -- opaque, region-prefixed externally
  region        text,             -- 'eu' | 'us' | ...  (home jurisdiction)
  status        text,             -- active | locked | erased
  dek_wrapped   bytea 🔒,         -- per-user DEK, wrapped by regional KEK
  pairwise_secret bytea 🔒,       -- for PPID derivation
  created_at    timestamptz
)

credentials (                      -- passkeys (primary) + optional password
  id            uuid pk,
  user_id       uuid fk,
  type          text,             -- 'passkey' | 'password'
  webauthn_pubkey bytea,          -- COSE public key
  webauthn_aaguid bytea,
  sign_count    bigint,
  password_hash bytea 🔒,         -- Argon2id, only if type='password'
  created_at    timestamptz
)

mfa_factors (
  id            uuid pk,
  user_id       uuid fk,
  type          text,             -- 'totp' | 'recovery_code' | 'hardware_key'
  secret        bytea 🔒,         -- encrypted TOTP secret
  code_hash     bytea,            -- hashed recovery code
  used          bool
)

relying_parties (                  -- RP/client registry (NO user data)
  client_id     text pk,
  name          text,
  sector_id     text,             -- groups redirect URIs for PPID
  redirect_uris text[],
  token_format  text,             -- 'jwt' | 'opaque'
  scopes_allowed text[]
)

grants (                           -- user↔RP consent
  id            uuid pk,
  user_id       uuid fk,
  client_id     text fk,
  pairwise_sub  text,             -- PPID this RP sees for this user
  scopes        text[],           -- consented claims only
  created_at    timestamptz,
  revoked_at    timestamptz
)

sessions (
  id            uuid pk,
  user_id       uuid fk,
  device_label  text,
  refresh_token_hash bytea,       -- opaque, rotating, one-time-use
  expires_at    timestamptz,
  revoked_at    timestamptz
)

audit_events (                     -- user-visible auth trail
  id            uuid pk,
  user_id       uuid fk,
  event_type    text,             -- login_success | login_fail | grant_added | ...
  client_id     text,
  occurred_at   timestamptz
  -- deliberately: NO cross-RP profiling, NO RP-internal activity
)
```

**PPID derivation** (§3.2): `pairwise_sub = B64URL(HMAC-SHA256(pairwise_secret, sector_id || user_id))`.

---

## 11. Key User Flows

### 11.1 Passkey registration (enrollment)
1. User creates account in their home region (region chosen at signup, encoded in id).
2. Browser calls WebAuthn `create()`; Harbor stores the passkey public key + metadata.
3. User is prompted to set up **recovery** (≥2 methods) and optionally a 2nd passkey/TOTP.
4. `pairwise_secret` and DEK generated, wrapped by regional KEK, stored 🔒.

### 11.2 OIDC login to an RP (Authorization Code + PKCE) — full walkthrough

The wire format is **standard OIDC** — any Google/Auth0-compatible client library works against Harbor unchanged. Harbor's differences live in *what the tokens contain* (PPID, relay email, minimal claims) and *where the issuer lives* (regional), **not** in the shape of the flow. This makes Harbor a drop-in privacy upgrade.

#### Endpoints (per regional issuer, e.g. `https://eu.harbor.id`)

Discoverable at `/.well-known/openid-configuration`:

| Purpose | Harbor endpoint |
|---|---|
| Authorization | `/authorize` |
| Token | `/token` |
| JWKS (public keys) | `/jwks.json` |
| UserInfo | `/userinfo` |
| Introspection | `/introspect` |
| Revocation | `/revoke` |

#### Step 0 — RP is registered (once)

The RP developer registers and receives a `client_id`. Public clients (SPA/mobile) use **no secret** (PKCE replaces it); confidential clients may also get a `client_secret`. The RP pre-registers exact `redirect_uri`(s) — an **exact-match allowlist**.

#### Step 1 — RP prepares the request (PKCE begins)

Client-side, the RP generates:

```
code_verifier  = random 43–128 char URL-safe string   (kept secret)
code_challenge = BASE64URL( SHA256( code_verifier ) )   (sent in step 2)
state          = random anti-CSRF value (stored in the user's session)
nonce          = random value (bound into the ID token, anti-replay)
```

**Why PKCE:** it proves the app that *redeems* the code is the same one that *started* the flow, so a stolen authorization code is useless without the original `code_verifier`. This is what removes the need for a client secret.

#### Step 2 — Redirect the user to `/authorize`

```
GET https://eu.harbor.id/authorize
  ?response_type=code
  &client_id=rp_abc123
  &redirect_uri=https://app.example.com/callback
  &scope=openid%20email%20profile
  &state=xyz789
  &nonce=n-9f2c
  &code_challenge=E9Melh...a1c
  &code_challenge_method=S256
```

`openid` in `scope` is what makes this OIDC. `state`/`nonce` provide CSRF + replay protection.

#### Step 3 — Harbor authenticates the user (the Harbor-specific part)

1. Validate `client_id`; verify `redirect_uri` **exactly matches** a registered URI (never redirect to an unregistered URI).
2. If no active Harbor session → show login → **passkey (WebAuthn)** primary factor, then MFA if required. *(This is the fast, cached auth core.)*
3. **Consent screen** shows exactly which claims the RP requests, and surfaces privacy options: **share a relay email** instead of the real one, and **per-RP PPID** so the RP can't correlate the user elsewhere.
4. User approves → grant recorded.

#### Step 4 — Harbor redirects back with an authorization code

```
302 https://app.example.com/callback?code=SplxlOB...S6WxSbIA&state=xyz789
```

`code` is short-lived (~30–60s) and **single-use**. The RP **must verify `state`** matches what it stored (else drop — CSRF). The code is safe in the URL because it's useless without the `code_verifier`.

#### Step 5 — RP exchanges the code for tokens (back-channel)

```
POST https://eu.harbor.id/token   (application/x-www-form-urlencoded)
  grant_type=authorization_code
  &code=SplxlOB...S6WxSbIA
  &redirect_uri=https://app.example.com/callback
  &client_id=rp_abc123
  &code_verifier=dBjftJeZ4CVP...bU3      ← the ORIGINAL secret from step 1
```

Harbor verifies: (a) the code exists, is unexpired, and **unused** (reuse ⇒ revoke everything — theft signal); (b) `SHA256(code_verifier) == code_challenge` from step 2 — **the PKCE check**; (c) `redirect_uri`/`client_id` match. On success:

```json
{
  "token_type": "Bearer",
  "expires_in": 600,
  "id_token": "eyJhbGciOiJFUzI1Ni…",   // JWT identity assertion
  "access_token": "…",                  // short-lived JWT (default) or opaque
  "refresh_token": "…"                  // opaque, rotating, regional DB
}
```

#### Step 6 — RP validates the ID token (JWT), once

Fetch `/jwks.json` (cached, matched by the JWT `kid`), verify the signature, then check: `iss == https://eu.harbor.id`, `aud == rp_abc123`, `exp` not passed, and **`nonce` == the step-1 nonce**. Decoded payload:

```json
{
  "iss": "https://eu.harbor.id",
  "sub": "PPID_9f83a2…",              // PER-RP pairwise id — not reusable elsewhere
  "aud": "rp_abc123",
  "exp": 1730000900, "iat": 1730000600,
  "nonce": "n-9f2c",
  "email": "x7f3@relay.harbor.id",    // relay address, not the real email
  "email_verified": true,
  "name": "Alex"                       // only if the user chose to share it
}
```

The **`sub` is Harbor's PPID** (§3.2) — the privacy linchpin. The same user at a different RP gets a completely different `sub`.

#### Step 7 — RP establishes its own session

The RP reads `sub` (+ any consented claims), looks up/creates its local user, and issues **its own session cookie**. From here the Harbor tokens aren't needed for the app session — which is why "log out of Harbor" ≠ "log out of every app."

#### Step 8 — (Optional) UserInfo & refresh

- **UserInfo:** `GET /userinfo` with `Authorization: Bearer <access_token>` returns the same PPID-keyed claims (often skipped, since the ID token already carries them).
- **Refresh:** near expiry, `POST /token` with `grant_type=refresh_token` mints a new access token without user interaction. Revoking that refresh token (dashboard or `/revoke`) is what actually cuts access (§3.5).

#### Sequence diagram

```
 RP                          Browser                      Harbor OP (eu.harbor.id)
  │  build verifier+challenge   │                               │
  │  state, nonce               │                               │
  │────302 to /authorize───────►│                               │
  │                             │───GET /authorize?…S256───────►│
  │                             │                               │ login (passkey + MFA)
  │                             │                               │ consent (relay email, PPID)
  │                             │◄──302 /callback?code&state────│
  │◄──GET /callback?code&state──│                               │
  │  verify state                                               │
  │──POST /token (code + code_verifier)────────────────────────►│  PKCE check, code single-use
  │◄── id_token(JWT) + access_token + refresh_token ────────────│
  │  verify id_token via /jwks.json (iss, aud, exp, nonce)      │
  │  create OWN session cookie                                  │
  ▼                                                             ▼
```

**Hot-path note:** the RP/resource server verifies the JWT **offline via cached JWKS** — no call back to Harbor. This is the millions/sec path (§6.1).

#### Harbor's deliberate deviations from a vanilla Google-style flow

| Aspect | Google | Harbor |
|---|---|---|
| PKCE | Recommended | **Mandatory for all clients** (OAuth 2.1) |
| `sub` | Stable per account | **PPID — per-RP**, uncorrelatable |
| `email` | Real Gmail address | **Relay address** by default |
| Primary auth | Password/passkey | **Passkey-first** |
| Issuer | Single global | **Per-jurisdiction** (`eu.`/`us.`…), data stays in region |
| Default claims | Returned every login | **Minimal by default**, selective disclosure |
| Access token | Opaque | **Short-lived JWT** (hot path) / opaque opt-in (§3.5) |

### 11.3 Add / remove a connected app
- Add: happens implicitly via first consent (§11.2, step 3 — the consent screen).
- Remove: dashboard → revoke grant → future logins require fresh consent; existing refresh tokens revoked; short-lived access tokens expire naturally (or bloom-filter kill).

### 11.4 MFA setup & step-up
- Setup: enroll TOTP or additional passkey in dashboard.
- Step-up: sensitive actions (edit recovery, connect high-trust RP) force a fresh strong assertion.

### 11.5 Account recovery
- User initiates recovery → must satisfy pre-registered methods (§7.2): e.g., a recovery code **+** a second passkey, or M-of-N social guardians. No unilateral operator reset.

### 11.6 GDPR view / export / delete
- **View/Export**: dashboard exports account data + audit log (JSON).
- **Delete**: destroy the user DEK (**crypto-shred**) → data unrecoverable even in backups; audit retains only minimal, legally-required, non-identifying records for the mandated window, then purged.

### 11.7 OIDC error cases & security validations

Every step of the Authorization Code + PKCE flow (§11.2) has failure modes, and OAuth/OIDC prescribe **exactly** how to signal each one. Getting this right is security-critical: sloppy error handling leaks whether accounts/clients exist, or worse, opens redirect-based token-exfiltration. Harbor follows RFC 6749 (§4.1.2.1, §5.2), OIDC Core, and RFC 6750 to the letter.

#### Two error channels

Errors surface on one of two channels depending on *where* they're detected:

- **(a) Authorization-endpoint errors** (`/authorize`) → **302 redirect** back to the RP's **registered** `redirect_uri` with `error`, `error_description`, and the echoed `state` as query parameters.
  - **Critical exception:** if `client_id` is unknown **or** `redirect_uri` is missing/doesn't exactly match a registered URI, Harbor **MUST NOT redirect**. It renders an **error page** in the browser instead. Redirecting an error to an unvalidated URI would let an attacker aim Harbor's response (and any leaked parameters) at a URI they control — an open-redirect / exfiltration vector. The redirect target must be *proven trusted* before it's ever used, even for errors.
- **(b) Token-endpoint errors** (`/token`) → **HTTP 400** (or 401 for client-auth failures) with a JSON body `{ "error": …, "error_description": … }`. No redirect is involved (this is a back-channel call).

A third, RP-side channel exists for **ID-token validation** (`state`, `nonce`, signature): these are enforced by the *RP*, not Harbor — Harbor's job is only to *supply* the bindings correctly (echo `state`, embed `nonce`, sign with a JWKS-published key).

#### Authorize phase (`/authorize`)

| Error case | Harbor validation | Response (code · HTTP · channel) |
|---|---|---|
| Unknown `client_id` | Client exists in registry | **Error page**, no redirect (channel a exception) |
| Missing / mismatched `redirect_uri` | **Exact-match** against registered allowlist | **Error page**, no redirect (channel a exception) |
| Missing/invalid `response_type` (not `code`) | Only `code` supported | `unsupported_response_type` · 302 · redirect |
| Client not allowed this flow/scope combo | Client policy check | `unauthorized_client` · 302 · redirect |
| Unknown / disallowed `scope` (missing `openid`, etc.) | Validate against `scopes_allowed` | `invalid_scope` · 302 · redirect |
| Malformed request (missing `state`/`nonce` where required, bad `code_challenge_method`) | Param presence/shape; **PKCE required** (`S256`) | `invalid_request` · 302 · redirect |
| User rejects the consent screen | User action | `access_denied` · 302 · redirect |
| `prompt=none` but no session / consent / interaction needed | Silent-auth check | `login_required` / `consent_required` / `interaction_required` · 302 · redirect |
| Internal fault | — | `server_error` · 302 · redirect |
| Overloaded / maintenance | — | `temporarily_unavailable` · 302 · redirect |

Example authorize-phase error redirect (note the echoed `state`):

```
302 https://app.example.com/callback
      ?error=invalid_scope
      &error_description=The%20requested%20scope%20is%20unknown%20or%20not%20permitted
      &state=xyz789
```

#### Token phase (`/token`)

| Error case | Harbor validation | Response (code · HTTP · channel) |
|---|---|---|
| Bad client authentication (confidential client) | Verify `client_secret` / client-auth JWT | `invalid_client` · **401** · JSON (add `WWW-Authenticate` if the client used the `Authorization` header) |
| Expired authorization code | Code TTL (~30–60s) | `invalid_grant` · 400 · JSON |
| **Reused** authorization code | Code is **single-use** | `invalid_grant` · 400 · JSON — **and revoke all tokens minted from that code** (theft signal, see §3.5) |
| **PKCE mismatch** — `SHA256(code_verifier) != code_challenge` | Recompute & compare (constant-time) | `invalid_grant` · 400 · JSON |
| `redirect_uri` / `client_id` don't match the authorize request | Bind code to original params | `invalid_grant` · 400 · JSON |
| Unsupported `grant_type` | Only `authorization_code` / `refresh_token` | `unsupported_grant_type` · 400 · JSON |
| Revoked / unknown / rotated-away refresh token | Lookup + rotation/reuse detection | `invalid_grant` · 400 · JSON (reuse ⇒ revoke the token family) |
| Missing/malformed params | Param validation | `invalid_request` · 400 · JSON |

Example token-endpoint error (single-use code reused):

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "error_description": "Authorization code is invalid, expired, or already used"
}
```

#### ID-token / RP-side validation

These are enforced by the **RP** on the tokens Harbor returns; Harbor's responsibility is to make them *verifiable*.

| Error case | Who validates | Harbor's role |
|---|---|---|
| **`state` mismatch** (CSRF) | **RP** compares returned `state` to the value it stored | Harbor **echoes `state` verbatim** on every authorize response (success *and* error); it never interprets it. A mismatch ⇒ the RP drops the response. |
| **`nonce` mismatch** (replay) | **RP** compares the ID token's `nonce` claim to the value it sent in step 1 | Harbor **binds the request `nonce` into the ID token**. This defeats token replay/injection: an attacker can't reuse an old ID token because its `nonce` won't match a fresh request. |
| Bad signature / wrong `kid` | **RP** verifies against `/jwks.json` | Harbor signs with an asymmetric key (ES256/EdDSA) whose public half is published in JWKS (§3.5). |
| `iss` / `aud` / `exp` wrong | **RP** | Harbor sets `iss` = the regional issuer, `aud` = the `client_id`, and a short `exp`. |

#### Resource-server / UserInfo (RFC 6750)

When a token is presented to `/userinfo` or an RP's own resource server:

| Error case | Validation | Response |
|---|---|---|
| **Missing** `Authorization` header (no credentials) | Bearer scheme check | `401` + plain `WWW-Authenticate: Bearer` (no `error` code) |
| **Malformed** `Authorization` header | Bearer scheme check | `400` + `WWW-Authenticate: Bearer error="invalid_request"` |
| Expired / revoked / bad-signature token | JWKS verify (or introspection for opaque) | `401` + `WWW-Authenticate: Bearer error="invalid_token"` |
| Token lacks the required scope | Scope check | `403` + `WWW-Authenticate: Bearer error="insufficient_scope"` |

Example `401` for an invalid/expired access token:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  error_description="The access token is expired or has been revoked"
```

#### Security invariants (non-negotiable)

- **Exact `redirect_uri` match** against a pre-registered allowlist — and **never** send an error (or anything else) to an unvalidated URI.
- **Authorization codes are single-use**; reuse ⇒ `invalid_grant` **and** revoke every token minted from that code (assume theft, §3.5).
- **PKCE verification is mandatory** for every client — `SHA256(code_verifier)` must equal the stored `code_challenge`.
- **`state` (CSRF) and `nonce` (replay)** are enforced by the RP; Harbor guarantees the bindings (echo `state`, embed `nonce`) on every response.
- **Generic `error_description`s** — never reveal whether a *user account* or *client* exists, or *why* auth failed beyond the standard code (defeats enumeration).
- **Constant-time comparisons** for codes, PKCE challenges, secrets, and tokens.
- **`Cache-Control: no-store`** on all token responses; short code TTLs (~30–60s).

---

## 12. Compliance & Governance

- **GDPR / CCPA**: data minimization and purpose limitation are built-in; per-region residency; DSАR (access/export/delete) self-serve in dashboard.
- **Data residency**: enforced by region-encoded identifiers + region-local storage/keys; no cross-region PII replication.
- **Right-to-erasure vs immutable audit**: reconciled via **crypto-shred** (destroy DEK) + minimal, time-boxed, non-identifying security records.
- **Legal / government requests**: we can only disclose what we hold (minimal, region-scoped). PPID means **we don't possess a cross-service identity graph to hand over**. Publish periodic transparency reports.

---

## 13. Age-Proof Add-On (future)

Privacy-preserving age verification via **verifiable credentials + selective disclosure**, so a user can prove `age_over_18` **without revealing birth date or identity**:

- **Formats**: **SD-JWT VC** (selective disclosure) and/or **ISO/IEC 18013-5 mDL** `age_over_NN` attributes; align with **W3C Verifiable Credentials 2.0** and the **W3C Digital Credentials API**; interoperate with **eIDAS 2.0 / EU Digital Identity Wallet**.
- **ZK / BBS+**: selective disclosure (and eventually ZK predicates) let us present *only* the boolean age assertion.
- **Model**: Harbor acts as issuer/holder-facilitator; the RP gets a signed `age_over_18 = true` and nothing else. Fits the no-tracking ethos perfectly.

---

## 14. Phased Roadmap / MVP

**Architected day-one (even if not fully scaled): PPID, per-region issuer scheme, JWT hot-path, envelope encryption, and the spec-first/codegen toolchain (§1).** These are hard to retrofit, so bake them in early.

**Phase 0 — MVP (single region, ship in ~months)**
- Go modular monolith: OIDC OP (auth code + PKCE), passkey login, TOTP + recovery codes.
- PPID `sub` from day one.
- Next.js dashboard: connected apps, sessions, passkeys, audit log, GDPR export/delete.
- Postgres + Redis, envelope encryption, JWT tokens verified via JWKS.
- Contracts-first from commit one: `api/openapi` + `api/proto` in place, codegen + spec-lint + breaking-change checks wired into CI.
- One region, but **all identifiers already region-prefixed** so multi-region is additive.

**Phase 1 — Performance hardening**
- Split `auth-hot` from `management`; HPA; edge/CDN JWKS caching; revocation bloom filter; load-test to millions/sec.

**Phase 2 — Multi-jurisdiction**
- Second region (e.g., US alongside EU); global PII-free control plane + region resolver; host-based edge routing.

**Phase 3 — Trust & enterprise**
- DPoP/token binding; social recovery; transparency log; third-party audit; (optional) SAML bridge for enterprise.

**Phase 4 — Add-ons**
- Age-proof verifiable credentials; further selective-disclosure claims.

---

## 15. Risks, Open Questions & Key Trade-offs

| # | Decision | Trade-off | Recommendation |
|---|---|---|---|
| 1 | **JWT vs opaque access tokens** | JWT = fast/cacheable/no-DB but revocation is coarse; opaque = revocable but needs introspection (DB/network) | **Hybrid**: JWT default (perf), opaque opt-in per-RP for high sensitivity; short TTLs + bloom-filter kill. |
| 2 | **Account recovery** | Strong (no email backdoor) vs user friction / lockout risk | Mandate ≥2 pre-registered methods; encourage multiple passkeys; opt-in social recovery. Communicate clearly. |
| 3 | **Region encoding** | Region-prefixed ids/issuers are simple & lookup-free but "leak" region and complicate account moves | Accept it; region isn't sensitive; support explicit (rare) region migration as a heavy operation. |
| 4 | **zitadel/oidc vs ory/fosite** | zitadel = higher-level/faster to build; fosite = more control/more work | **zitadel/oidc** for MVP velocity; revisit if we need lower-level control. |
| 5 | **Modular monolith vs microservices** | Monolith = fast to build/operate; micro = independent scale | Monolith with clean seams; split **only** the hot path first. |
| 6 | **SAML now vs later** | Enterprise reach vs privacy-model complexity | **Later**, isolated bridge. Keep core OIDC-clean. |
| 7 | **Global control plane existence** | Any global component is a residency/attack risk | Keep it **PII-free** (RP registry + routing only); consider signed static regional config instead. |
| 8 | **RP over-collection** | RPs may demand email/name as universal id, undermining PPID | Default PPID; email/name only via explicit per-grant consent; educate RPs. |
| 9 | **OpenAPI for "every" interface** | One spec language is simpler, but OpenAPI is awkward for gRPC and can't redefine OIDC/WebAuthn | **Spec-first everywhere, best native contract per surface**: OpenAPI (REST), Protobuf (gRPC), SQL/`sqlc` (DB), standards+conformance (protocol edge). All codegen-driven (§1.4). |

**Open questions to resolve next:**
- Which cloud/KMS/HSM per region (AWS KMS+CloudHSM, GCP, or self-hosted Vault+HSM)?
- Exact regional footprint at launch (EU-only first, or EU+US)?
- Business model (per-auth pricing? RP subscription?) — informs the control-plane billing design.
- Do we host the RP-facing consent UI, or offer a headless option?

---

*Next step: turn Phase 0 into a concrete implementation plan (repo scaffold, contract definitions in `api/`, DB schema migrations, OIDC endpoints, passkey flow, dashboard).*

---

## Appendix A — Threat Model Deep-Dive (STRIDE)

This appendix expands the high-level threat model in §2.3 with a **per-component STRIDE analysis**. §2.3 is the summary (adversary-oriented); this appendix is the detailed, component-oriented expansion. Most mitigations already exist elsewhere in the design — this appendix *maps* them to concrete threats rather than inventing new controls.

**STRIDE legend:** **S**poofing (identity) · **T**ampering (integrity) · **R**epudiation (deniability) · **I**nformation disclosure (confidentiality) · **D**enial of service (availability) · **E**levation of privilege (authorization).

We analyze each trust-boundary component separately because their risk profiles differ sharply: the hot path is a stateless, internet-facing verification surface; the KMS is a small, extremely-high-value secret store; the relay is an inbound-mail surface; and so on.

### A.1 Components & trust boundaries

| # | Component | What it is | Design refs |
|---|---|---|---|
| (a) | **Hot path** (`harbor-hot`) | `/authorize`, `/token`, `/jwks`, discovery, verify/introspect — stateless, internet-facing | §4.1, §6.1 |
| (b) | **Cold path / management plane** | Dashboard/BFF, enrollment, consent, audit, admin | §4.1, §6.2 |
| (c) | **KMS/HSM & signing keys** | Per-region KEKs + token-signing keys; per-user DEKs | §4.4, §7.3 |
| (d) | **Email relay** | Inbound MX + forwarding for `relay.<region>.harbor.id` | §7.5 |
| (e) | **Global control plane** | PII-free RP registry + region resolver | §5.3 |

```
            ┌── (e) GLOBAL control plane (PII-FREE) ──┐
            │   RP registry · region resolver         │  no keys, no user data
            └───────────────┬─────────────────────────┘
   ==============  trust boundary: nothing sensitive crosses  ==============
            ┌───────────────▼──────────── REGION (jurisdiction) ───────────┐
   internet │  (a) HOT path ⚡         (b) COLD path 🔒                     │
   ────────►│  authorize/token/jwks    dashboard/consent/admin             │
            │        │                      │                             │
            │        └──────┬───────────────┘                             │
            │        (c) KMS/HSM 🔑    (d) Email relay ✉ (inbound MX)      │
            │        per-region keys   opaque→real forwarding             │
            └──────────────────────────────────────────────────────────────┘
```

### A.2 Hot path (`harbor-hot`) — §4.1, §6.1

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Forged JWT, stolen bearer token, phishing of credentials | Asymmetric **JWKS-verified** signatures (§3.5); **passkeys** are phishing-resistant (§7.1); **PKCE mandatory** (§11.2); **DPoP/token-binding** planned (§3.1, phase 2) to bind tokens to a client key. |
| **T** | Claim/token tampering; **JWKS poisoning** (swap in an attacker key) | Signature verification on every token; JWKS served over **TLS** and matched by **`kid`** (§3.4); keys originate only from the HSM (§7.3). |
| **R** | User denies initiating an authentication | **User-owned audit log** of every `AuthEvent` (§4.3, §11.6). |
| **I** | Token/claim leakage; **cross-RP correlation** from `sub` | **Minimal claims** in tokens (§3.3); **PPID** `sub` per RP (§3.2); TLS in transit; short TTLs (§3.5). |
| **D** | Verification flood; key-rotation storms; auth-code brute force | **Stateless offline verify** — resource servers verify via cached JWKS with no callback (§6.1); **edge/CDN cache** for JWKS/discovery; **HPA** autoscaling (§6.2); **rate-limiting** on ephemeral signals (§6.4). |
| **E** | Scope/`aud` escalation; **algorithm-confusion** (`alg:none`, RS↔HS downgrade) | **Strict signing-alg allow-list** (ES256/EdDSA only — **no `alg:none`, no symmetric fallback**); exact **`scope`/`aud`/`redirect_uri`** checks (§11.7). |

### A.3 Cold path / management plane — §4.1, §6.2

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Session hijack; **CSRF** on dashboard actions | **Passkey step-up** for sensitive ops (§7.1); **`HttpOnly`/`SameSite`** cookies (§7.4); `state` on OAuth flows (§11.7). |
| **T** | Grant/consent tampering; **mass-assignment** on management APIs | Per-object authorization checks; **contract-validated inputs** (§1.2) — no vague payloads; deny-by-default fields. |
| **R** | User disputes a grant/revocation | **Audit log** records grant add/remove and admin actions (§4.3). |
| **I** | PII over-exposure via dashboard/API responses | Authorization + **data minimization** (§2.2); **region residency** so responses never carry cross-region PII (§5). |
| **D** | Enrollment / endpoint abuse floods the management plane | **Rate-limiting**; management plane **scales separately** from the hot path so abuse can't starve auth (§6.2). |
| **E** | **IDOR**; escalate to another user or **another region**; admin abuse | **Per-object authz**; **region checks** on every access; **least-privilege, audited admin** actions with **no bulk-decrypt** (§2.3). |

### A.4 KMS/HSM & signing keys — §4.4, §7.3

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Impersonate the token signer | Signing **private keys never leave the HSM boundary** (§7.3); public half only in JWKS. |
| **T** | Unauthorized key use or rotation | **HSM access control**, **audited key operations**, **rotation-with-overlap** so rotations are controlled and reversible (§7.3). |
| **R** | Dispute over who used/rotated a key | **All key operations are audited** (§7.3). |
| **I** | Key extraction; per-user **DEK** exposure; **bulk decrypt** | **Envelope encryption** (per-user DEK wrapped by regional KEK, §4.4); **no bulk-decrypt capability** (§2.3); **per-region KEK** contains blast radius. |
| **D** | Signing throughput limits; KMS outage | Public **JWKS cached at the edge** so **verification survives KMS blips** (§6.1); capacity planning; verify path never calls the HSM. |
| **E** | Insider uses keys to **deanonymize** users | **Per-user pairwise secret** (no global secret, §3.2); **no bulk decrypt**; least privilege + audit + **separation of duties** (§2.3). |

### A.5 Email relay — §7.5

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Spoofed sender to a relay address; phishing *via* the relay | **SPF/DKIM/DMARC alignment** authenticates the sender domain (§7.5.2). *Caveat:* a relay address accepts mail from **any authenticated sender**, not only the paired RP — so we lean on rate-limits + kill switches, not sender allow-listing (§7.5.2). |
| **T** | Message altered in transit on forward | **ARC sealing** on forward so downstream inboxes still trust the relayed message (§7.5.2). |
| **R** | Dispute over whether mail was delivered | **Accepted trade-off (privacy over non-repudiation):** we keep only minimal routing metadata and **retain no message content** (§7.5.2), so we deliberately *cannot* prove delivery of a message's contents — consistent with the no-tracking promise (§2.2). |
| **I** | Real-email leak; **relay→user** linkage | **Opaque, unlinkable** relay addresses (§7.5.1); **encrypted, region-local mapping** table; **no content retention** (§7.5.2, §7.5.5). |
| **D** | Mail-bomb a relay address | **Per-address rate limits** (§7.5.6) + instant **hard-bounce kill switch** (§7.5.4). |
| **E** | Abuse relay as an **open relay / spam amplifier** | **Inbound-only forwarding** — no arbitrary outbound send; reply-through is gated and phase-2 (§7.5.2). |

### A.6 Global control plane — §5.3

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Fake **region resolver**; **RP-registry poisoning** | **Signed static config** + TLS; the plane holds **no PII/keys**, so spoofing it leaks nothing sensitive (§5.3). |
| **T** | Tamper an RP's `redirect_uri`/`sector` to hijack codes | **Signed registry**; **exact `redirect_uri` match** at `/authorize` (§11.7); reviewed RP registration. |
| **R** | Dispute over an RP registry change | **Change-audited** registry. |
| **I** | Disclosure of what the plane holds | **PII-free by design** (§5.3) — a breach leaks RP metadata + routing only, **no user data**. |
| **D** | Resolver becomes a **global chokepoint** | Resolver **reads only the region prefix** and is **cacheable / replaceable by signed static regional config** (§5.1, §5.3); not on the per-auth data path. |
| **E** | Compromise → **pivot into a region** | Control plane holds **no keys and no PII** and **cannot authenticate as a user**; **regions are isolated** (§5.4) so there is no lateral path into a jurisdiction's data. |

### A.7 Cross-cutting residual risks & assumptions

- **Operator-with-key-access correlation:** as stated honestly in §3.2.4, an operator holding a *specific* user's key *could* correlate that one user across RPs — but only **per-user, audited, non-bulk**. There is **no global secret** that deanonymizes everyone. This is a deliberate, disclosed residual.
- **HSM vendor trust:** we assume the KMS/HSM boundary holds; a vendor-level compromise is out of our direct control (mitigated by per-region isolation and rotation).
- **KEK bulk-unwrap (population-level risk):** the regional KEK wraps every per-user DEK in the region. While PPID's per-user secret limits blast radius at the DEK layer, the KEK itself is a population-level single point of failure. The KEK must be HSM-bound, non-exportable, and its API must expose **no bulk-unwrap operation** — only per-key unwrap with individual audited calls (§3.2.1, §7.3). Coercion of the KEK bypasses the per-user isolation guarantee.
- **Supply chain:** malicious dependency or build tampering — mitigated by **reproducible builds** (§2.2) and **dependency/SAST/secret scanning** (§1.7, §1.8), but never fully eliminated.
- **Recovery social-engineering:** the account-recovery flow is a classic attack surface — mitigated by requiring **≥2 pre-registered methods and no email backdoor** (§7.2), but human factors remain.
- **Bearer-token theft window:** until **DPoP/token-binding** ships (§3.1, phase 2), a stolen access token is usable within its **short TTL** (§3.5). Short TTLs bound, but don't eliminate, this until binding lands.

### A.8 Priority mitigations to bake in day-one

The highest-leverage controls — cheap to include now, painful to retrofit:

1. **Asymmetric-only signing alg allow-list** — ES256/EdDSA only; reject `alg:none` and any symmetric/HS fallback (A.2 **E**).
2. **PKCE everywhere** — mandatory for all clients (§11.2).
3. **Exact `redirect_uri` match** — pre-registered allowlist, never redirect to an unvalidated URI (§11.7, A.6 **T**).
4. **Per-user pairwise secret** — no global correlation secret (§3.2).
5. **No bulk-decrypt capability** — structurally absent, not merely policy (§2.3, A.4 **I/E**).
6. **PII-free global control plane** — a control-plane breach must leak zero user data (§5.3).
7. **Region isolation** — no cross-region PII, keys, or lateral auth path (§5.4).
