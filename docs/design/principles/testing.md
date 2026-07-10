> **DESIGN §1.7** · [↑ DESIGN index](../../DESIGN.md) · prev: [contracts-and-codegen](contracts-and-codegen.md) · next: [cicd](cicd.md)

# Testing Strategy

## 1.7 Testing strategy (independently *and* as a system)

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
