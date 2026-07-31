# Full-codebase audit — 2026-07-30

> **Status:** findings only, no fixes applied. Scope: every hand-written Go file
> (~28k LOC), all 17 migrations, `api/openapi/harbor.yaml`, `deploy/k8s`,
> `deploy/helm`, `.github/workflows`. Build clean; `go test ./...` fully green at
> time of audit (commit `67dd7c2`, branch `docs/t2-t3-hardening-plans`).

## Executive summary

The **library layer is strong** — pure-core/IO-shell separation, the
type-level PII allow-list in `internal/telemetry/labels.go`, the PPID injectivity
argument, the auth-code DoS ordering in `Service.Token`, the refresh-rotation
commit-point analysis. That work is sound and should be preserved.

**Nearly every finding below lives at the wiring seam.** `cmd/harbor-hot/main.go`
and `cmd/harbor-mgmt/main.go` assemble the production binaries out of the *dev
scaffolds* while the DB-backed, security-critical implementations sit unused.
The test suite is green because every test builds its own object graph from
fakes; **nothing asserts what `main()` actually wires**.

Twelve security-critical constructors exist in the tree and are referenced
nowhere outside their own package + tests:

```
NewRedisAuthCodeStore    NewDBClientRegistry       NewJWTVerifier
NewRevocationWorker      NewBloomRevocationFilter  NewDBRevokedJTIStore
NewRevocationSubscriber  NewStepUpGate             RecordTOTPStepUp
DBSessionStore (in hot)  WithEnrollmentSessions    WithClientRegistration
```

**Root cause:** the "optional dependency, degrade gracefully" pattern
(`if pool != nil` / `WithX(nil)` → noop or 503). Each optional dep forks the
object graph; the fake branch is the tested one and the real branch is the
shipped one. See [Recommendation](#recommendation-collapse-to-one-object-graph).

---

## Critical

### C1 — All of harbor-mgmt's user API authenticates off a client-supplied header

`internal/mgmtapi/consent.go:46` defines `UserIDHeader = "X-Harbor-User-ID"`.
Every user-scoped endpoint reads it straight off the request:

- `consent.go:70,119` · `relay.go:70,115,237,334,372,451,529`
- `compliance.go:67,112` · `audit.go:106` · `mfa.go:77` · `recovery.go:258,556`

Comments claim it is "set by upstream authentication middleware." **No such
middleware exists.** `cmd/harbor-mgmt/main.go:376` wires `bff.Middleware`, which
populates the request *context*, never the header. Nothing in `deploy/k8s/` or
`deploy/helm/` strips it (no `proxy_set_header` / `more_clear_input_headers`
anywhere in the tree).

Impact — universal read/write/destroy across every account:

```bash
curl -X POST  .../compliance/export   -H 'X-Harbor-User-ID: <victim>'  # full DSAR bundle
curl -X POST  .../compliance/erase    -H 'X-Harbor-User-ID: <victim>'  # irreversible shred
curl -X DELETE .../mfa/factors/x      -H 'X-Harbor-User-ID: <victim>'  # disable victim MFA
```

`e2e/recovery_test.go:54` uses this header *as its auth mechanism*, so the e2e
suite institutionalises the bug.

**Fix:** delete `UserIDHeader`; read `bff.UserIDFromContext(r.Context())` in every
handler, as `internal/bff/dashboard.go` already does correctly.

### C2 — `/admin/keys/rotate` and `/admin/revoke-jwt` unauthenticated on the public ingress

`internal/oidcapi/admin_keys.go:26-28` asserts "Admin authentication is enforced
by middleware wired in front of this handler." It is not.
`cmd/harbor-hot/main.go:242-243` is the entire chain:

```go
base := openapi.HandlerFromMux(srv, mux)
handler := oidcapi.WithRateLimits(base, buildRateLimits(redisClient, logger))
```

`api/openapi/harbor.yaml:222-311` — both admin paths document a `401` but carry
**no `security:` block** (contrast `/userinfo` at `:207`). oapi-codegen's
`HandlerFromMux` does not enforce security schemes regardless; there is no
request-validator middleware.

`deploy/k8s/ingress.yaml` routes `path: /` `Prefix` to harbor-hot. `s.rotator` is
non-nil whenever `DATABASE_URL` is set. Therefore:

```bash
curl -X POST 'https://auth.example.com/admin/keys/rotate?emergency=true'
```

is an unauthenticated, repeatable total outage — emergency rotation uses zero
grace *and* zero overlap (`crypto/rotator.go:213-222`), retiring the old key from
JWKS immediately and invalidating every outstanding token.

### C3 — Login session fixation → account takeover

`internal/bff/login.go:99,148` sets the browser's `__Host-harbor-bff` cookie to
whatever `request_id` arrives **in the URL query string**. The request_id is
minted at `/authorize` on harbor-hot and handed over via redirect, so there is no
browser binding at creation time — an attacker-initiated request_id is
indistinguishable from a victim-initiated one.

1. Attacker starts `/authorize` with **their own** `client_id` + `redirect_uri`,
   captures `request_id=R`.
2. Lures victim to `https://mgmt.harbor.id/login?request_id=R`.
3. Victim's browser gets cookie `=R`, does a normal-looking passkey assertion,
   POSTs `/login/complete`.
4. `FinishLoginWithParsedData` writes the **victim's** userID into session `R`
   (`login.go:279`).
5. `GetAuthorizeComplete` (`oidcapi/authorize.go:216-245`) reads `request_id`
   **from the query string** with no cookie comparison, issues a code for the
   victim, redirects it to the **attacker's** `redirect_uri`.

`SameSite=Strict` does not help: step 2 is a top-level navigation (cookie is
*set* normally) and step 3 is same-site.

**Fix:** bind request_id to the browser before any credential is presented — set
the cookie at `/authorize`, and require `ReadBFFCookie(r) == requestID`
(constant-time) at both `/login` and `/authorize/complete`.

### C4 — `/introspect` and `/revoke` client authentication is a no-op

`internal/oidcapi/auth.go:73-86` — `validateClientCredentials` looks up the client
and then `_ = secret`. Worse, `PostIntrospect` (`introspect.go:31-51`) never calls
it: it takes the Basic-auth **username verbatim** as the authenticated
`clientID`, with no registry lookup at all. The Introspector's cross-client
isolation (`oidc/introspect.go:225`) is defeated by claiming to be whichever
`client_id` the token's `aud` names.

`PostRevoke` is the same shape — `parseBasicAuth` succeeding (any non-empty
username) is the whole gate, then `revokeAccessToken` passes `IsAdmin: true` to
bypass cross-client checks (`revoke.go:150`).

Knock-on: `/register` mints and stores `client_secret` hashes, but `/token` never
verifies them, so every RFC 7591 `client_secret_basic` client is functionally
public. Discovery tells the truth (`discovery.go:71`,
`token_endpoint_auth_methods_supported: ["none"]`), contradicting
`register_validate.go:74-78`.

---

## High

### H1 — harbor-hot ships the dev scaffolds as production

`cmd/harbor-hot/main.go:156-189`:

- `oidc.NewInMemoryClientRegistry()` seeded with a live **`demo-client`**
  (redirect `http://localhost/callback`) on every deployment, unconditionally.
- **No RP can ever be registered.** `DBClientRegistry` is never used;
  `WithClientRegistration` is never called → `/register` returns 503. There is no
  path to add a client.
- `oidc.NewInMemoryAuthCodeStore()` — auth codes are per-process. With
  `hpa.maxReplicas: 20`, `/token` fails whenever the exchange lands on a
  different pod than `/authorize`. `RedisAuthCodeStore` exists (Lua atomic
  consume) and is never wired.
- **Unbounded memory growth:** `InMemoryAuthCodeStore` never evicts
  (`oidc/store.go:160-194`) — `Save` inserts, `Consume` tombstones, nothing
  deletes. Every `/authorize` grows the map permanently.
- **`offline_access` refresh tokens are never issued.** `SessionStore` defaults
  to `noopSessionStore`; the in-memory `grantStore` makes `FindGrant` miss, so
  `issueRefreshToken` bails at `service.go:536`.

### H2 — RP-initiated logout never logs anyone out

`cmd/harbor-hot/main.go:196-197`: `logoutVerifier` is declared nil and never
assigned; `sessionRevoker` is `noopSessionRevoker{}`. `endSession`
(`oidcapi/end_session.go:85`) short-circuits to `redirectLoggedOut` when these are
nil. `/end_session` is a cosmetic redirect: no revocation, no `id_token_hint`
verification, `post_logout_redirect_uri` never honoured. `NewJWTVerifier` is never
constructed anywhere in the tree.

### H3 — Emergency revocation is entirely dead

Bloom filter, `revoked_jtis` (migration 0010), `RevocationWorker`, Redis pub/sub
subscriber, `RehydrateFilter` — all exist, none instantiated. `s.revoked == nil`
→ `/admin/revoke-jwt` 503; `s.filter == nil` → `Introspect` and
`JWTVerifier.Verify` skip revocation entirely.

Latent amplification once wired: with C2 unfixed, an attacker floods arbitrary
JTIs into the filter. If `RevokedChecker` is nil, `confirmRevocation` returns
`true` for any bloom hit (`introspect.go:263-266`, `jwt_verifier.go:236-239`) —
saturating the filter fail-closes the whole fleet.

### H4 — `/userinfo` accepts expired access tokens forever

`internal/oidcapi/userinfo.go:95-97` documents it: *"It does NOT check expiry."*
No `exp` check, no revocation check. A token leaked from a log or proxy cache
works for the lifetime of the signing key. Directly contradicts the design's
"short TTL is the revocation story" premise.

### H5 — `JWTVerifier` holds one key and ignores `kid`

`internal/oidc/jwt_verifier.go:98-106` extracts a single `pubKey` from
`cfg.Signer`. `Verify` reads `h.Kid` only to check `alg`, never to select a key.
During any rotation overlap — the window the entire `signing_keys` state machine
exists to provide — tokens signed by the non-active key fail verification.
`Introspector.publicKeyByKID` and `Server.publicKeyByKID` both do this correctly.

Related inconsistency: `Introspector.Introspect` never checks `iss` (accepts
cross-region tokens); `JWTVerifier` and `/userinfo` both do. Three verification
paths, three rule sets.

### H6 — Revoking consent does not revoke consent

Two parallel consent tables:

| Table | Migration | Read by |
|---|---|---|
| `grants` | 0001 | `PPIDSessionResolver.Resolve`, `Service.Refresh`, `end_session` |
| `consent_grants` | 0011 | `mgmtapi` consent endpoints, dashboard |

`DELETE /consent-grants/{client_id}` revokes the `consent_grants` row and
cascades session revocation, but leaves the `grants` row untouched. Next
`/authorize`: `PPIDSessionResolver.Resolve` finds the surviving grant
(`resolver.go:150`) and returns `approved=true` silently, with no consent prompt.
The user's "disconnect this app" does not disconnect the app.

### H7 — TOTP has no brute-force protection, and MFA is never enforced

`mfa.Service.Verify` does a bare `totp.Validate` with `totpSkew = 1` (~90s
acceptance) and no attempt counter. `POST /mfa/verify` has no rate limiter —
**harbor-mgmt has no rate limiting on any endpoint**. Six digits, unlimited
attempts.

Moot in practice: MFA is inert. `StepUpGate` and `RecordTOTPStepUp` are never
called, so a successful `/mfa/verify` sets no session state and nothing consults
`MFAVerifiedAt`. `WithRecoveryRateLimiter` is likewise never called →
`/recovery/complete` unlimited.

### H8 — Passkey enrollment is impossible as wired

`cmd/harbor-mgmt/main.go:359` calls `webauthn.RegisterRoutes(mux, svc)`, which
builds a handler with **no** enrollment session store, so `userIDFromRequest`
(`webauthn/handlers.go:152-164`) returns `501` for all four ceremony endpoints.
`mgmtServer` never calls `WithEnrollmentSessions`, so `POST /enroll` sets no
cookie either.

No passkey can be registered → no discoverable credential exists →
`BeginDiscoverableLogin` has nothing to assert against → **the login flow cannot
complete for any user**. As wired, there is no working authentication path.

---

## Medium

### M1 — The k8s manifests cannot boot either binary

`deploy/k8s/` has drifted from the code:

| Manifest sets | Code reads | Effect |
|---|---|---|
| `HARBOR_KEK_SECRET` (secret-mgmt) | `HARBOR_KMS_SECRET` | mgmt fatal-exits with `DATABASE_URL` set |
| `WEBAUTHN_RP_NAME` (configmap-mgmt) | `WEBAUTHN_RP_DISPLAY_NAME` | silently wrong RP name |
| `WEBAUTHN_ORIGIN` (configmap-mgmt) | `WEBAUTHN_RP_ORIGINS` | falls back to `localhost` → all ceremonies fail |
| *(nothing)* | `REGION` | mgmt hits the `region.Resolve` boot invariant, `os.Exit(1)` |

The Helm chart is better but still blocked:

- `deploy/helm/templates/secret-hot.yaml` provides `KEK_SECRET` but **not**
  `HARBOR_KMS_SECRET` (required by `buildBFFDepsFromPool`) and no `LOGIN_URL`
  (required by `validateProductionReadiness`) → harbor-hot refuses to start.
- `deployment-mgmt.yaml` comments *"harbor-mgmt does not use Redis"* — false.
  mgmt uses Redis for the **BFF session store** and the **WebAuthn session
  store** (`main.go:104-139`). Without it, mgmt writes BFF sessions to process
  memory while hot reads them from Redis; the two halves of login never meet.

Deeper modelling problem: `KEK_SECRET` (hot, signing keys) and
`HARBOR_KMS_SECRET` (mgmt, user DEKs) are separate vars, but hot *also* needs
mgmt's value to unwrap user DEKs for PPID derivation. The chart has one
`kekSecret` per component and no way to express the shared one.

### M2 — `/login/complete` redirects to a path that does not exist on its own host

`internal/bff/login.go:294` builds a **relative** `"/authorize/complete?..."`,
resolving against the harbor-mgmt origin. `/authorize/complete` is registered on
**harbor-hot** (`cmd/harbor-hot/main.go:236`). Unless both binaries sit behind one
ingress on one hostname — which contradicts `WEBAUTHN_RP_ORIGINS` being "the
dashboard/BFF origin, NOT the issuer" — this 404s at the last step of every login.

### M3 — `auth_time` is a lie on every refreshed token

The `sessions` table has no `auth_time` / `acr` / `amr` columns, and
`rowToRefreshSession` (`clients/sessions.go:294-317`) does not populate those
fields. `Service.Refresh` passes `AuthTime: session.AuthTime` = `0`, so every
refresh-issued ID token claims `auth_time: 0` (1970-01-01) and drops ACR/AMR. Any
RP enforcing `max_age` gets a false answer. `InMemorySessionStore` round-trips
these correctly — which is exactly why the tests miss it.

### M4 — Rate-limit bypass; scheduled rotation never completes

- `clientIP` (`oidcapi/ratelimit.go:124-139`) takes the **leftmost** entry of
  `TRUSTED_FORWARDED_HEADER`. nginx-ingress's default `$proxy_add_x_forwarded_for`
  *appends* to the client-supplied header, so the leftmost value is
  attacker-controlled. `X-Forwarded-For: <random>` per request = unlimited
  `/token` and `/introspect`.
- `KeyRotator.Rotate` computes `PromoteAt`/`RetireOldAt` for a non-emergency
  rotation and returns them — nothing ever calls `Promote` or `Retire`. A
  scheduled rotation adds a pending key to JWKS that is never promoted and never
  retired. `Rotate` is also unguarded against concurrency (`SetActive` races).

### M5 — Dead code, panics, hygiene

- `cmd/harbor-hot/bootstrap.go` (365 lines) is **entirely dead** — `main.go` uses
  `buildSigningStack`/`SigningKeyLoader`. Referenced only by its own test. Its
  `rotationStoreAdapter.wrappedKeys` map is unsynchronised.
- `DashboardHandler` nil-checks `relay` and `auditTrail` but **not** `consents`,
  `sessions`, `credentials`. Without `DATABASE_URL` these are nil interfaces and
  `GET /dashboard/apps` nil-derefs. `cmd/harbor-mgmt/main.go:332` claims "All deps
  are nil-safe."
- `relay.FormatEmail` hardcodes `@relay.<region>.harbor.id`, ignoring the
  configured `RELAY_DOMAIN` used by the same handler for DNS instructions —
  displayed addresses won't match the deployment.
- Discovery advertises `EdDSA` but every issuer/verifier hard-rejects non-`ES256`.
  It also omits `revocation_endpoint`, `introspection_endpoint`,
  `registration_endpoint`, all of which exist.
- Dashboard state-changing POSTs have no CSRF token and no `Origin` check —
  `SameSite=Strict` is the sole, single-layered defence.
- No panic-recovery middleware in `httpserver.Run`. `pgxpool.New` uses defaults
  (no `MaxConns` cap) against an HPA that scales to 20.
- **A 32 MB compiled binary is committed:** `cmd/harbor-hot/harbor-hot`.
  `.gitignore` has `/harbor-hot`, root-anchored, which does not match the nested
  path.
- Migration numbering skips `0014`; `0017` omits the
  `SET lock_timeout/statement_timeout` preamble every other migration has.

---

## What is good (preserve through any refactor)

- **`internal/telemetry/labels.go`** — phantom-typed, allow-listed metric
  dimensions with no exported constructor make PII labels *unexpressible*.
  Backed by an arch test. Strongest pattern in the repo.
- **`identity.DerivePPID`** — the 8-byte length prefix defeating
  `("a","bc")`/`("ab","c")` collisions, with the reasoning in the comment.
- **`Service.Token` ordering** — peek → validate → consume, so a stolen code
  cannot be burned to DoS its rightful owner.
- **`internal/crypto`** — HKDF domain separation by `region+purpose`, AAD binding
  as an independent second layer, fail-closed `Decrypt`, zero-DEK rejection.
- **`RotateSession` commit-context isolation** (`clients/sessions.go:233-242`) —
  cancelled-ctx-during-COMMIT → false failure → retry with revoked token → family
  lockout. Most codebases find that in production.
- **`internal/region`** — total, never-defaulting resolution; add-only
  conflict-rejecting `BindIssuerHost`; boot-time map validation.
- **Comment quality** — accepted limitations, coupling notes, and "do not remove
  this call because…" are consistently present and honest.

---

## Plan-status integrity (found while planning the fixes)

Three plans are marked shipped while their code is **unreachable from `main()`**:

| Plan | Status claims | Reality |
|---|---|---|
| `auth-code-persistence` | `completed`, promoted to a feature doc | `NewRedisAuthCodeStore` never wired; hot path uses the in-memory store |
| `client-grant-persistence` | `promoted` | `NewDBClientRegistry` never wired |
| `bloom-filter-revocation` | `promoted` | filter never instantiated |

This is exactly the failure `.agents/plan.md` documents under *The merged gate*:
"an agent finished on a branch" conflated with "shipped." The `status:` field is
honor-system YAML and nothing verifies it.

Two further plans have **stale problem statements** — their libraries landed but
their wiring did not, so the plan still describes a world that no longer exists:
`totp-mfa` ("nothing above the DB layer exists" — `internal/mfa/service.go` is
complete) and `end-session-logout` ("Harbor has no end_session endpoint" —
`oidcapi/end_session.go` is complete). Both have been annotated in place.

**Suggested guard:** extend the `agent-check` docs-integrity suite (which
already runs `check-design-refs.py` and `check-doc-links.py`) with a check that
a `promoted` plan's key symbols are reachable from `cmd/`. That would have
caught all three mechanically.

Status corrections are queued but **not applied** — they belong with the PRs
that actually wire each component.

## Recommendation: collapse to one object graph

The optional-dependency pattern is the common cause of C1-adjacent wiring bugs
and all of H1, H2, H3, H8. Postgres and Redis are already hard requirements in
`validateProductionReadiness` — that guard exists *because* the degradation is
dangerous. Make the dependency real instead of guarding it.

Three rules:

1. **Constructors take dependencies, not `nil`.** `New*` returns an error when a
   required collaborator is missing. Delete every `WithX(nil)` → noop/503 path.
   `NewService` already panics on one noop combination (`service.go:217-223`) —
   evidence the footgun was already found once.
2. **In-memory implementations move where `cmd/` cannot import them** — a
   `//go:build test` tag or an `internal/testsupport` package, enforced by
   `internal/arch`.
3. **One boot path.** Delete `HARBOR_DEV_MODE`, `validateProductionReadiness`,
   `PlaceholderIssuer`, `StubSessionResolver`, and every `noop*` store. Local dev
   gets Postgres + Redis from the existing `e2e/docker-compose.yml`.

Keep: `RevocationFilter` (a real in-process cache, not a scaffold),
`InMemory*` stores as *test* fixtures.

## The fix DAG

Ten features across three waves. Five reuse existing Wave 6 slugs (annotated in
place with this audit's findings); five are new. Weft enforces the edges — only
the roots are launched by hand.

```
WAVE 1 — roots, independent, launch together
├── fix-mgmt-context-auth ......... C1  🔴 spoofable X-Harbor-User-ID
├── admin-endpoint-auth ........... C2  🔴 unauthenticated /admin/*     (existing slug)
├── fix-bff-session-binding ....... C3  🔴 login session fixation + M2
└── hardening-cleanup ............. M5 + M4  (no code-path overlap)
             │
             │ (child of admin-endpoint-auth: shares cmd/harbor-hot/main.go)
             ▼
WAVE 2 — the root-cause refactor
└── production-wiring-collapse .... H1 + H8 + M1
             │
             ├──────────┬──────────┬──────────┬──────────┬──────────┐
             ▼          ▼          ▼          ▼          ▼          ▼
WAVE 3 — parallel children
  client-secret-auth      C4   (existing slug, scope expanded)
  unify-token-verification H4+H5
  unify-consent-ledger    H6
  end-session-logout      H2   (existing slug, problem statement refreshed)
  wire-revocation-pipeline H3   ← also requires admin-endpoint-auth on main
  totp-mfa                H7   (existing slug, scope refocused on enforcement)
  refresh-session-claims  M3
```

**Wave-3 conflict notes.** `client-secret-auth`, `unify-token-verification`, and
`end-session-logout` all touch `internal/oidcapi/` — expect rebases; sequence
them within the wave if it bites. `unify-consent-ledger` and
`refresh-session-claims` both amend existing migrations, but different files
(`0001`/`0011` vs `0002`), so they do not collide.

**`wire-revocation-pipeline` has a cross-wave prerequisite:**
`admin-endpoint-auth` must be verifiably on `origin/main` first. Today
`/admin/revoke-jwt` is harmless only because its store is unwired and it 503s;
wiring revocation without authenticating the endpoint converts a dead feature
into an unauthenticated fleet-wide kill switch.

**Regression guard:** the tests are thorough but all bottom-up. One test that
builds the real handler graph via the actual `run()` against testcontainers
Postgres/Redis and asserts *which implementations are live* would have caught H1,
H2, H3, H8, and M1 together. `internal/arch` already does compile-time boundary
enforcement; extending it to wiring assertions is the natural home.
