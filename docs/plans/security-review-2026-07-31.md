# Security Review — 2026-07-31

## Scope and status

This is a security-only review of the `main` snapshot at `cd865af`, performed on
branch `review/adversarial-main-2026-07-31`. The pass covered the Go source and
tests, SQL queries/migrations, HTTP route wiring, crypto/key handling, OIDC and
BFF flows, WebAuthn/MFA, relay ingress, and Kubernetes/Helm deployment
configuration. Generated code was checked at its trust boundaries; it was not
treated as an independent source of policy.

No production code has been changed. This report is the only intended branch
artifact from the review.

Verification baseline:

- `go test ./...` passes.
- `go vet ./...` passes.
- The passing tests are mostly unit/package tests; they do not prove that the
  production command dependency graph, cross-service session flow, or rendered
  deployment manifests are secure.

The pass did not find an additional obvious SQL-concatenation injection path,
shell-command execution path, or unsafe `html/template` rendering path. The
previous spoofable management identity header, permissive admin fallback, and
untrusted proxy-hop behavior appear corrected on this snapshot. Those controls
were treated as verified improvements, not as evidence that the unresolved
production wiring and authorization gaps are safe.

## Mini TODO list — ordered by risk

- [ ] **C-01 — Replace the production scaffold graph.** `harbor-hot` always
  constructs the in-memory client registry, in-memory authorization-code store,
  and in-memory grant store, while omitting the DB/Redis session, consent,
  revocation, outbox, and logout dependencies. The readiness check does not
  detect this. This leaves production client registration, multi-replica code
  exchange, refresh-token persistence, logout, and revocation incomplete.
- [ ] **C-02 — Enforce confidential-client authentication on introspection and
  revocation.** Both endpoints parse Basic auth but do not validate the client
  or secret. Revocation then sets `IsAdmin=true`, making the unchecked caller
  authorization bypass cross-client isolation.
- [ ] **C-03 — Remove the local software-derived KEK from production paths.**
  `harbor-hot`, `harbor-mgmt`, and `harbor-relay` call the explicitly
  development-only `NewLocalKeyProvider` even when backed by a real database.
  This places user DEKs, signing keys, and relay mappings behind an application
  environment secret instead of the required KMS/HSM boundary.
- [ ] **H-01 — Make consent explicit and canonical.** The live BFF completion
  path calls a resolver that auto-approves requested scopes and silently unions
  newly requested scopes. The consent decision store is not consulted.
- [ ] **H-02 — Unify grant and consent revocation.** Dashboard disconnects revoke
  `consent_grants`, while authorization reads the separate `grants` table; the
  hot command also wires an in-memory grant store. Revoking an app therefore
  does not reliably prevent a later reauthorization.
- [ ] **H-03 — Use one strict access-token verifier for `/userinfo`, introspection,
  revocation, and downstream callers.** `/userinfo` does not enforce expiry,
  audience, JTI revocation, token type, or required scope. Other verifiers have
  different issuer/key-set behavior, so endpoint validity is inconsistent.
- [ ] **H-04 — Wire emergency revocation, logout, and theft-signal delivery.**
  The deployed hot configuration leaves the revoked-JTI store/filter/publisher,
  logout verifier/session revoker, and durable revocation outbox at nil/no-op
  defaults. Security events can therefore be accepted locally or lost.
- [ ] **H-05 — Enforce the recovery-required account fence and make enrollment
  reachable.** New users are persisted with `recovery_required=true`, but the
  login path calls `SetUser`, not `SetUserWithRecoveryStatus`; management routes
  are not wrapped with `RequireFullScope`; and the live WebAuthn handler has no
  enrollment-session store, returning 501 for registration.
- [ ] **H-06 — Make MFA a real step-up and rate-limit verification.** The MFA
  verify handlers only validate a code and return success. They do not stamp the
  BFF session or attach the step-up gate to sensitive routes. TOTP and recovery
  verification have no distributed attempt limiter.
- [ ] **H-07 — Close the client-authentication and registration contract gap.**
  Registration advertises `client_secret_basic` and `client_secret_post`, but
  `/token` never accepts or verifies a client secret. Dynamic registration is
  currently not wired, so this is latent today and a release blocker before it
  is enabled. If enabled without an initial access token, registration is open.
- [ ] **H-08 — Make BFF completion one-time and require a nonce.** Completion
  issues an auth code and best-effort deletes the BFF session; failure can allow
  repeated completion. Login and completion also conditionally skip nonce checks
  for legacy records with an empty nonce hash.
- [ ] **M-01 — Fix WebAuthn sign-count atomicity.** The DB update is guarded by a
  monotonic predicate but the generated `:exec` result is ignored. Concurrent
  assertions with the same counter can both pass the pre-read and the second
  no-op update is treated as success, weakening clone detection.
- [ ] **M-02 — Make abuse controls fail closed or use a bounded fallback.**
  `RATE_LIMIT_DISABLED` disables all hot-path limits, and Redis limiter failures
  are documented/implemented as fail-open. This removes the only online defense
  against token probing, MFA abuse, and endpoint flooding.
- [ ] **M-03 — Reconcile deployment contracts and supply-chain defaults.** Raw
  manifests and Helm defaults use `:latest`; raw manifests contain stale secret
  and WebAuthn environment names, omit management Redis despite live Redis
  session usage, and comments claim the wrong runtime contract. Network policies
  also allow broad egress. These mismatches can cause operators to deploy an
  insecure or non-functional security configuration.
- [ ] **M-04 — Default relay authentication enforcement on.** The relay binary
  treats an unset `RELAY_ENFORCE_AUTH` as monitor-only, accepting mail that
  fails SPF/DKIM/DMARC. The chart overrides this to true, but the binary default
  is fail-open outside that chart.

## Verified findings and remediation plans

### C-01 — Production security dependency graph is still scaffolded

**Evidence:** `cmd/harbor-hot/main.go:154-189` creates
`NewInMemoryClientRegistry`, `NewInMemoryGrantStore`, and
`NewInMemoryAuthCodeStore`. `main.go:199-208` passes the in-memory grant/client
objects to the API and supplies a noop session revoker. The DB-backed grant and
secret dependencies constructed at `main.go:321-364` are used only by the BFF
resolver. `internal/oidc/service.go:112-128,157-190` defaults omitted session,
consent, revocation, and outbox collaborators to no-op implementations.

The real Redis authorization-code store exists in
`internal/clients/codes.go:17-31`, and DB-backed client/grant/session stores
exist, but the production command does not wire them. The startup check at
`cmd/harbor-hot/main.go:413-455` checks environment variables and only the BFF
resolver dependencies; it does not check the actual OIDC service collaborators.

**Why this is verified:** the deployed binary can pass its readiness check while
using process-local state and no-op security sinks. An HPA replica cannot see an
authorization code issued by another replica. Real clients cannot be loaded from
the DB registry, refresh sessions are not persisted, and logout/revocation paths
have no durable backing. The seeded `demo-client` also retains localhost redirect
URIs in the production graph (`main.go:157-163`).

**Fix plan:**

1. Build one explicit production dependency graph: DB client registry, Redis
   authorization-code store, DB grants/consents/sessions, revoked-JTI store and
   filter hydration, Redis publisher, logout verifier/revoker, and durable
   revocation outbox/worker.
2. Remove production seeding of `demo-client`; keep it behind an explicit test
   constructor or test-only build path.
3. Replace environment-presence readiness checks with typed wiring checks that
   reject in-memory/noop implementations when `HARBOR_DEV_MODE` is false.
4. Add a startup integration test that constructs the real command graph and
   asserts every security collaborator is distributed or durable.

### C-02 — Introspection and revocation caller authentication is bypassable

**Evidence:** `internal/oidcapi/introspect.go:27-51` parses Basic credentials,
assigns `clientID`, and explicitly leaves secret validation as a TODO.
`internal/oidcapi/revoke.go:35-48` has the same behavior. The shared helper in
`internal/oidcapi/auth.go:58-86` is not used by either endpoint, and
`internal/oidcapi/auth_test.go:221-241` explicitly documents that arbitrary
secrets succeed. `revokeAccessToken` then constructs an introspection request
with `IsAdmin: true` at `revoke.go:143-151`.

**Why this is verified:** any caller who can send syntactically valid Basic
credentials can ask for token metadata and can revoke active access tokens. The
revocation path bypasses the cross-client audience check after the unchecked
authentication step. A client secret is not a secret in this path.

**Fix plan:**

1. Implement one client-authenticator that loads the client from the durable
   registry, verifies the configured method, and compares a stored secret hash
   in constant time.
2. Require it in both endpoints; bind a non-admin request to the authenticated
   client ID and remove the unchecked `IsAdmin` escape hatch.
3. Add negative tests for unknown client, empty secret, wrong secret,
   cross-client introspection, and cross-client revocation. Add an authenticated
   admin path only after defining and testing its credential source.

### C-03 — Production uses the explicitly dev-only key provider

**Evidence:** `internal/crypto/keyprovider.go:37-60` says
`NewLocalKeyProvider` is development-only and violates the HSM boundary.
Nevertheless, `cmd/harbor-hot/main.go:292-297,351-356`,
`cmd/harbor-mgmt/main.go:167-187`, and `cmd/harbor-relay/main.go:85-115` all
construct it for database-backed runtime paths. The production KMS provider and
AWS KMS client exist in `internal/crypto/keyprovider_kms.go` and
`internal/crypto/kmsclient_aws.go`, but no command wires them.

**Why this is verified:** compromise of the application environment secret or a
process memory dump exposes the software-derived regional KEK. That permits
decryption of stored user pairwise secrets/relay mappings and unwrap of signing
private keys, undermining both data confidentiality and token integrity. This is
not merely a warning-level configuration issue because the runtime path is
explicitly selected in code.

**Fix plan:**

1. Add a production KMS/HSM factory and configure regional key IDs through a
   secret manager/workload identity, not a raw application KEK.
2. Make the commands refuse `NewLocalKeyProvider` whenever a real database or
   production mode is active; require an explicit dev flag for local crypto.
3. Add provider-type startup assertions and migration/rewrap procedures for
   existing data and signing keys. Rotate any material protected by the local
   provider after migration.

### H-01 — BFF authorization silently approves and escalates scopes

**Evidence:** the live completion path `internal/oidc/service.go:275-320`
calls `SessionResolver.Resolve` and trusts its `approved` result. The production
resolver `internal/oidc/resolver.go:144-208` returns `approved=true` for both a
new grant and an existing grant; when new scopes are requested it revokes and
recreates the grant with the union at lines 155-175. It never calls the
`ConsentStore`. `AuthorizeRequest` has a `Prompt` field, but
`internal/oidcapi/authorize.go:164-180` does not populate it from query
parameters, and `ValidateAuthorize` does not enforce prompt semantics.

**Why this is verified:** after passkey authentication, any registered RP can
receive every scope it is allowed to request without a user approval decision.
Re-requesting a previously approved client with `offline_access` or another
allowed scope silently escalates the grant.

**Fix plan:** make one consent state machine authoritative for first consent,
scope escalation, `prompt=consent`, `prompt=none`, and revocation. Persist the
grant only after an explicit approval transaction, and test first consent,
repeat consent, escalation, denial, and revoked-grant reauthorization end to
end.

### H-02 — Consent revocation and authorization read different ledgers

**Evidence:** management deletion in `internal/mgmtapi/consent.go:101-176`
revokes `consent_grants` through `internal/clients/consent.go`, while
`PPIDSessionResolver` reads/writes the separate `grants` store at
`internal/oidc/resolver.go:150-208`. The SQL queries confirm separate tables:
`db/queries/consent_grants.sql:22-44` versus `db/queries/grants.sql:28-32`.

**Why this is verified:** disconnecting an app can revoke the management ledger
and current sessions while leaving the active authorization grant that the
resolver uses. A later login can therefore find the old grant and mint another
code with the old authorization. In `harbor-hot`, the service-level grant store
is additionally in-memory, so refresh-token issuance cannot reliably see the
resolver's DB grant.

**Fix plan:** remove the duplicate authorization ledgers or make one canonical
table back every reader and writer. Revoke grant, refresh sessions, and consent
as one transaction; make the resolver, refresh path, dashboard, and logout use
that same record. Add a revoke-then-new-login integration test across both
commands.

### H-03 — Token validation is inconsistent and incomplete at `/userinfo`

**Evidence:** `internal/oidcapi/userinfo.go:18-26` models only issuer, subject,
and scope; `userinfo.go:92-155` verifies a compact ES256 signature and issuer
but explicitly does not check expiry. It does not require `aud`, `jti`, access
token type, revocation status, or the `openid`/userinfo scope. The introspector
has a different policy at `internal/oidc/introspect.go:202-226`, including
expiry, JTI filter, and audience checks, while `internal/oidc/jwt_verifier.go`
uses one configured public key and does not select by JOSE `kid`.

**Why this is verified:** an expired or emergency-revoked bearer token remains
usable at `/userinfo`. A valid Harbor-signed ID token or a token minted for a
different audience may also pass the `/userinfo` checks. Key rotation can make
one endpoint reject a valid overlap key while another accepts it.

**Fix plan:** implement one shared verifier with issuer, exact audience, `typ`,
`exp`/`iat`/`jti`, scope, and key-set/`kid` policy. Use it in userinfo,
introspection, revocation, and logout; add tests for expired, wrong audience,
ID-token, revoked, old-key/new-key, and cross-region tokens.

### H-04 — Revocation, logout, and theft signals are not live in production

**Evidence:** `cmd/harbor-hot/main.go:191-208` leaves the logout verifier nil and
uses `noopSessionRevoker`. It does not populate revoked-JTI storage/filter or
publisher. `internal/oidcapi/server.go:105-138,168-196` accepts these as
optional, and `internal/oidc/service.go:176-190` defaults revocation and outbox
to no-op implementations. The endpoint implementations consequently return
503/no-op behavior when those fields are absent.

**Why this is verified:** client-driven or administrative JWT revocation is not
durable or distributed, RP-initiated logout does not revoke the initiating
session, and authorization-code/refresh-token reuse signals do not have a
durable delivery path. These controls may appear in the API contract while not
protecting deployed tokens.

**Fix plan:** wire DB revocation persistence, startup hydration, local filter,
Redis propagation, DB confirmation on filter hits, logout token verification and
session revocation, and the transactional outbox worker. Make readiness fail if
any required control is absent and add multi-replica propagation tests.

### H-05 — Recovery fencing is not enforced and passkey enrollment is unreachable

**Evidence:** `internal/identity/enroll.go:101-108` sets
`RecoveryRequired: true` for a new user. The production login path
`internal/bff/login.go:318-328` calls `SetUser`, not
`SetUserWithRecoveryStatus`; the latter appears only in the store/tests. The
management route table `internal/mgmtapi/server.go:298-325` registers sensitive
routes without `RequireFullScope`, even though the gate exists in
`internal/bff`.

Separately, `cmd/harbor-mgmt/main.go:287-293` does not call
`WithEnrollmentSessions`. Its WebAuthn routes are registered through a handler
without an enrollment store, and `internal/webauthn/handlers.go:144-163` returns
501 when the enrollment cookie/store is absent. The direct legacy
`POST /users/enroll` route at `main.go:357-363,475-497` bypasses the proper
session-setting handler and body/rate controls.

**Why this is verified:** the account state explicitly requiring recovery is not
propagated into the BFF session, and management authorization is based only on
caller identity. A newly enrolled user can therefore reach sensitive cold-path
operations without completing the required recovery ceremony. At the same time,
the intended ceremony cannot establish the session required to register a
passkey.

**Fix plan:** load the authoritative recovery flag during login and atomically
write the user, scope, and recovery status to the BFF session. Wrap every
sensitive management route with `RequireFullScope`, leaving only the recovery
and enrollment subset available to restricted sessions. Wire a distributed,
short-lived enrollment-session store, remove the duplicate legacy route, cap its
body, and add a full enrollment/recovery integration test.

### H-06 — MFA verification does not create a step-up

**Evidence:** `internal/mgmtapi/mfa.go:175-230` validates TOTP/recovery codes
and returns `{"status":"verified"}` without updating the BFF session.
`internal/bff/stepup.go:17-90` provides `StepUpGate` and
`RecordTOTPStepUp`, but `rg` found no production wiring for either. The MFA
service `internal/mfa/service.go:233-248,339-361` validates TOTP without an
attempt counter or lockout; recovery-code verification at lines 250-282 is also
not fronted by a production rate limiter. `cmd/harbor-mgmt/main.go:287-293`
only attaches the MFA service.

**Why this is verified:** successful MFA does not change authorization state, so
the advertised step-up requirement is absent from live requests. An attacker can
also make unlimited online guesses against the six-digit TOTP/recovery endpoints
subject only to general infrastructure limits.

**Fix plan:** bind verification to the BFF session ID, call
`RecordTOTPStepUp` atomically, and wrap all sensitive operations in
`StepUpGate`. Add distributed per-user/session/IP attempt limits, lockout and
telemetry, and fail closed or use a bounded local fallback when Redis is down.
Test that verification grants only the intended session and expires at the gate
TTL.

### H-07 — Token endpoint and dynamic-registration authentication contracts diverge

**Evidence:** `internal/oidcapi/token.go:38-59` does not parse Basic auth or
`client_secret_post`; `TokenRequest` has no client secret field. In contrast,
`internal/mgmtapi/register_validate.go:72-78` permits
`client_secret_basic`, `client_secret_post`, and `none`, and
`internal/mgmtapi/register.go:140-170` issues confidential client secrets.
`cmd/harbor-mgmt/main.go` does not wire `WithClientRegistration`, so this is
currently latent rather than an exposed registration endpoint. If registration
is wired without an initial access token, `initialAccessTokenAuthorized` returns
true when its hash is nil (`internal/mgmtapi/register.go:221-236`).

**Fix plan:** either implement the full confidential-client authentication path
and registration authorization before enabling registration, or restrict the
contract to public PKCE clients and reject confidential methods. Require an
initial access token or an authenticated administrative registration policy,
plus rate limits and negative tests.

### H-08 — BFF completion has replay and legacy-session gaps

**Evidence:** `internal/oidcapi/authorize.go:281-320` saves the authorization
code and then best-effort deletes the BFF session. If deletion fails, the same
request can be completed again while the session remains valid. The nonce checks
in `internal/bff/login.go:126-132,294-300` and
`internal/oidcapi/authorize.go:251-263` are conditional on a non-empty
`BrowserNonceHash`, allowing legacy records without the binding to proceed.

**Fix plan:** make completion an atomic consume/mark-complete operation in the
distributed session store and refuse to redirect if the consume fails. Require a
nonce hash for production records, invalidate or migrate legacy sessions, and
test concurrent completion plus stale-cookie replay.

### M-01 — WebAuthn sign-count update can accept a concurrent no-op

**Evidence:** `internal/webauthn/store_db.go:173-194` reads the credential,
checks the counter in Go, then calls the generated update. The SQL at
`db/queries/credentials.sql:32-41` is `:exec` and only updates when
`sign_count < $2`; its comment says the caller treats zero rows as failure, but
the Go caller receives no rows-affected result and returns the query error only.

**Why this is verified:** two assertions can read the same old counter, both pass
the pre-check, and the second conditional update can affect zero rows while
returning nil. The second assertion is then accepted, weakening the clone/replay
detection contract.

**Fix plan:** make the query return rows affected or the updated row and treat
zero rows as `ErrSignCountRegression`; preferably combine credential ownership
and monotonic update into one atomic statement. Add a concurrent assertion test.

### M-02 — Rate limiting can be disabled or fail open

**Evidence:** `cmd/harbor-hot/main.go:547-556` makes
`RATE_LIMIT_DISABLED` a transparent passthrough. The Redis rate limiter in
`internal/oidcapi/ratelimit.go:65-68,98-107` fails open on Redis errors, and the
client limiter contract documents the same behavior.

**Fix plan:** reject the disable switch outside an explicit dev mode. For
security-sensitive endpoints, use a bounded local limiter when Redis is
unavailable or fail closed according to a documented availability budget. Apply
the same policy to MFA/recovery and add outage tests.

### M-03 — Deployment manifests do not express the runtime security contract

**Evidence:** `deploy/helm/values.yaml:17-25` and raw deployments use
`:latest` with `IfNotPresent`, despite the Kyverno policy in
`deploy/kyverno/policies/disallow-latest-tag.yaml` only protecting clusters
where that policy is installed. Raw manifests use `HARBOR_KEK_SECRET` while Go
reads `HARBOR_KMS_SECRET`, and raw WebAuthn config uses
`WEBAUTHN_RP_NAME`/`WEBAUTHN_ORIGIN` while Go reads
`WEBAUTHN_RP_DISPLAY_NAME`/`WEBAUTHN_RP_ORIGINS`. The management deployment
omits `REDIS_URL` even though `cmd/harbor-mgmt/main.go:73-139` uses Redis for
BFF and WebAuthn sessions. Network policy comments and rules allow broad
smarthost/external egress.

**Fix plan:** choose one canonical manifest source, render it in CI, and test
every environment variable against command startup requirements. Require image
digests/signatures, make unsafe scaffold values invalid defaults, add admission
policy checks to CI, supply management Redis, and narrow egress to resolved
service CIDRs/ports.

### M-04 — Relay authentication enforcement defaults to monitor-only

**Evidence:** `cmd/harbor-relay/main.go:243-268` returns `false` when
`RELAY_ENFORCE_AUTH` is unset. The Helm value defaults to true, but a raw or
non-Helm deployment can omit it and run the MTA in fail-open mode.

**Fix plan:** require an explicit production value or default to true outside
dev mode; make readiness fail when enforcement is disabled in production. Add a
deployment-independent test for unset, invalid, and explicit false values.

## Remediation sequence

1. **Containment and startup safety:** fail closed on the local key provider,
   scaffold/no-op production dependencies, missing revocation/session stores,
   missing enrollment state, disabled rate limiting, and unsafe relay defaults.
2. **Identity and authorization correctness:** wire the durable client/session
   graph, implement client authentication, enforce recovery scope, and make
   consent canonical and explicit.
3. **Token lifecycle:** deploy the shared token verifier, durable revocation and
   logout paths, refresh/session revocation, outbox delivery, and atomic BFF
   completion.
4. **Account assurance and abuse resistance:** wire WebAuthn enrollment,
   session-bound MFA step-up, attempt limiting, and atomic sign-count handling.
5. **Deployment and regression coverage:** reconcile Helm/raw manifests, pin and
   verify images, narrow network policy, and add end-to-end tests covering a
   multi-replica authorization flow, consent revoke/re-authorize, recovery
   fencing, MFA step-up, token revocation, key rotation, and Redis/KMS outages.
