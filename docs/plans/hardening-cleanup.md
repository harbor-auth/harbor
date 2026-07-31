---
title: Hardening cleanup — CSRF, panic recovery, repo hygiene, spec honesty
status: draft
design_refs: [§6.5, §3.4, §7.5]
targets: [internal/bff/, internal/httpserver/, internal/oidcapi/, internal/relay/, internal/clients/, db/migrations/, .gitignore]
promoted_to: null
openspec: changes/hardening-cleanup
created: 2026-07-30
---

# Hardening cleanup (plan)

> **Severity: MEDIUM / LOW.** Audit finding M5 (and the stragglers from M4) —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).
> **DAG root** — shares no code path with the critical fixes and can run in
> parallel with them.

## Problem

A cluster of small, independent defects. None is individually alarming; together
they are the difference between "the security model holds" and "the security
model holds as long as nothing else goes wrong."

1. **Dashboard CSRF is single-layered.** Every state-changing dashboard route is
   a cookie-authenticated `POST` (`bff/dashboard.go:113-121`:
   `/dashboard/apps/{id}/revoke`, `/dashboard/sessions/{id}/revoke`,
   `/dashboard/credentials/{id}/revoke`, `/dashboard/relay/{id}/deactivate`)
   with **no CSRF token and no `Origin`/`Sec-Fetch-Site` check**.
   `SameSite=Strict` on `__Host-harbor-bff` is the sole defence. That is a real
   defence, but it is one browser-behaviour assumption away from account-level
   damage, and it is the only layer.

2. **No panic recovery.** `httpserver.Run` (`internal/httpserver/server.go:35-83`)
   sets sensible timeouts but installs no recovery middleware. Go's `net/http`
   recovers per-connection, so a handler panic aborts the request with no
   response body, no `500`, no structured log, and no metric. Given the nil-deref
   hazards the audit found (`bff/dashboard.go` does not nil-check `consents`,
   `sessions`, or `credentials` despite `cmd/harbor-mgmt/main.go:332` claiming
   "All deps are nil-safe"), this is a live blind spot.

3. **Relay email addresses are wrong.** `relay.FormatEmail`
   (`internal/relay/address.go:191-195`) hardcodes
   `<token>@relay.<region>.harbor.id`, ignoring the configured `RELAY_DOMAIN`
   that the *same handler* uses to generate DNS setup instructions
   (`mgmtapi/relay.go:591-593`). Any deployment not on `harbor.id` shows users an
   address that does not exist.

4. **Discovery lies in two directions.** `oidcapi/discovery.go` advertises
   `EdDSA` in `id_token_signing_alg_values_supported`, but every issuer and
   verifier hard-rejects anything but `ES256`. It also **omits**
   `revocation_endpoint`, `introspection_endpoint`, and `registration_endpoint` —
   all of which exist and are documented in the OpenAPI contract.

5. **Connection-pool sizing is unset.** `clients.ConnectDB` uses `pgxpool.New`
   defaults (≈4×NumCPU max conns) against an HPA that scales to 20 replicas
   (`values.yaml`). Under load that is a Postgres connection exhaustion waiting
   to happen.

6. **A 32 MB compiled binary is committed to git:**
   `cmd/harbor-hot/harbor-hot`. `.gitignore` has `/harbor-hot`, which is
   root-anchored and does not match the nested path. Repo hygiene and a
   supply-chain smell — a committed binary is an artefact nobody reviews.

7. **Migration hygiene.** `0017_logout_uris.up.sql` omits the
   `SET lock_timeout = '3s'; SET statement_timeout = '30s';` header that every
   other migration carries. Numbering also skips `0014` with no note.
   *(Pre-launch, this is cosmetic — there is no live schema to protect. Fix it
   because consistency is cheap now and expensive later.)*

8. **Rate-limit bypass via `X-Forwarded-For` (audit M4).**
   `internal/oidcapi/ratelimit.go:124-139` takes the **leftmost** entry of the
   configured `TRUSTED_FORWARDED_HEADER`. nginx-ingress's default
   `$proxy_add_x_forwarded_for` **appends** to the client-supplied header, so
   the leftmost value is attacker-controlled: `X-Forwarded-For: <random>` per
   request gives unlimited `/token` and `/introspect`. Every anonymous-bucket
   limit in the system is therefore decorative.

## Proposed approach

Small, independent commits within one feature branch — each item is
self-contained and separately testable.

1. **CSRF defence in depth.** Add an `Origin` / `Sec-Fetch-Site` check middleware
   applied to all state-changing dashboard routes, rejecting cross-site requests
   with `403`. Prefer this over a synchroniser token: the dashboard is
   server-rendered `html/template` with no build step, so a header check adds a
   real second layer with near-zero surface. If a token is wanted later, the
   middleware is the natural place to add it.
2. **Recovery middleware** in `httpserver` wrapping the whole handler: recover,
   log via `slog` at ERROR with **no PII and no panic value in the response**,
   emit a counter through the existing `telemetry` facade, and return a generic
   `500`. Apply in both binaries.
3. **Thread the relay domain.** `FormatEmail(token, region, relayDomain)`, or
   move it behind a small configured formatter. Fix every call site; assert
   consistency between the address shown and the DNS instructions generated.
4. **Make discovery honest.** Drop `EdDSA` until a signer supports it; add
   `revocation_endpoint`, `introspection_endpoint`, and `registration_endpoint`.
   Update `api/openapi/harbor.yaml` in the same commit so `make generate-check`
   stays clean.
5. **Configure the pool.** Explicit `MaxConns`/`MinConns`/`MaxConnLifetime` from
   env with documented defaults sized against the HPA ceiling. Document the
   arithmetic (replicas × MaxConns ≤ Postgres `max_connections` headroom).
6. **Remove the binary.** `git rm --cached cmd/harbor-hot/harbor-hot`; fix
   `.gitignore` to match nested paths (`harbor-hot` / `harbor-mgmt`, unanchored,
   plus `/bin/`). Add a CI guard that fails on a committed file above a size
   threshold — `tools/lint/filesize` already exists and is the natural home.
7. **Migration hygiene.** Add the missing header to `0017`; add a short comment
   noting the `0014` gap so future readers do not hunt for a lost migration.
8. **Fix XFF trust.** Replace "leftmost entry" with a **trusted-proxy-count**
   model: given `TRUSTED_PROXY_HOPS=N`, take the Nth-from-**right** entry —
   the address the outermost trusted proxy actually observed, which the client
   cannot forge. Default `0` (trust nothing; use `RemoteAddr`). Document the
   nginx-ingress `$proxy_add_x_forwarded_for` interaction explicitly in
   `deploy/README.md` — this is a config-shaped footgun and the comment should
   say so.

## DESIGN alignment

Serves §6.5 (PII-free errors and observability), §3.4 (discovery document is the
contract), §7.5 (relay addressing). No DESIGN change.

## Target code paths

- `internal/bff/csrf.go` — **new**: `Origin`/`Sec-Fetch-Site` middleware
- `internal/bff/dashboard.go` — apply to mutating routes
- `internal/httpserver/server.go` — recovery middleware
- `internal/relay/address.go` + `internal/mgmtapi/relay.go` — thread `RELAY_DOMAIN`
- `internal/oidcapi/discovery.go`, `api/openapi/harbor.yaml` — honest metadata
- `internal/clients/pool.go` — explicit pool sizing
- `.gitignore`, `tools/lint/filesize/` — hygiene + guard
- `db/migrations/0017_logout_uris.up.sql` — timeout header

## Implementation checklist

- [ ] `Origin`/`Sec-Fetch-Site` middleware; apply to all four mutating dashboard routes
- [ ] Panic-recovery middleware in `httpserver`; wire in both binaries; PII-free log + metric + generic 500
- [ ] Nil-check (or make required) `consents`/`sessions`/`credentials` in `DashboardHandler`
- [ ] Thread `RELAY_DOMAIN` through `FormatEmail`; fix all call sites
- [ ] Discovery: drop `EdDSA`; add revocation/introspection/registration endpoints; sync the spec
- [ ] Explicit `pgxpool` sizing from env, with documented defaults vs. the HPA ceiling
- [ ] `git rm --cached cmd/harbor-hot/harbor-hot`; fix `.gitignore`; add the filesize CI guard
- [ ] Add the timeout header to migration `0017`; note the `0014` gap
- [ ] Replace leftmost-XFF with `TRUSTED_PROXY_HOPS` (default 0 = trust nothing); document the nginx-ingress interaction
- [ ] Tests: cross-site `POST` to each mutating dashboard route ⇒ `403`; same-site ⇒ allowed
- [ ] Tests: a forged `X-Forwarded-For` cannot escape the anonymous rate-limit bucket (M4 regression)
- [ ] Tests: a panicking handler ⇒ `500` + one metric + a log carrying no panic value or PII
- [ ] Tests: the relay address returned by the API matches the configured `RELAY_DOMAIN`
- [ ] Tests: discovery advertises only algorithms the issuer actually emits
- [ ] Author & verify paired OpenSpec change: `@openspec new hardening-cleanup` then `openspec validate hardening-cleanup --strict`
- [ ] Reconcile & promote: `@plan promote hardening-cleanup`

## Risks & open questions

- **`Origin` checks and legitimate clients.** Some browsers omit `Origin` on
  same-origin `GET`s. Only mutating routes are gated, and `Sec-Fetch-Site: same-origin`
  is the primary signal with `Origin` as fallback — verify against the actual
  dashboard flows before enforcing, and fail closed only for `POST`.
- **Removing `EdDSA` from discovery is technically a capability regression** in
  the advertised metadata. It is a correction — nothing ever supported it — but
  call it out in the PR description in case an RP has already keyed off it.
- **Deleting a committed binary rewrites nothing** (it stays in history). If the
  history size matters, that is a separate, disruptive `filter-repo` decision —
  do not attempt it here.
- Adjust the `MaxConns` default only alongside a real load test; the arithmetic
  in the plan is a starting point, not a measurement.

## Definition of done

- Dashboard mutations require a same-site origin **and** the session cookie.
- A handler panic produces a logged, metered, PII-free `500`.
- Relay addresses and discovery metadata both match reality.
- No compiled binary is tracked, and CI fails if one is added.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check`,
  `make generate-check` green.
