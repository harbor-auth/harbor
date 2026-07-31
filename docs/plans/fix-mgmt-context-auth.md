---
title: Replace the spoofable X-Harbor-User-ID header with BFF session context
status: draft
design_refs: [§9, §6.5, §11.3]
targets: [internal/mgmtapi/, internal/bff/, e2e/]
promoted_to: null
openspec: changes/fix-mgmt-context-auth
created: 2026-07-30
---

# Replace the spoofable X-Harbor-User-ID header with BFF session context (plan)

> **Severity: CRITICAL.** Audit finding C1 —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).

## Problem

`internal/mgmtapi/consent.go:46` defines `UserIDHeader = "X-Harbor-User-ID"`, and
every user-scoped cold-path endpoint reads the caller's identity straight off
that request header:

- `consent.go:70,119` · `relay.go:70,115,237,334,372,451,529`
- `compliance.go:67,112` · `audit.go:106` · `mfa.go:77` · `recovery.go:258,556`

The doc comments claim the header is "set by upstream authentication
middleware." **No such middleware exists.** `cmd/harbor-mgmt/main.go:376` wires
`bff.Middleware(bffStore)`, which populates the request *context* and never
touches the header. Nothing in `deploy/k8s/` or `deploy/helm/` strips inbound
copies of it — there are no `proxy_set_header` or `more_clear_input_headers`
annotations anywhere in the tree.

Any client can therefore assume any identity:

```bash
curl -X POST   .../compliance/export -H 'X-Harbor-User-ID: <victim>'  # full DSAR bundle
curl -X POST   .../compliance/erase  -H 'X-Harbor-User-ID: <victim>'  # irreversible shred
curl -X DELETE .../mfa/factors/x     -H 'X-Harbor-User-ID: <victim>'  # disable victim MFA
```

This is universal read / write / destroy across every account in the region.

`internal/bff/dashboard.go` already does this correctly — it reads
`UserIDFromContext`. The mgmtapi handlers simply never adopted the pattern.

## Proposed approach

Delete the header seam entirely rather than trying to sanitise it at the edge.
Edge stripping is a second thing to get right in every deployment topology; a
context read is correct by construction and matches the dashboard.

1. Remove the `UserIDHeader` constant and every `r.Header.Get(UserIDHeader)`.
2. Add one shared helper on `*Server` — `callerID(w, r) (string, bool)` — that
   reads `bff.UserIDFromContext(r.Context())`, writes the existing `401`
   envelope when empty, and returns `ok=false`. This keeps the 14 call sites to
   a one-line change each and gives a single place to add future checks.
3. `internal/mgmtapi` must not import `internal/bff` if that breaks the arch
   boundary — check `internal/arch/arch_test.go` first. If the edge is
   disallowed, define a tiny `mgmtapi.CallerSource` interface satisfied by a
   `bff` adapter and inject it in `cmd/harbor-mgmt`, mirroring how
   `webauthn.EnrollmentSessionStore` stays decoupled.
4. Add a **regression guard**: a package-level test that greps the `mgmtapi`
   source for `X-Harbor-User-ID` / `Header.Get(UserIDHeader)` and fails if
   either reappears. The `tools/lint/` analyzers are the precedent for this
   style of guard.
5. Rewrite `e2e/recovery_test.go` (and any sibling e2e that sets the header) to
   drive the real BFF cookie flow. **The e2e suite currently uses this header as
   its auth mechanism (`e2e/recovery_test.go:54`), so it institutionalises the
   bug** — leaving it would silently re-permit the vulnerability.

### Rejected alternative

*Strip the header at the ingress.* Rejected: harbor-mgmt is reachable
cluster-internally and in local dev without an ingress in front of it, so the
guarantee would hold only in one topology. The vulnerability class survives.

## DESIGN alignment

Serves §9 (the BFF session is the only authenticated seam; there is deliberately
no client-supplied user id — the same rule `webauthn/handlers.go:144-152`
already states for ceremonies) and §6.5 (PII-free, non-enumerable errors — the
existing `401` envelope is unchanged). No DESIGN change.

## Target code paths

- `internal/mgmtapi/consent.go` — delete `UserIDHeader`, add `callerID` helper
- `internal/mgmtapi/{relay,compliance,audit,mfa,recovery}.go` — 14 call sites
- `internal/mgmtapi/*_test.go` — tests currently set the header; switch to context
- `e2e/recovery_test.go` and siblings — drive the real cookie flow
- `internal/arch/arch_test.go` — allow the new edge if required

## Implementation checklist

- [ ] Read `internal/arch/arch_test.go`; decide direct `bff` import vs. injected `CallerSource`
- [ ] Add `(*Server).callerID(w, r) (string, bool)` with the existing 401 envelope
- [ ] Convert all 14 `r.Header.Get(UserIDHeader)` call sites
- [ ] Delete the `UserIDHeader` constant and its doc comment
- [ ] Update every `mgmtapi` unit test to seed context, not headers
- [ ] Rewrite `e2e/recovery_test.go` to authenticate via the BFF cookie
- [ ] Tests: **negative** — a request carrying `X-Harbor-User-ID: <other-user>` with no valid session gets `401`; a request carrying it *alongside* a valid session for a different user is scoped to the **session** user, not the header
- [ ] Tests: regression guard asserting the header name is absent from `internal/mgmtapi/`
- [ ] Author & verify paired OpenSpec change: `@openspec new fix-mgmt-context-auth` then `openspec validate fix-mgmt-context-auth --strict`
- [ ] Reconcile & promote: `@plan promote fix-mgmt-context-auth`

## Risks & open questions

- **Arch boundary.** `mgmtapi` importing `bff` may violate an existing rule. The
  injected-interface fallback is designed for that case; do not weaken the arch
  test to make the direct import pass.
- **Scope creep.** Do **not** rewire stores or touch `cmd/harbor-mgmt` beyond
  what the `CallerSource` injection requires — the production-wiring collapse is
  a separate feature (`production-wiring-collapse`) that builds on this one.
- Endpoints that legitimately have no session yet (`POST /enroll`) must keep
  working unauthenticated; only the *user-scoped* endpoints change.

## Definition of done

- `grep -r 'X-Harbor-User-ID' internal/ e2e/` returns nothing.
- Every user-scoped mgmtapi endpoint resolves its caller from the BFF session.
- Negative tests prove header spoofing no longer grants access.
- `go build ./...`, `go vet ./...`, `go test ./...`, and `make agent-check` green.
