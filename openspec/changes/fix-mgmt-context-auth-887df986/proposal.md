# Replace Spoofable X-Harbor-User-ID Header with BFF Session Context

## Change ID
fix-mgmt-context-auth-887df986

## Status
draft

## Why
`internal/mgmtapi/consent.go:46` defines `UserIDHeader = "X-Harbor-User-ID"`. Every
user-scoped endpoint reads caller identity straight off that header — consent, relay,
compliance, audit, MFA, and recovery. No middleware ever sets this header; instead,
`cmd/harbor-mgmt/main.go` wires `bff.Middleware` which populates the request **context**.
Nothing in the deployment strips inbound copies of the header. Any client can therefore
assume any user identity (audit finding C1 — universal account takeover).

## What
Delete the header seam entirely. Add a `CallerSource` interface to `internal/mgmtapi`
injected at wiring time from `cmd/harbor-mgmt` (which adapts `bff.UserIDFromContext`).
Add a shared `(*Server).callerID(w, r, endpoint)` helper used at all 14 call sites.
Delete `UserIDHeader`. Add negative tests proving the seam is gone. Add a regression
guard test. Rewrite `e2e/recovery_test.go` to use the BFF cookie flow.

## Non-goals
- Does not rewire stores or substantially change `cmd/harbor-mgmt` beyond the
  CallerSource adapter.
- Does not touch `POST /enroll`, `POST /recovery/begin`, `POST /recovery/complete`
  (legitimately unauthenticated endpoints).
- Does not fix other audit findings (C2, C3, C4, H1-H8, M1-M5).
