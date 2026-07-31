---
title: Replace the spoofable X-Harbor-User-ID header with BFF session context
status: in-progress
plan: docs/plans/fix-mgmt-context-auth.md
design_refs: [§9, §6.5, §11.3]
created: 2026-07-30
---

# Proposal: Replace spoofable X-Harbor-User-ID header with BFF session context

## Problem

`internal/mgmtapi` read caller identity directly from the `X-Harbor-User-ID`
request header — a client-supplied value. No middleware ever set or stripped
that header. Any client could pass an arbitrary victim user ID and invoke
`POST /compliance/export` (full DSAR PII bundle) or `POST /compliance/erase`
(irreversible crypto-shred) on any account. This was audit finding C1:
universal account takeover.

## Proposed Solution

Delete the header seam entirely. Introduce a tiny `CallerSource` interface that
`mgmtapi` accepts via injection, decoupled from `internal/bff` (which cannot be
imported directly without creating a cycle). The BFF session — already populated
in the request context by `bff.Middleware` — is the only legitimate auth seam.
One shared `(*Server).callerID(w, r)` helper reads the context, writes 401 on
empty, and replaces all 14 former `r.Header.Get` call sites.

## Non-Goals

- Rewiring stores or any change to `cmd/harbor-mgmt` beyond the `CallerSource`
  adapter injection.
- Edge-layer header stripping (rejected: cluster-internal paths bypass ingress).
- Any change to the OIDC hot-path or WebAuthn ceremony flows.
