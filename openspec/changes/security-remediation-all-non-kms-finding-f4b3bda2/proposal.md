---
title: Remediate all non-KMS security findings
status: complete
created: 2026-08-01
---

# Proposal: Remediate all non-KMS security findings

## Problem

Production composition roots retained scaffold implementations, token consumers
did not share one complete verification policy, consent and recovery state was
split across authorities, browser and WebAuthn mutations admitted race windows,
and deployment configuration could weaken abuse and supply-chain controls.

## Proposed Solution

Fail closed in production and use durable PostgreSQL, Redis, and outbox-backed
implementations across the hot and management services. Apply one client
authentication and JWT policy, make consent and revocation lifecycle changes
durable and replica-safe, bind recovery and MFA to distributed BFF sessions,
atomically consume browser continuations, guard WebAuthn counters, and enforce
the same security contract in Helm and raw manifests.

## Non-Goals

- Provisioning or inventing regional OVH KMS keys or credentials.
- Broad product features unrelated to the enumerated security findings.
- Allowing local crypto or scaffold stores in production.
