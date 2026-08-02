---
title: Collapse production wiring onto durable dependencies
status: complete
created: 2026-08-02
plan: docs/plans/production-wiring-collapse.md
---

# Proposal: Collapse production wiring onto durable dependencies

## Problem

The hot and management binaries could assemble development, no-op, or
in-memory collaborators in production. That made startup appear successful
while authentication, cross-replica authorization-code exchange, refresh-token
issuance, enrollment, and dynamic registration were unavailable or unsafe.
Deployment manifests also projected names and secrets that did not match the
runtime configuration contract.

## Proposed Solution

Build both binaries from one fail-closed object graph backed by required
PostgreSQL and Redis dependencies. Remove production scaffolds and development
mode, require all security-critical collaborators at construction, explicitly
size PostgreSQL pools, and align raw Kubernetes and Helm configuration. Preserve
only the documented revocation hot-path caches and local crypto provider.

Add architecture and integration coverage proving the live graph uses durable
implementations and supports cross-replica authorization, refresh, enrollment,
and client registration.

## Non-goals

- Replacing Redis with PostgreSQL.
- Replacing the local crypto provider before an HSM backend exists.
- Removing the deliberate revocation cache.
- Adding post-launch compatibility migrations.
