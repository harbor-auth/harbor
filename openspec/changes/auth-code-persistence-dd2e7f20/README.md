# Authorization Code Persistence

Replace in-memory auth code store with Redis-backed durable store for multi-replica safety.

## Status

In Progress

## Files

- [proposal.md](./proposal.md) — Problem statement and proposed solution
- [design.md](./design.md) — Technical architecture and implementation details
- [tasks.md](./tasks.md) — Implementation checklist
- [specs/core/spec.md](./specs/core/spec.md) — Requirements and acceptance scenarios

## Summary

Authorization codes are short-lived (≤60s) but must survive across replicas. The
in-memory store causes non-deterministic `invalid_grant` errors in multi-replica
deployments. This change introduces a Redis-backed `AuthCodeStore` with:

- Atomic `Consume` via Lua script
- TTL-based expiry (no cleanup jobs)
- Consumed marker with 2× TTL for reliable reuse detection
- Fallback to in-memory for dev environments without Redis
