---
name: db-migrate
description: Postgres schema migrations using the expand/contract pattern (safe, backward-compatible, reversible).
---

Run Harbor's Postgres schema migrations. Per `docs/DESIGN.md` §1.8, **migrations run as a gated, backward-compatible step using expand/contract, so schema changes are decoupled from code deploys — each independently reversible**. SQL is the contract (§1.3): after any schema change, regenerate typed Go via `sqlc` (see `@codegen`).

> **Update this skill:** if the migration tool, directory layout, or commands below drift from the code, fix this file as part of your change. Harbor is greenfield — this describes the **intended** workflow per the design and is updated as the code lands. A stale skill is a bug.

## Why expand/contract

During a rollout, **old and new code run simultaneously**. A migration must never break the currently-running code. So we never change a column's meaning in place — we **add the new shape, migrate onto it, then remove the old shape** in separate, independently-reversible steps. Region isolation (§5) means migrations run **per-region**, so a bad migration is contained to one jurisdiction.

## The three phases (each its own migration + deploy)

1. **Expand** — add the new schema **additively**: a new **nullable** column, a new table, or a new index built `CONCURRENTLY`. Backward-compatible: old code ignores it.
2. **Migrate / backfill + dual-write** — deploy code that writes **both** old and new; **backfill** existing rows **in batches** (avoid long locks); reads can start preferring the new shape.
3. **Contract** — once **all** code reads/writes the new shape and it's proven in prod, **drop** the old column/constraint in a **later, separate** migration.

## Safety rules

- **Additive first.** Never rename/repurpose a column in place — add new, migrate, drop old.
- **`NOT NULL` only after backfill:** add the column **nullable** → backfill → then `SET NOT NULL` (or add a `NOT VALID` constraint, backfill, then `VALIDATE`).
- **Build indexes `CONCURRENTLY`** so you don't hold a write lock on a hot table. **Gotcha:** `CREATE/DROP INDEX CONCURRENTLY` **cannot run inside a transaction block**, but migration tools wrap each migration in a transaction by default — you must opt out: goose `-- +goose NO TRANSACTION`; golang-migrate: isolate the `CONCURRENTLY` statement in its own migration (it runs statements outside a txn). Otherwise the migration fails at runtime.
- **Avoid table-rewriting ops** that take `ACCESS EXCLUSIVE` locks (e.g. changing a column type on a big table) — use an additive column + backfill instead.
- **Keep each migration small and reversible** — every migration MUST have a working `down`.
- **Fail fast, don't stall the hot path:** set a short `lock_timeout` and `statement_timeout` so a blocked migration errors out instead of blocking `/authorize`/`/token`.

```sql
SET lock_timeout = '3s';
SET statement_timeout = '30s';
```

## The `sqlc` tie-in (§1.3)

The query **is** the contract. After changing schema or queries, **regenerate typed Go with `sqlc` via `@codegen`** — never hand-write DB types. A schema change that doesn't regenerate is **drift** and will fail CI (§1.5).

## Commands (intended)

Migrations live under **`db/migrations/`** as versioned `.up.sql` / `.down.sql` pairs. Using a tool such as **`golang-migrate`** or **`goose`**:

```bash
# Create a new migration pair
migrate create -ext sql -dir db/migrations -seq add_pairwise_sub     # golang-migrate
goose -dir db/migrations create add_pairwise_sub sql                  # goose

# Apply / roll back / status
migrate -path db/migrations -database "$DATABASE_URL" up             # apply all
migrate -path db/migrations -database "$DATABASE_URL" down 1         # roll back one
migrate -path db/migrations -database "$DATABASE_URL" version        # status

# goose equivalents
goose -dir db/migrations up
goose -dir db/migrations down
goose -dir db/migrations status

# Regenerate typed Go after the schema change (see @codegen)
sqlc generate
```

## CI/CD (§1.8)

Migrations are a **gated step separate from the code deploy**, run **per-region**, always **backward-compatible**, and **independently reversible**. Progressive delivery (canary → rollout) with automated health checks and fast rollback; a failed migration in one region does not touch the others.

## Annotated example — adding `grants.pairwise_sub` (§10)

```sql
-- === Phase 1: EXPAND (migration 0007) ===
-- NOTE: CONCURRENTLY needs NO transaction wrapping (goose: -- +goose NO TRANSACTION).
-- Additive + nullable; index built without locking writes.
ALTER TABLE grants ADD COLUMN pairwise_sub TEXT;                 -- nullable: old code ignores it
CREATE INDEX CONCURRENTLY idx_grants_pairwise_sub                -- no ACCESS EXCLUSIVE lock
  ON grants (pairwise_sub);
-- down: DROP INDEX CONCURRENTLY idx_grants_pairwise_sub; ALTER TABLE grants DROP COLUMN pairwise_sub;
```

```text
-- === Phase 2: MIGRATE (deploy dual-write code + backfill) ===
-- App now writes pairwise_sub on every new/updated grant.
-- Backfill existing rows in batches to avoid long locks:
--   UPDATE grants SET pairwise_sub = <derive> WHERE pairwise_sub IS NULL AND id BETWEEN ...;
-- Once backfilled, optionally: ALTER TABLE grants ALTER COLUMN pairwise_sub SET NOT NULL;
```

```sql
-- === Phase 3: CONTRACT (later migration, once new shape is proven) ===
-- (assuming a prior `legacy_sub` column this replaces)
ALTER TABLE grants DROP COLUMN legacy_sub;   -- remove the old shape, separately reversible
```

## Checklist

- [ ] **Expand is additive** (nullable column / new table / new index) — doesn't break running code?
- [ ] Indexes created **`CONCURRENTLY`**?
- [ ] `NOT NULL`/constraints added **only after** a **batched** backfill?
- [ ] Each migration has a **working `down`** and is small/reversible?
- [ ] `lock_timeout` / `statement_timeout` set so it fails fast?
- [ ] **`sqlc generate` re-run** (via `@codegen`) — **no drift** (`git diff --exit-code` clean)?
