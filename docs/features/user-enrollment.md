---
title: User Creation & Enrollment (§11.1 signup)
status: implemented
design_refs: [§11.1, §10, §4.4]
code:  [internal/identity/, internal/webauthn/, internal/mgmtapi/, cmd/harbor-mgmt/, db/queries/]
spec:  []
tests: [internal/identity/, internal/webauthn/]
depends_on: [webauthn-passkeys, ppid-identity]
plan: user-enrollment
last_reconciled: 2026-07-20
---

# User Creation & Enrollment (§11.1 signup)

## Summary

Harbor has a real signup: enrollment creates a region-encoded `users` row with a
wrapped DEK and an envelope-encrypted `pairwise_secret`, then registers the
user's first passkey to the `credentials` table — replacing the insecure
dev-only `?user_id=` query-param path. The pure `identity.Enroller` orchestrates
region assignment + secret generation + DEK wrapping (no DB client — persistence
lives behind `identity.UserPersister`, §1.7), the management plane exposes
`POST /enroll` (`internal/mgmtapi`), and `webauthn.DBStore` persists credentials
and **atomically** activates the user on first passkey (§11.1). This is the front
door that produces the `pairwise_secret` every PPID derivation (§3.2) depends on.

## Behavior (as-built)

**Enrollment orchestration (`identity.Enroller`)** — `NewEnroller(keys, cipher,
persist)` builds a `UserRecord`: a fresh UUIDv4 `id`, a validated `region`, a
DEK wrapped under the regional KEK (`crypto.KeyProvider.WrapDEK`), and a CSPRNG
`pairwise_secret` AES-256-GCM-encrypted under that DEK. The AAD binds the
encrypted secret to the specific user id (`identity.PairwiseSecretAAD`), so a
blob minted for user A cannot authenticate when opened as user B (§4.4). Every
freshly enrolled user gets `RecoveryRequired = true` (REQ-005) — a fail-closed
guard until recovery setup completes. The core logic is pure; persistence is
delegated to `UserPersister`.

**Management endpoint (`POST /enroll`, `internal/mgmtapi`)** — accepts a region
string (body capped at 4 KB to bound memory, §6.5), enrolls the user, and
reports enrollment status `pending` — distinct from the `users.status`
(`active` on insert): the account isn't usable until passkey registration
completes (§11.1). `cmd/harbor-mgmt` refuses to enroll with a dev key against a
real DB — `HARBOR_KMS_SECRET` **must** be set when `DATABASE_URL` is configured
(else anyone with the source could re-derive every user's pairwise secret).
Without `DATABASE_URL` it falls back to a no-op persister (dev only) and warns.

**Credential store (`webauthn.DBStore`)** — sqlc-backed store replacing the
in-memory one, keyed off the real `users.id`. `AddCredentialAndActivateUser`
runs credential-create + user-activate inside one pgx transaction (`txBeginner`)
so a half-enrolled account is impossible; the same logic runs inside or outside
a transaction via the narrow `activationQuerier` seam.

**Storage** — `db/queries/users.sql` (`CreateUser`, `GetUser`, `SetUserStatus`,
`SetRecoveryComplete`) with both 🔒 columns (`dek_wrapped`, `pairwise_secret`)
stored as envelope-encrypted `bytea` — never plaintext (§4.4, §10). Migration
`0003_webauthn_cred_id` adds the credential lookup column.

## Interfaces / Endpoints

- `POST /enroll` (harbor-mgmt) → creates the user, returns `{ user_id, region,
  status: "pending" }`; the passkey ceremony completes activation.
- Exported Go surface:
  - `identity.Enroller` / `identity.NewEnroller`, `identity.UserRecord`,
    `identity.UserPersister`, `identity.EnrollResult`, `identity.PairwiseSecretAAD`.
  - `webauthn.DBStore` (+ `AddCredentialAndActivateUser`).
- Storage: `db/queries/users.sql`; migration `0003_webauthn_cred_id`.

## Code map

| Path | Role |
|---|---|
| `internal/identity/enroll.go` | Pure `Enroller` — region + DEK wrap + `pairwise_secret` encrypt; `UserRecord`/`UserPersister` seam. |
| `internal/mgmtapi/enroll.go` | `POST /enroll` handler (region parse, body cap, `pending` status). |
| `internal/webauthn/store_db.go` | `DBStore` — sqlc credential store + atomic credential-create/user-activate. |
| `db/queries/users.sql` | `CreateUser`/`GetUser`/`SetUserStatus`/`SetRecoveryComplete` (secrets as encrypted bytea). |
| `db/migrations/0003_webauthn_cred_id.up.sql` | Adds the WebAuthn credential-id lookup column. |
| `cmd/harbor-mgmt/main.go` | Wires key provider + persister; refuses dev key against a real DB. |

## Security & privacy invariants

- **Secrets never stored plaintext (§4.4, §10)** — `dek_wrapped` is sealed under
  the regional KEK; `pairwise_secret` is GCM-encrypted under that DEK, both as
  `bytea`.
- **AAD binds secret to user (§4.4)** — `PairwiseSecretAAD(userID)` makes a
  cross-user blob swap fail GCM authentication.
- **Fail-closed enrollment key policy** — `harbor-mgmt` refuses to enroll with a
  dev KMS key when a real `DATABASE_URL` is configured.
- **Recovery fail-closed (REQ-005)** — enrollment sets `RecoveryRequired = true`
  until recovery credentials are added.
- **Atomic enrollment (§11.1)** — user row + first credential are activated in a
  single transaction; no half-enrolled accounts.
- **Dev-only `user_id` path removed** — the insecure query-param path is deleted.

## Tests

- `internal/identity/enroll_test.go` — enrollment produces exactly one record
  with region + wrapped DEK + encrypted `pairwise_secret`; AAD round-trips for
  the right user and fails for the wrong user; `RecoveryRequired` set.
- `internal/webauthn/store_db_test.go` — credential persists to the real
  `users.id`; `AddCredentialAndActivateUser` is atomic (activate + create
  together); sign-count update; the dev-only path is gone.

## Known gaps / TODOs

- **Recovery setup is partial (§7.2)** — enrollment records the requirement +
  recovery-code path; full social/≥2-method recovery is a separate plan.
- **`pairwise_secret` DEK wrapping depends on** the regional KEK provider from
  [envelope-encryption-kms](../plans/envelope-encryption-kms.md) (in progress);
  dev uses a local key provider gated by `HARBOR_KMS_SECRET`.
- Consumed by [session-ppid-seam](session-ppid-seam.md), which decrypts the
  enrolled `pairwise_secret` to derive the per-RP PPID.
