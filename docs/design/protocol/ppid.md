> **DESIGN §3.2 (1/2)** · [↑ DESIGN index](../../DESIGN.md) · next: [ppid-guarantees](ppid-guarantees.md)

# Pairwise Subject Identifiers (PPID) — Derivation & Storage

OIDC supports `subject_type = pairwise`. For each `(user, RP-sector)` pair we derive a stable, opaque `sub` — the **PPID** — that is the privacy linchpin of the whole system (see the positioning in §2.4). This section specifies exactly how it's derived, stored, and why it resists correlation *even by us*.

## 3.2.1 Derivation

```
ppid = Base64URL( HMAC-SHA256( key = user_pairwise_secret,
                               msg = sector_identifier || user_id ) )
```

> **Implementation note:** the `||` concatenation is made **injective** by length-prefixing the sector (fixed-width big-endian length, then `sector`, then `user_id`), so distinct pairs can never encode to the same message (e.g. `("a","bc")` ≠ `("ab","c")`). See `internal/identity/ppid.go`.

| Input | What it is | Why |
|---|---|---|
| `user_pairwise_secret` | A high-entropy secret **generated per user** at signup, held **encrypted** in the user's home region | It is the HMAC **key**, not a message input, so the output is a keyed one-way function — irreversible and unforgeable without the secret. |
| `sector_identifier` | An identifier grouping an RP's redirect URIs (see §3.2.2) | Makes the `sub` **stable per RP** but **unrelated across RPs**. |
| `user_id` | The user's opaque internal id | Binds the `sub` to this specific user within the sector. |

**Why HMAC (not a plain hash or a stored random value):** HMAC-SHA256 is **keyed, deterministic, and one-way**. Deterministic ⇒ the same `(user, sector)` always yields the same `sub` (stable logins) without storing a row per pair up front. Keyed ⇒ nobody can compute or verify a `sub` without the secret. One-way ⇒ a leaked `sub` reveals nothing about the user or other RPs' `sub`s.

**Why a *per-user* secret key instead of a single global salt:** this is the crucial design choice. With a global salt/pepper, that one secret's compromise would let an attacker recompute **every** user's `sub` at **every** RP and deanonymize the entire population in one shot. With a **per-user** secret, there is **no single global secret** whose compromise breaks everyone — correlating a user across RPs requires *that specific user's* secret, which lives encrypted in their region behind the KEK/HSM (§4.4). The blast radius of any key compromise is one user, not the world.

> **KEK blast-radius footnote:** "one compromised key = one user" holds strictly **at the DEK layer** (the per-user pairwise secret is the DEK). The **regional KEK** that wraps every DEK in the region is a population-level single point: coercion or compromise of the KEK would allow bulk-unwrap of all per-user secrets in that region. The KEK must therefore be **HSM-bound, non-exportable, and incapable of bulk-unwrap in any API it exposes** (§7.3). This is a residual risk — see the **KEK bulk-unwrap** entry in §A.7.

## 3.2.2 The `sector_identifier`

Per the OIDC spec, the sector groups an RP's redirect URIs so a single logical RP with many domains still sees **one** stable `sub`:

- By default the sector is derived from the host component of the RP's registered `redirect_uri`(s).
- An RP with multiple redirect hosts declares a **`sector_identifier_uri`** (a JSON array of its redirect URIs); Harbor uses that host as the sector so all of the RP's domains map to the same `sub`.
- **Two different RPs get different sectors**, hence **unrelated `sub`s** — they cannot join identities by comparing subjects.

**Sector granularity is a named design decision with product consequences:**

| Scenario | Consequence |
|---|---|
| `client_id` / `redirect_uri` rotation (RP rotates credentials) | As long as the `sector_identifier_uri` is stable, the `sub` is unchanged. RPs **must keep a stable sector**, not rotate it as they would a `client_secret`. |
| RP re-registration under a new sector | The `sub` changes — the RP sees a new user. This is intentional (a new sector = a new privacy context) but must be communicated clearly; migrating accounts requires an explicit **account-linking step** (see §3.2.6). |
| Vendor with many apps (multi-tenant RP) | Each app that registers as a separate RP with its own sector gets a different `sub`, blocking cross-app correlation even within one vendor — **tighter than Apple** (§2.4.5). A vendor that wants shared identity across its apps may share a `sector_identifier_uri`, but that is an explicit, deliberate opt-in. |

## 3.2.3 Storage model

- `user_pairwise_secret` is **generated at signup**, **envelope-encrypted** (wrapped by the regional KEK per §4.4), stored **only in the user's home region**, **never logged**, and **never leaves the region**.
- The materialized `pairwise_sub` for each user↔RP grant is persisted in the **`grants` table** (§10, column `pairwise_sub`). At token-issuance time we read it from the grant (a cheap indexed lookup) rather than recomputing the HMAC on the hot path, and it also enables **reverse lookup** (`pairwise_sub → grant → user`) when an RP calls `/userinfo` or introspection.
- This `pairwise_sub` is exactly the value that appears as the ID-token **`sub`** in the §11.2 flow.
