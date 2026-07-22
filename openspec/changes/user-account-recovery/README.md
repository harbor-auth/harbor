# user-account-recovery

Give passkey users a **safe, fail-closed** way back into their account when they
lose their authenticators (§11.7, §4.4) — without handing the operator a
backdoor. Adds a `recovery_codes` table (migration 0015) that stores only a
**salted SHA-256 hash** of each **single-use** code (the plaintext is shown to
the user exactly once and never persisted), supports **fallback authenticators**
(additional passkeys and hardware keys registered through the shipped WebAuthn
path), and a recovery ceremony that accepts a valid unused code or a fallback
factor, re-authenticates the user, and **requires enrolling a fresh passkey
before clearing the `recovery_required` fail-closed guard**. Recovery is
single-use (replay rejected), rate-limited, region-pinned, metered
aggregate-only, and audited (`auth.recovery_*`). Scoped to a minimal Phase 1 —
social / M-of-N (guardian) recovery is explicitly deferred to a later wave.
