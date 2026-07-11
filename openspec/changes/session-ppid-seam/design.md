# Design: Session seam — login → PPID → subject

## Key Decisions

### Decision 1: Implement the existing `SessionResolver` seam
**Chosen:** A real `SessionResolver`; `service.go`'s `/authorize` logic is
untouched.
**Rationale:** The seam was designed for this swap; the DoS-safe flow ordering
and error channels stay intact.
**Alternatives considered:** Threading login/PPID through the service directly
(couples flow to auth + crypto, rejected).

### Decision 2: Derive PPID via the already-tested `identity.DerivePPID`
**Chosen:** Call the existing, frozen-vector-tested primitive; do not
reimplement HMAC here.
**Rationale:** §3.2 correctness is guarded by golden vectors (F2); reuse keeps a
single source of truth for the derivation.

### Decision 3: Fail closed — never fall back to raw `user_id`
**Chosen:** Any error in auth/decrypt/lookup denies the request; no token is
ever minted with a non-PPID subject.
**Rationale:** A raw `user_id` as `sub` would silently break cross-RP
unlinkability — the exact core-promise violation §11.7 fail-closed exists to
prevent.
**Alternatives considered:** Best-effort fallback subject (catastrophic privacy
leak, rejected).

### Decision 4: Minimal consent step for v1, full UI later
**Chosen:** Land the security-critical parts (PPID derivation + grant recording)
now behind a minimal/programmatic consent; defer the hosted UI.
**Rationale:** Unlinkability and consent persistence are the parts that must be
correct; the UI is presentation and can follow without changing the seam.

### Decision 5: Cache the unwrapped DEK per session, never persist it
**Chosen:** Keep the unwrapped DEK in memory for the session's duration only.
**Rationale:** Avoids a KEK unwrap on every hot-path derivation while never
writing a plaintext key anywhere (§4.4, §6.5.7).
