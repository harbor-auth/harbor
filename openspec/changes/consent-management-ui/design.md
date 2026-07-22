# Design: Consent management UI (user privacy dashboard)

## Key Decisions

### Decision 1: Composition, not new authority
**Chosen:** The dashboard is a pure composition over already-shipped
user-scoped, region-pinned endpoints (`consent-ledger` list/revoke,
`user-audit-trail` read, session/WebAuthn stores). It introduces **no** new data
store and **no** new authorization primitive.
**Rationale:** A privacy dashboard is dangerous exactly when it grows a new,
broader read capability. Restricting it to composing existing caller-scoped
endpoints means it cannot see across users by construction — the safety property
is inherited, not re-invented.
**Alternatives considered:** A new "dashboard service" with its own aggregated
read model (rejected — a new cross-user read path is a design violation); an
admin-style view (rejected — the user's dashboard must be strictly
caller-scoped).

### Decision 2: Activity view decrypts under the caller's DEK only
**Chosen:** The activity (audit-trail) view renders the caller's **own
decrypted** events, decrypting only under the caller's DEK; there is no operator
plaintext path.
**Rationale:** The audit trail is the user's own history and is envelope-
encrypted per §11.6. The UI must preserve that — only the caller (holding their
DEK-derived context) can read their events; the operator serving the page never
sees plaintext.
**Alternatives considered:** Server-side pre-decryption for rendering (rejected —
creates an operator plaintext path); a shared read key (rejected — breaks
per-user isolation).

### Decision 3: Soft, feature-detected relay toggle
**Chosen:** The per-RP email-relay toggle is a soft, feature-detected element —
present and functional when `email-relay-service` is live, absent/disabled
otherwise.
**Rationale:** This UI (Gate 3) may ship before or after relay (Gate 4). A soft
toggle lets the dashboard ship independently and light up relay when it arrives,
with no hard build-order coupling.
**Alternatives considered:** Hard-depend on relay (rejected — needlessly couples
Gate 3 to Gate 4); hide the toggle permanently (rejected — loses the control
once relay ships).

### Decision 4: XSS-safe rendering of RP/user strings
**Chosen:** All RP- and user-supplied strings (app names, scopes, device labels)
are contextually escaped; no user/RP content is trusted in the template.
**Rationale:** The dashboard renders attacker-influenceable strings (an RP picks
its own name). Contextual escaping is the load-bearing defence against a stored
XSS that could exfiltrate another view's data.
**Alternatives considered:** Trust server-provided strings (rejected — RP names
are attacker-controlled); client-side sanitisation only (rejected — must escape
at render in the correct context).

## Interface sketch

```go
package bff

// DashboardData composes the signed-in caller's own grants, activity, and
// sessions from shipped user-scoped endpoints. Strictly caller-scoped and
// region-pinned; the activity events are decrypted under the caller's DEK only.
func DashboardData(ctx context.Context, caller UserID) (Dashboard, error)
```

## Security & privacy invariants

- The dashboard is strictly caller-scoped — no cross-user or operator read path
  (Decision 1).
- The activity view decrypts under the caller's DEK only; the operator sees no
  plaintext (Decision 2).
- Reads are region-pinned; UI metrics are aggregate-only; no PII in client
  logs/analytics.
- RP/user-supplied strings are contextually escaped (Decision 4).
