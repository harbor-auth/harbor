# Spec: Consent management UI (user privacy dashboard)

Adds a user-authenticated privacy dashboard on the BFF, composed entirely from
shipped user-scoped primitives: a connected-apps view with a revoke action that
cascades RP token/session revocation, an activity view that decrypts the
caller's own audit-trail under the caller's DEK only, sessions/device
management, and a soft per-RP relay toggle. Strictly caller-scoped,
region-pinned, aggregate-only UI metrics. Realises §2.1.

## ADDED Requirements

### Requirement: REQ-001 Caller-scoped connected-apps and activity views

The system SHALL present a signed-in user only their **own** connected apps
(consent grants: scopes, granted-at, last-used), activity events, and sessions.
It MUST NOT expose any other user's data.

#### Scenario: A user sees only their own data

**Given** two users A and B
**When** user A opens the dashboard
**Then** A sees only A's grants, activity, and sessions — never B's

### Requirement: REQ-002 Revoke-app cascades LIVE RP revocation, fail-closed

The system SHALL, when the user revokes a connected app, call the shipped
consent-revoke, which MUST invalidate **live** artifacts — not merely write a
ledger row. The cascade is: ledger revoke event → client-grant row invalidation
→ refresh-token family invalidation → active session invalidation. Revocation
MUST NOT be cosmetic (i.e. must not wait for natural token expiry). If any step
of the cascade fails mid-way, the grant is treated as **revoked / access
denied** (fail closed), the cascade is retried, and no partial "still-live"
state is silently left behind. The change is reflected in the view.

#### Scenario: Revoking an app cuts it off immediately

**Given** a connected app with an active grant, live refresh-token family, and active session
**When** the user revokes it from the dashboard
**Then** the ledger revoke event is written, the client-grant row is invalidated, the refresh-token family and active sessions are invalidated (not left live until expiry), and the app no longer appears as connected

#### Scenario: A mid-cascade failure fails closed

**Given** a revocation whose refresh-token or session invalidation step fails mid-cascade
**When** the cascade cannot complete
**Then** the grant is treated as revoked / access-denied, the cascade is retried, and no partial still-live artifact is silently left usable

### Requirement: REQ-003 Activity decrypts under the caller's DEK only

The system SHALL render the activity (audit-trail) view by decrypting the
caller's own events under the caller's DEK only. There MUST be no operator
plaintext path and no cross-user decryption.

#### Scenario: No operator plaintext path

**Given** the dashboard server serving user A's activity view
**When** the view is rendered
**Then** only A's events are decrypted, under A's DEK, and the operator obtains no plaintext

### Requirement: REQ-004 Soft, feature-detected relay toggle

The system SHALL surface a per-RP email-relay toggle when `email-relay-service`
is available and MUST degrade gracefully (absent/disabled) when it is not, with
no hard dependency.

#### Scenario: Toggle degrades gracefully when relay is absent

**Given** a deployment where `email-relay-service` is not live
**When** the user opens the dashboard
**Then** the per-RP relay toggle is absent or disabled and the rest of the dashboard works normally

### Requirement: REQ-005 Region-pinned reads and aggregate-only UI metrics

The system SHALL perform region-pinned reads and emit only aggregate-only UI
metrics, with no PII in client logs or analytics.

#### Scenario: No PII in UI telemetry

**Given** the dashboard is in use
**When** UI metrics are emitted
**Then** only aggregate metrics are recorded and no PII appears in client logs or analytics
