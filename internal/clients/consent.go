package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// consentQuerier is the narrow interface over *db.Queries that DBConsentStore
// needs. Production code passes *db.Queries; tests pass a small fake.
type consentQuerier interface {
	GetConsentGrantByUserClient(ctx context.Context, arg db.GetConsentGrantByUserClientParams) (db.ConsentGrant, error)
	UpsertConsentGrant(ctx context.Context, arg db.UpsertConsentGrantParams) (db.ConsentGrant, error)
	ListConsentGrantsByUser(ctx context.Context, userID pgtype.UUID) ([]db.ConsentGrant, error)
	RevokeConsentGrant(ctx context.Context, id pgtype.UUID) error
}

// DBConsentStore is a sqlc-backed oidc.ConsentStore. It persists consent grants
// in the consent_grants table (docs/DESIGN.md §11) — per-(user, RP, scope)
// consent records enforced at /authorize and managed via harbor-mgmt.
type DBConsentStore struct {
	q       consentQuerier
	emitter oidc.ConsentEventEmitter
}

// NewDBConsentStore returns a ConsentStore backed by q. q is typically
// *db.Queries obtained from a pgx connection pool. Event emission defaults to
// a no-op; call WithEmitter to wire an observability backend.
func NewDBConsentStore(q consentQuerier) *DBConsentStore {
	return &DBConsentStore{q: q, emitter: oidc.NoopConsentEventEmitter()}
}

// WithEmitter attaches a ConsentEventEmitter so grant/escalation/revocation
// events are published for audit and analytics. A nil emitter leaves the
// existing (no-op) emitter in place. Returns s for chaining.
func (s *DBConsentStore) WithEmitter(emitter oidc.ConsentEventEmitter) *DBConsentStore {
	if emitter != nil {
		s.emitter = emitter
	}
	return s
}

// emit publishes a consent event best-effort: a nil emitter is skipped and any
// emit error is swallowed so observability never blocks the consent write path.
func (s *DBConsentStore) emit(ctx context.Context, event oidc.ConsentEvent) {
	if s.emitter == nil {
		return
	}
	//nolint:errcheck // consent event emission is best-effort; failure must not block the grant
	_ = s.emitter.Emit(ctx, event)
}

// Compile-time proof that DBConsentStore implements oidc.ConsentStore.
var _ oidc.ConsentStore = (*DBConsentStore)(nil)

// Get implements oidc.ConsentStore. Returns (ConsentGrant{}, false, nil) when
// no active grant exists for (userID, clientID). Any DB error propagates as
// the third return value.
func (s *DBConsentStore) Get(ctx context.Context, userID, clientID string) (oidc.ConsentGrant, bool, error) {
	uUID, err := parseUUID(userID)
	if err != nil {
		return oidc.ConsentGrant{}, false, fmt.Errorf("clients: Get consent: invalid userID: %w", err)
	}
	row, err := s.q.GetConsentGrantByUserClient(ctx, db.GetConsentGrantByUserClientParams{
		UserID:   uUID,
		ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.ConsentGrant{}, false, nil
		}
		return oidc.ConsentGrant{}, false, fmt.Errorf("clients: Get consent: %w", err)
	}
	return rowToConsentGrant(row), true, nil
}

// Upsert implements oidc.ConsentStore. Creates a new consent grant or updates
// the scopes of an existing active grant. Scopes are canonicalized (sorted and
// deduplicated) before storage.
func (s *DBConsentStore) Upsert(ctx context.Context, userID, clientID string, scopes []string) (oidc.ConsentGrant, error) {
	uUID, err := parseUUID(userID)
	if err != nil {
		return oidc.ConsentGrant{}, fmt.Errorf("clients: Upsert consent: invalid userID: %w", err)
	}

	// Look up any existing active grant BEFORE writing so we can classify the
	// resulting event as a first-time grant vs a scope escalation. A lookup
	// error is non-fatal — we fall back to treating the write as a new grant.
	//nolint:errcheck // a prior read failure is tolerated; Upsert re-derives state from the write below
	existing, hadExisting, _ := s.Get(ctx, userID, clientID)

	canonicalScopes := oidc.CanonicalizeScopes(scopes)
	row, err := s.q.UpsertConsentGrant(ctx, db.UpsertConsentGrantParams{
		UserID:   uUID,
		ClientID: clientID,
		Scopes:   canonicalScopes,
	})
	if err != nil {
		return oidc.ConsentGrant{}, fmt.Errorf("clients: Upsert consent: %w", err)
	}
	grant := rowToConsentGrant(row)

	// Classify and emit the consent event. A re-confirmation with no new scopes
	// emits nothing — there is no meaningful state change to record.
	switch {
	case !hadExisting:
		s.emit(ctx, oidc.ConsentEvent{
			Kind:      oidc.ConsentEventGranted,
			GrantID:   grant.ID,
			UserID:    grant.UserID,
			ClientID:  grant.ClientID,
			Scopes:    grant.Scopes,
			Timestamp: grant.GrantedAt,
		})
	case scopesWidened(existing.Scopes, canonicalScopes):
		s.emit(ctx, oidc.ConsentEvent{
			Kind:      oidc.ConsentEventScopeEscalated,
			GrantID:   grant.ID,
			UserID:    grant.UserID,
			ClientID:  grant.ClientID,
			Scopes:    grant.Scopes,
			Timestamp: grant.UpdatedAt,
		})
	}

	return grant, nil
}

// List implements oidc.ConsentStore. Returns all active (non-revoked) consent
// grants for a user, newest first.
func (s *DBConsentStore) List(ctx context.Context, userID string) ([]oidc.ConsentGrant, error) {
	uUID, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("clients: List consents: invalid userID: %w", err)
	}
	rows, err := s.q.ListConsentGrantsByUser(ctx, uUID)
	if err != nil {
		return nil, fmt.Errorf("clients: List consents: %w", err)
	}
	out := make([]oidc.ConsentGrant, len(rows))
	for i, r := range rows {
		out[i] = rowToConsentGrant(r)
	}
	return out, nil
}

// Revoke implements oidc.ConsentStore. Soft-deletes by ID. id must be a UUID string.
func (s *DBConsentStore) Revoke(ctx context.Context, id string) error {
	gUID, err := parseUUID(id)
	if err != nil {
		return fmt.Errorf("clients: Revoke consent: invalid id: %w", err)
	}
	if err := s.q.RevokeConsentGrant(ctx, gUID); err != nil {
		return fmt.Errorf("clients: Revoke consent: %w", err)
	}
	// The revoke query returns no row, so only the grant ID is available for the
	// event; audit consumers resolve (user, client, scopes) from GrantID.
	s.emit(ctx, oidc.ConsentEvent{
		Kind:      oidc.ConsentEventRevoked,
		GrantID:   id,
		Timestamp: time.Now(),
	})
	return nil
}

// scopesWidened reports whether newScopes contains any scope not already present
// in oldScopes (i.e. the grant is being expanded). Both slices are expected to
// be canonical (sorted, deduplicated).
func scopesWidened(oldScopes, newScopes []string) bool {
	old := make(map[string]struct{}, len(oldScopes))
	for _, sc := range oldScopes {
		old[sc] = struct{}{}
	}
	for _, sc := range newScopes {
		if _, ok := old[sc]; !ok {
			return true
		}
	}
	return false
}

// rowToConsentGrant maps a sqlc ConsentGrant row to the oidc domain type.
// It is a pure function so it is directly unit-testable without a DB.
func rowToConsentGrant(row db.ConsentGrant) oidc.ConsentGrant {
	return oidc.ConsentGrant{
		ID:        uuidToString(row.ID),
		UserID:    uuidToString(row.UserID),
		ClientID:  row.ClientID,
		Scopes:    row.Scopes,
		GrantedAt: row.GrantedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
		RevokedAt: timePtrFromPgtz(row.RevokedAt),
	}
}
