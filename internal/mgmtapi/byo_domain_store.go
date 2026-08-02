package mgmtapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/relay"
)

type byoDomainQueries interface {
	CreateBYODomain(context.Context, db.CreateBYODomainParams) (db.ByoDomain, error)
	GetBYODomainByName(context.Context, db.GetBYODomainByNameParams) (db.ByoDomain, error)
	ListBYODomainsByUser(context.Context, pgtype.UUID) ([]db.ByoDomain, error)
	UpdateBYODomainState(context.Context, db.UpdateBYODomainStateParams) (db.ByoDomain, error)
	DeleteBYODomain(context.Context, pgtype.UUID) (pgtype.UUID, error)
}

// DBBYODomainStore persists user-owned BYO-domain verification challenges in
// PostgreSQL. Name lookups remain owner-scoped so callers cannot discover that
// another user has already registered a domain.
type DBBYODomainStore struct {
	q byoDomainQueries
}

var _ BYODomainStore = (*DBBYODomainStore)(nil)

// NewDBBYODomainStore creates a PostgreSQL-backed BYO-domain store.
func NewDBBYODomainStore(q byoDomainQueries) *DBBYODomainStore {
	if q == nil {
		panic("mgmtapi: nil BYO-domain queries")
	}
	return &DBBYODomainStore{q: q}
}

func (s *DBBYODomainStore) CreateDomain(ctx context.Context, domain *relay.BYODomain) error {
	if domain == nil {
		return errors.New("mgmtapi: CreateDomain: nil domain")
	}
	_, err := s.q.CreateBYODomain(ctx, db.CreateBYODomainParams{
		ID:             pgUUID(domain.ID),
		Domain:         domain.Domain,
		UserID:         pgUUID(domain.UserID),
		ChallengeToken: domain.ChallengeToken,
		State:          string(domain.State),
		Region:         string(domain.Region),
		CreatedAt:      pgtype.Timestamptz{Time: domain.CreatedAt, Valid: true},
		VerifiedAt:     optionalTimestamp(domain.VerifiedAt),
		ExpiresAt:      pgtype.Timestamptz{Time: domain.ExpiresAt, Valid: true},
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "byo_domains_domain_key" {
			return relay.ErrDomainAlreadyExists
		}
		return fmt.Errorf("mgmtapi: create BYO domain: %w", err)
	}
	return nil
}

func (s *DBBYODomainStore) GetDomainByName(ctx context.Context, userID, domain string) (*relay.BYODomain, error) {
	ownerID, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("mgmtapi: get BYO domain: invalid user ID: %w", err)
	}
	row, err := s.q.GetBYODomainByName(ctx, db.GetBYODomainByNameParams{UserID: ownerID, Domain: domain})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, relay.ErrDomainNotFound
		}
		return nil, fmt.Errorf("mgmtapi: get BYO domain: %w", err)
	}
	return byoDomainFromRow(row)
}

func (s *DBBYODomainStore) ListDomainsByUser(ctx context.Context, userID string) ([]*relay.BYODomain, error) {
	ownerID, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("mgmtapi: list BYO domains: invalid user ID: %w", err)
	}
	rows, err := s.q.ListBYODomainsByUser(ctx, ownerID)
	if err != nil {
		return nil, fmt.Errorf("mgmtapi: list BYO domains: %w", err)
	}
	domains := make([]*relay.BYODomain, 0, len(rows))
	for _, row := range rows {
		domain, err := byoDomainFromRow(row)
		if err != nil {
			return nil, fmt.Errorf("mgmtapi: list BYO domains: %w", err)
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

func (s *DBBYODomainStore) UpdateDomainState(ctx context.Context, domainID string, state relay.BYODomainState) error {
	id, err := parseUUID(domainID)
	if err != nil {
		return fmt.Errorf("mgmtapi: update BYO domain: invalid domain ID: %w", err)
	}
	_, err = s.q.UpdateBYODomainState(ctx, db.UpdateBYODomainStateParams{ID: id, State: string(state)})
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.ErrDomainNotFound
	}
	if err != nil {
		return fmt.Errorf("mgmtapi: update BYO domain: %w", err)
	}
	return nil
}

func (s *DBBYODomainStore) DeleteDomain(ctx context.Context, domainID string) error {
	id, err := parseUUID(domainID)
	if err != nil {
		return fmt.Errorf("mgmtapi: delete BYO domain: invalid domain ID: %w", err)
	}
	_, err = s.q.DeleteBYODomain(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return relay.ErrDomainNotFound
	}
	if err != nil {
		return fmt.Errorf("mgmtapi: delete BYO domain: %w", err)
	}
	return nil
}

func byoDomainFromRow(row db.ByoDomain) (*relay.BYODomain, error) {
	if !row.ID.Valid || !row.UserID.Valid || !row.CreatedAt.Valid || !row.ExpiresAt.Valid {
		return nil, errors.New("invalid persisted BYO-domain identifiers or timestamps")
	}
	state, err := relay.ParseBYODomainState(row.State)
	if err != nil {
		return nil, fmt.Errorf("invalid persisted BYO-domain state: %w", err)
	}
	reg, err := region.Parse(row.Region)
	if err != nil {
		return nil, fmt.Errorf("invalid persisted BYO-domain region: %w", err)
	}
	var verifiedAt *time.Time
	if row.VerifiedAt.Valid {
		value := row.VerifiedAt.Time
		verifiedAt = &value
	}
	return &relay.BYODomain{
		ID: uuid.UUID(row.ID.Bytes), Domain: row.Domain, UserID: uuid.UUID(row.UserID.Bytes),
		ChallengeToken: row.ChallengeToken, State: state, Region: reg,
		CreatedAt: row.CreatedAt.Time, VerifiedAt: verifiedAt, ExpiresAt: row.ExpiresAt.Time,
	}, nil
}

func parseUUID(value string) (pgtype.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgUUID(id), nil
}

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func optionalTimestamp(value *time.Time) pgtype.Timestamptz {
	if value == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *value, Valid: true}
}
