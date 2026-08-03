// Package cloudapi implements the authenticated internal management API
// Harbor Cloud (the closed-source SaaS control plane) uses to mint
// provisioning sessions, manage namespace lifecycle, and trigger signing-key
// rotation against a self-hosted Harbor core cluster
// (openspec/changes/harbor-cloud-management-api-contract-2ee993ea). It is
// wired only into cmd/harbor-mgmt, behind the private
// mgmt.cloudIntegration gate — harbor-hot's public listener never imports
// this package.
//
// This file holds the persistence layer: the namespace provisioning record,
// the idempotency ledger shared by namespace create/delete and session
// minting, and namespace-scoped session records. It follows the same
// domain⇄sqlc split as internal/clients — production callers pass a
// *db.Queries; tests supply a small fake.
package cloudapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
)

// ErrNamespaceNotFound is returned when a namespace lookup finds no row with
// the given id.
var ErrNamespaceNotFound = errors.New("cloudapi: namespace not found")

// ErrNamespaceAlreadyExists is returned when creating a namespace whose id
// already exists (cloud_namespaces.id is the primary key).
var ErrNamespaceAlreadyExists = errors.New("cloudapi: namespace already exists")

// ErrOperationNotFound is returned when an idempotency-ledger lookup finds no
// row for the given (idempotency key, operation) pair.
var ErrOperationNotFound = errors.New("cloudapi: operation not found")

// ErrOperationAlreadyExists is returned when two concurrent requests race to
// record the same (idempotency key, operation) pair.
var ErrOperationAlreadyExists = errors.New("cloudapi: operation already recorded")

// ErrSessionNotFound is returned when a session lookup finds no row with the
// given session id.
var ErrSessionNotFound = errors.New("cloudapi: session not found")

// Namespace is the provisioning-lifecycle record for a Harbor Cloud
// self-hosted namespace. It is a provisioning record only, not a
// routing/PII boundary — harbor-core stays single-tenant per region.
// Delete is soft: DeletedAt is set rather than the row being removed, so
// the idempotent-delete contract (204 on an absent OR already-deleted
// namespace) never depends on whether the row still exists.
type Namespace struct {
	ID        string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// Operation is one row of the idempotency ledger shared by namespace
// create/delete and session minting. RequestHash lets a replayed key with a
// different body be rejected; ResponseBody lets a replayed key with the same
// body replay the original response verbatim.
type Operation struct {
	IdempotencyKey string
	Name           string
	RequestHash    []byte
	ResponseBody   []byte
	CreatedAt      time.Time
}

// Session is a short-lived, namespace-scoped credential Harbor Cloud mints
// to perform bounded provisioning operations against one namespace. It has
// no relationship to end-user OIDC/BFF sessions. Only TokenHash is ever
// persisted; the plaintext bearer is returned once at mint time.
type Session struct {
	SessionID   string
	NamespaceID string
	TokenHash   []byte
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
	CreatedAt   time.Time
}

// querier is the narrow sqlc surface Store needs. Production code passes a
// *db.Queries; tests pass a small fake.
type querier interface {
	CreateCloudNamespace(ctx context.Context, arg db.CreateCloudNamespaceParams) (db.CloudNamespace, error)
	GetCloudNamespace(ctx context.Context, id string) (db.CloudNamespace, error)
	SoftDeleteCloudNamespace(ctx context.Context, id string) error
	CreateCloudOperation(ctx context.Context, arg db.CreateCloudOperationParams) (db.CloudOperation, error)
	GetCloudOperation(ctx context.Context, arg db.GetCloudOperationParams) (db.CloudOperation, error)
	CreateCloudSession(ctx context.Context, arg db.CreateCloudSessionParams) (db.CloudSession, error)
	GetCloudSession(ctx context.Context, sessionID string) (db.CloudSession, error)
}

// Store persists Harbor Cloud management API records — namespaces, the
// idempotency ledger, and namespace-scoped sessions — in PostgreSQL.
type Store struct {
	q querier
}

// NewStore wraps a sqlc Queries (or any querier). Panics if q is nil —
// callers must ensure the store is wired before startup.
func NewStore(q querier) *Store {
	if q == nil {
		panic("cloudapi: nil querier")
	}
	return &Store{q: q}
}

// CreateNamespace persists a new namespace provisioning record in the given
// status. It returns ErrNamespaceAlreadyExists if id is already taken
// (cloud_namespaces.id is the primary key; this covers both a live and a
// soft-deleted row with the same id).
func (s *Store) CreateNamespace(ctx context.Context, id, status string) (Namespace, error) {
	row, err := s.q.CreateCloudNamespace(ctx, db.CreateCloudNamespaceParams{ID: id, Status: status})
	if err != nil {
		if isUniqueViolation(err) {
			return Namespace{}, ErrNamespaceAlreadyExists
		}
		return Namespace{}, fmt.Errorf("cloudapi: create namespace: %w", err)
	}
	return namespaceFromRow(row), nil
}

// GetNamespace returns the namespace row regardless of DeletedAt — the
// caller decides whether a soft-deleted row should be treated as not-found,
// mirroring clients.DBSessionStore's "return populated state, let the
// caller interpret lifecycle" pattern.
func (s *Store) GetNamespace(ctx context.Context, id string) (Namespace, error) {
	row, err := s.q.GetCloudNamespace(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Namespace{}, ErrNamespaceNotFound
		}
		return Namespace{}, fmt.Errorf("cloudapi: get namespace: %w", err)
	}
	return namespaceFromRow(row), nil
}

// SoftDeleteNamespace marks a namespace deleted. It does not error when id
// is absent or already deleted — the underlying UPDATE simply affects zero
// rows — so callers can implement the idempotent-delete contract (204,
// always) without a separate existence check.
func (s *Store) SoftDeleteNamespace(ctx context.Context, id string) error {
	if err := s.q.SoftDeleteCloudNamespace(ctx, id); err != nil {
		return fmt.Errorf("cloudapi: soft delete namespace: %w", err)
	}
	return nil
}

// CreateOperation records the response for a (idempotencyKey, operation)
// pair in the idempotency ledger. It returns ErrOperationAlreadyExists if a
// concurrent request already recorded that pair.
func (s *Store) CreateOperation(ctx context.Context, idempotencyKey, operation string, requestHash, responseBody []byte) (Operation, error) {
	row, err := s.q.CreateCloudOperation(ctx, db.CreateCloudOperationParams{
		IdempotencyKey: idempotencyKey,
		Operation:      operation,
		RequestHash:    requestHash,
		ResponseBody:   responseBody,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Operation{}, ErrOperationAlreadyExists
		}
		return Operation{}, fmt.Errorf("cloudapi: create operation: %w", err)
	}
	return operationFromRow(row), nil
}

// GetOperation looks up a prior operation by its idempotency key and
// operation name, returning ErrOperationNotFound if none was recorded.
func (s *Store) GetOperation(ctx context.Context, idempotencyKey, operation string) (Operation, error) {
	row, err := s.q.GetCloudOperation(ctx, db.GetCloudOperationParams{
		IdempotencyKey: idempotencyKey,
		Operation:      operation,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Operation{}, ErrOperationNotFound
		}
		return Operation{}, fmt.Errorf("cloudapi: get operation: %w", err)
	}
	return operationFromRow(row), nil
}

// CreateSession mints a namespace-scoped session record. Only tokenHash is
// persisted; the caller is responsible for returning the plaintext bearer
// exactly once, at mint time.
func (s *Store) CreateSession(ctx context.Context, sessionID, namespaceID string, tokenHash []byte, expiresAt time.Time) (Session, error) {
	row, err := s.q.CreateCloudSession(ctx, db.CreateCloudSessionParams{
		SessionID:   sessionID,
		NamespaceID: namespaceID,
		TokenHash:   tokenHash,
		ExpiresAt:   pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Session{}, fmt.Errorf("cloudapi: create session: session id %q already exists", sessionID)
		}
		return Session{}, fmt.Errorf("cloudapi: create session: %w", err)
	}
	return sessionFromRow(row), nil
}

// GetSession returns the session row regardless of expiry/consumption — the
// caller decides 410 session_expired / 403 cross_tenant_forbidden from the
// returned fields rather than have the store hide lifecycle state.
func (s *Store) GetSession(ctx context.Context, sessionID string) (Session, error) {
	row, err := s.q.GetCloudSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("cloudapi: get session: %w", err)
	}
	return sessionFromRow(row), nil
}

// isUniqueViolation reports whether err is a Postgres unique/primary-key
// constraint violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func namespaceFromRow(row db.CloudNamespace) Namespace {
	return Namespace{
		ID:        row.ID,
		Status:    row.Status,
		CreatedAt: timestampOrZero(row.CreatedAt),
		UpdatedAt: timestampOrZero(row.UpdatedAt),
		DeletedAt: optionalTimestamp(row.DeletedAt),
	}
}

func operationFromRow(row db.CloudOperation) Operation {
	return Operation{
		IdempotencyKey: row.IdempotencyKey,
		Name:           row.Operation,
		RequestHash:    row.RequestHash,
		ResponseBody:   row.ResponseBody,
		CreatedAt:      timestampOrZero(row.CreatedAt),
	}
}

func sessionFromRow(row db.CloudSession) Session {
	return Session{
		SessionID:   row.SessionID,
		NamespaceID: row.NamespaceID,
		TokenHash:   row.TokenHash,
		ExpiresAt:   timestampOrZero(row.ExpiresAt),
		ConsumedAt:  optionalTimestamp(row.ConsumedAt),
		CreatedAt:   timestampOrZero(row.CreatedAt),
	}
}

// timestampOrZero converts a NOT NULL pgtype.Timestamptz column to time.Time,
// returning the zero value for an invalid (unexpected NULL) reading.
func timestampOrZero(ts pgtype.Timestamptz) time.Time {
	if !ts.Valid {
		return time.Time{}
	}
	return ts.Time
}

// optionalTimestamp converts a nullable pgtype.Timestamptz column to *time.Time,
// returning nil for NULL.
func optionalTimestamp(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	value := ts.Time
	return &value
}
