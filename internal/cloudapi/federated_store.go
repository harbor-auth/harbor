// This file implements ResolveOrCreateFederatedUser: the identity-resolution
// step behind POST /admin/v1/user-sessions (usersessions.go). It maps a
// namespace-scoped, HMAC'd corporate-SSO subject to a Harbor user — creating
// that user the first time the subject is seen — via the federated_identities
// table (db/migrations/0021_federated_identities.up.sql).
package cloudapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/harbor-auth/harbor/internal/clients"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
)

// federatedTxQuerier is the narrow set of federated_identities/users queries
// ResolveOrCreateFederatedUser needs, run against a single transaction.
// Satisfied by *db.Queries (production, via db.New(tx)); tests supply an
// in-memory fake that reproduces the same atomicity contract without a real
// Postgres transaction — the same "domain⇄sqlc split, fakes over
// integration tests" pattern this package already uses for querier
// (store.go) and sessionQuerier-style fakes elsewhere in this codebase.
type federatedTxQuerier interface {
	GetFederatedIdentity(ctx context.Context, arg db.GetFederatedIdentityParams) (db.FederatedIdentity, error)
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
	TouchFederatedIdentity(ctx context.Context, arg db.TouchFederatedIdentityParams) error
	CreateFederatedIdentity(ctx context.Context, arg db.CreateFederatedIdentityParams) (db.FederatedIdentity, error)
	CreateFederatedUser(ctx context.Context, arg db.CreateFederatedUserParams) (db.User, error)
}

// federatedTx is a federatedTxQuerier bound to one in-flight transaction.
type federatedTx interface {
	federatedTxQuerier
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// federatedPool begins a federatedTx (the atomic create-or-map path) and
// answers two plain, non-transactional reads (used once each, to re-read the
// winner after losing a create race, and then re-check ITS user's status —
// L7: the loser must apply the exact same active-status gate the primary
// read path does, not silently skip it just because it arrived at the
// winner's row via a different path). *pgxpool.Pool satisfies this via
// pgxFederatedPool (below); tests supply an in-memory fake.
type federatedPool interface {
	Begin(ctx context.Context) (federatedTx, error)
	GetFederatedIdentity(ctx context.Context, arg db.GetFederatedIdentityParams) (db.FederatedIdentity, error)
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
}

// pgxFederatedPool adapts a *pgxpool.Pool to federatedPool for production
// wiring (cmd/harbor-mgmt/main.go).
type pgxFederatedPool struct {
	pool *pgxpool.Pool
}

// NewPgxFederatedPool wraps pool for Store.WithFederatedIdentities.
func NewPgxFederatedPool(pool *pgxpool.Pool) federatedPool {
	return &pgxFederatedPool{pool: pool}
}

func (p *pgxFederatedPool) Begin(ctx context.Context) (federatedTx, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &pgxFederatedTx{q: db.New(tx), tx: tx}, nil
}

func (p *pgxFederatedPool) GetFederatedIdentity(ctx context.Context, arg db.GetFederatedIdentityParams) (db.FederatedIdentity, error) {
	return db.New(p.pool).GetFederatedIdentity(ctx, arg)
}

func (p *pgxFederatedPool) GetUser(ctx context.Context, id pgtype.UUID) (db.User, error) {
	return db.New(p.pool).GetUser(ctx, id)
}

// pgxFederatedTx adapts a real pgx.Tx (via db.New(tx)) to federatedTx.
type pgxFederatedTx struct {
	q  *db.Queries
	tx pgx.Tx
}

func (t *pgxFederatedTx) GetFederatedIdentity(ctx context.Context, arg db.GetFederatedIdentityParams) (db.FederatedIdentity, error) {
	return t.q.GetFederatedIdentity(ctx, arg)
}
func (t *pgxFederatedTx) GetUser(ctx context.Context, id pgtype.UUID) (db.User, error) {
	return t.q.GetUser(ctx, id)
}
func (t *pgxFederatedTx) TouchFederatedIdentity(ctx context.Context, arg db.TouchFederatedIdentityParams) error {
	return t.q.TouchFederatedIdentity(ctx, arg)
}
func (t *pgxFederatedTx) CreateFederatedIdentity(ctx context.Context, arg db.CreateFederatedIdentityParams) (db.FederatedIdentity, error) {
	return t.q.CreateFederatedIdentity(ctx, arg)
}
func (t *pgxFederatedTx) CreateFederatedUser(ctx context.Context, arg db.CreateFederatedUserParams) (db.User, error) {
	return t.q.CreateFederatedUser(ctx, arg)
}
func (t *pgxFederatedTx) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t *pgxFederatedTx) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }

// ErrFederatedIdentitiesUnconfigured is returned when ResolveOrCreateFederatedUser
// is called before WithFederatedIdentities has wired its dependencies.
var ErrFederatedIdentitiesUnconfigured = errors.New("cloudapi: federated identities not configured")

// ErrFederatedSubjectUnavailable is returned when an existing federated
// mapping resolves to a user who is no longer `active` (e.g. erased/
// shredded via compliance export). Maps to 403 subject_unavailable — an
// erased account must never be re-enterable via SSO.
var ErrFederatedSubjectUnavailable = errors.New("cloudapi: federated subject's user is not active")

// ResolveOrCreateFederatedUser maps (namespaceID, subjectHMAC, keyVersion) to
// a Harbor user id, creating a new user the first time this triple is seen.
// userRegion is the region the new user (if any) is enrolled into.
//
// Runs in ONE database transaction: SELECT the existing mapping; on a miss,
// INSERT a fresh user (identity.EnrollFederated) and INSERT the mapping row;
// COMMIT. The transaction is what makes the create-or-map race safe: if two
// requests race to create the first mapping for the same subject, the loser's
// CreateFederatedIdentity INSERT hits the table's primary key and fails with
// 23505 — and because that loser's freshly-created user row was written in
// the SAME transaction, ROLLBACK discards it too. There is never a window
// where an orphaned, credential-less "active" user is left behind by the
// losing side of the race.
//
// This is also the core isolation property of the whole federated-identity
// design: user_id is NEVER written to federated_identities except as an id
// THIS call just created via EnrollFederated. There is no code path here
// that looks up a pre-existing user (by email, by any other attribute) and
// binds a federated subject to it — users has no email column and no lookup
// by anything but id, which is what makes that kind of account-linking
// structurally impossible here, not just policy-forbidden.
func (s *Store) ResolveOrCreateFederatedUser(ctx context.Context, namespaceID string, subjectHMAC []byte, keyVersion int16, userRegion string) (userID string, created bool, err error) {
	if s.fedPool == nil || s.keys == nil || s.cipher == nil {
		return "", false, ErrFederatedIdentitiesUnconfigured
	}

	txn, err := s.fedPool.Begin(ctx)
	if err != nil {
		return "", false, fmt.Errorf("cloudapi: begin federated identity tx: %w", err)
	}
	defer func() { _ = txn.Rollback(context.WithoutCancel(ctx)) }() //nolint:errcheck // Rollback after Commit is a no-op (pgx.ErrTxClosed).

	existing, getErr := txn.GetFederatedIdentity(ctx, db.GetFederatedIdentityParams{
		NamespaceID: namespaceID, SubjectHmac: subjectHMAC, KeyVersion: keyVersion,
	})
	switch {
	case getErr == nil:
		u, uerr := txn.GetUser(ctx, existing.UserID)
		if uerr != nil {
			return "", false, fmt.Errorf("cloudapi: load federated user: %w", uerr)
		}
		if terr := txn.TouchFederatedIdentity(ctx, db.TouchFederatedIdentityParams{
			NamespaceID: namespaceID, SubjectHmac: subjectHMAC, KeyVersion: keyVersion,
		}); terr != nil {
			return "", false, fmt.Errorf("cloudapi: touch federated identity: %w", terr)
		}
		if cerr := txn.Commit(ctx); cerr != nil {
			return "", false, fmt.Errorf("cloudapi: commit federated identity read: %w", cerr)
		}
		// An erased/shredded account (status != active) must never be
		// re-enterable via SSO — checked AFTER commit so the last_seen_at
		// touch above is never lost just because the caller goes on to
		// refuse the login.
		if u.Status != "active" {
			return "", false, ErrFederatedSubjectUnavailable
		}
		return uuidToString(existing.UserID), false, nil
	case errors.Is(getErr, pgx.ErrNoRows):
		// Fall through: no existing mapping, create one below.
	default:
		return "", false, fmt.Errorf("cloudapi: get federated identity: %w", getErr)
	}

	// Seal and persist a brand-new federated user INSIDE this transaction —
	// see the doc comment above for why that atomicity matters. A fresh
	// Enroller is constructed per call (cheap: a plain struct, no I/O) rather
	// than reusing harbor-mgmt's shared Enroller, because its persister must
	// be bound to txn specifically, not the pool.
	txPersister := clients.NewDBFederatedUserPersister(txn)
	enroller := identity.NewEnroller(s.keys, s.cipher, nil).WithFederatedPersister(txPersister)
	result, err := enroller.EnrollFederated(ctx, userRegion)
	if err != nil {
		return "", false, fmt.Errorf("cloudapi: enroll federated user: %w", err)
	}

	var uid pgtype.UUID
	if err := uid.Scan(result.UserID); err != nil {
		return "", false, fmt.Errorf("cloudapi: parse federated user id: %w", err)
	}

	if _, err := txn.CreateFederatedIdentity(ctx, db.CreateFederatedIdentityParams{
		NamespaceID: namespaceID, SubjectHmac: subjectHMAC, KeyVersion: keyVersion, UserID: uid,
	}); err != nil {
		if isUniqueViolation(err) {
			// Lost the race to a concurrent mint for the same
			// (namespace, subject): this txn's deferred Rollback discards
			// the user row EnrollFederated just wrote above along with it
			// — the whole point of doing both writes in one transaction is
			// that the loser never leaves behind an orphaned,
			// credential-less "active" user. Re-read the winner once,
			// outside this now-dead transaction.
			winner, rerr := s.fedPool.GetFederatedIdentity(ctx, db.GetFederatedIdentityParams{
				NamespaceID: namespaceID, SubjectHmac: subjectHMAC, KeyVersion: keyVersion,
			})
			if rerr != nil {
				return "", false, fmt.Errorf("cloudapi: re-read federated identity after conflict: %w", rerr)
			}
			// L7: apply the SAME active-status gate the primary (cache-hit)
			// read path above enforces. Without this, the create-race loser
			// was the one return path that could hand back a user id
			// belonging to an erased/shredded account — subject_unavailable
			// must hold regardless of which side of the race a caller landed
			// on.
			winnerUser, uerr := s.fedPool.GetUser(ctx, winner.UserID)
			if uerr != nil {
				return "", false, fmt.Errorf("cloudapi: load federated user after conflict: %w", uerr)
			}
			if winnerUser.Status != "active" {
				return "", false, ErrFederatedSubjectUnavailable
			}
			return uuidToString(winner.UserID), false, nil
		}
		return "", false, fmt.Errorf("cloudapi: create federated identity: %w", err)
	}

	if err := txn.Commit(ctx); err != nil {
		return "", false, fmt.Errorf("cloudapi: commit federated identity create: %w", err)
	}
	return result.UserID, true, nil
}

// uuidToString renders a pgtype.UUID in the canonical hyphenated text form —
// required because bff.BFFSessionRecord.UserID must be that canonical form
// (clients.ListGrantsByUser parses it), mirroring cmd/harbor-mgmt/caller.go's
// uuid.UUID(handle).String() conversion.
func uuidToString(id pgtype.UUID) string {
	return uuid.UUID(id.Bytes).String()
}
