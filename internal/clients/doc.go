// Package clients provides DB-backed implementations of the oidc.ClientRegistry
// and oidc.GrantStore interfaces (docs/DESIGN.md §10). It is the bridge between
// the pure-Go oidc core (internal/oidc) and the sqlc-generated DB layer
// (internal/gen/db), keeping those two packages free of each other's types.
//
// Production callers pass a *db.Queries (which satisfies both rpQuerier and
// grantQuerier); unit tests supply a small in-process fake.
package clients
