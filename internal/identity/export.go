package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/jackc/pgx/v5/pgtype"
)

// ExportUserLoader loads the user row needed to unwrap the DEK and populate
// the profile section of the export bundle.
// Satisfied by *db.Queries.
type ExportUserLoader interface {
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
}

// ExportConsentLoader loads active consent grants for a user.
// Satisfied by *db.Queries.
type ExportConsentLoader interface {
	ListConsentGrantsByUser(ctx context.Context, userID pgtype.UUID) ([]db.ConsentGrant, error)
}

// ExportAuditLoader loads audit events (including encrypted payloads) for a user.
// Satisfied by *db.Queries.
type ExportAuditLoader interface {
	ListAuditEventsByUserWithPayload(ctx context.Context, arg db.ListAuditEventsByUserWithPayloadParams) ([]db.AuditEvent, error)
}

// ExportRelayLoader loads relay address mappings for a user.
// Satisfied by *db.Queries.
type ExportRelayLoader interface {
	ListRelayAddressesByUser(ctx context.Context, userID pgtype.UUID) ([]db.RelayAddress, error)
}

// exportAuditPageSize is the number of audit events fetched per page during
// bundle assembly. Pagination ensures the export is complete regardless of
// how many events exist.
const exportAuditPageSize = int32(500)

// Bundle is the portable DSAR export for a single authenticated user.
// Every field is decrypted under the caller's own DEK; no operator plaintext
// path exists and no cross-user read can occur. The bundle is assembled in
// memory and never persisted — it is PII and must be treated accordingly.
type Bundle struct {
	UserID        string              `json:"user_id"`
	Region        string              `json:"region"`
	Status        string              `json:"status"`
	CreatedAt     time.Time           `json:"created_at"`
	ConsentGrants []ConsentGrantEntry `json:"consent_grants"`
	AuditEvents   []AuditEventEntry   `json:"audit_events"`
	RelayMappings []RelayMappingEntry `json:"relay_mappings"`
}

// ConsentGrantEntry is a portable representation of a single active consent
// grant in the export bundle.
type ConsentGrantEntry struct {
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
}

// AuditEventEntry is a portable representation of a single audit event with
// its decrypted detail payload. Detail is omitted when the stored payload was
// empty (e.g. pre-encryption legacy rows).
type AuditEventEntry struct {
	EventType  string          `json:"event_type"`
	OccurredAt time.Time       `json:"occurred_at"`
	ClientID   *string         `json:"client_id,omitempty"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

// RelayMappingEntry is a portable representation of a relay address with its
// decrypted real email address.
type RelayMappingEntry struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	State     string    `json:"state"`
	Region    string    `json:"region"`
	RealEmail string    `json:"real_email"`
	CreatedAt time.Time `json:"created_at"`
}

// ExportBundler assembles a caller-scoped DSAR export bundle synchronously.
// All decryption happens under the caller's own DEK; the operator never sees
// plaintext data.
type ExportBundler struct {
	users   ExportUserLoader
	consent ExportConsentLoader
	audit   ExportAuditLoader
	relay   ExportRelayLoader
	keys    crypto.KeyProvider
	cipher  crypto.Decryptor
}

// NewExportBundler constructs an ExportBundler. All arguments must be non-nil.
func NewExportBundler(
	users ExportUserLoader,
	consent ExportConsentLoader,
	audit ExportAuditLoader,
	relay ExportRelayLoader,
	keys crypto.KeyProvider,
	cipher crypto.Decryptor,
) *ExportBundler {
	return &ExportBundler{
		users:   users,
		consent: consent,
		audit:   audit,
		relay:   relay,
		keys:    keys,
		cipher:  cipher,
	}
}

// Assemble decrypts and assembles all data owned by userID into a portable
// Bundle. It is fail-closed: any error (user not found, DEK unwrap failure,
// individual payload decrypt failure) returns a non-nil error and a nil bundle.
//
// Invariants enforced:
//   - Decryption occurs only under the caller's own DEK (userID-scoped load).
//   - No cross-user reads are possible through the narrow loader interfaces.
//   - The bundle is never stored; it is returned to the caller for immediate delivery.
func (b *ExportBundler) Assemble(ctx context.Context, userID string) (*Bundle, error) {
	userUUID, err := parseAuditUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("identity: export: parse user ID: %w", err)
	}

	user, err := b.users.GetUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("identity: export: load user: %w", err)
	}

	dek, err := b.keys.UnwrapDEK(ctx, user.Region, user.DekWrapped)
	if err != nil {
		return nil, fmt.Errorf("identity: export: unwrap DEK: %w", err)
	}

	grants, err := b.assembleConsent(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	auditEvents, err := b.assembleAudit(ctx, userUUID, userID, dek)
	if err != nil {
		return nil, err
	}

	relayMappings, err := b.assembleRelay(ctx, userUUID, dek)
	if err != nil {
		return nil, err
	}

	bundle := &Bundle{
		UserID:        userID,
		Region:        user.Region,
		Status:        user.Status,
		ConsentGrants: grants,
		AuditEvents:   auditEvents,
		RelayMappings: relayMappings,
	}
	if user.CreatedAt.Valid {
		bundle.CreatedAt = user.CreatedAt.Time
	}
	return bundle, nil
}

// assembleConsent loads and converts active consent grants. Consent rows carry
// no envelope-encrypted PII so no decryption is needed here.
func (b *ExportBundler) assembleConsent(ctx context.Context, userUUID pgtype.UUID) ([]ConsentGrantEntry, error) {
	rows, err := b.consent.ListConsentGrantsByUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("identity: export: list consent grants: %w", err)
	}
	out := make([]ConsentGrantEntry, 0, len(rows))
	for _, row := range rows {
		entry := ConsentGrantEntry{
			ClientID: row.ClientID,
			Scopes:   row.Scopes,
		}
		if row.GrantedAt.Valid {
			entry.GrantedAt = row.GrantedAt.Time
		}
		out = append(out, entry)
	}
	return out, nil
}

// assembleAudit paginates through all audit events, decrypting each payload
// under the caller's DEK. A complete export is mandatory for DSAR compliance,
// so pagination continues until the store returns a short page.
func (b *ExportBundler) assembleAudit(ctx context.Context, userUUID pgtype.UUID, userID string, dek crypto.DEK) ([]AuditEventEntry, error) {
	aad := auditPayloadAAD(userID)
	var out []AuditEventEntry
	for offset := int32(0); ; offset += exportAuditPageSize {
		rows, err := b.audit.ListAuditEventsByUserWithPayload(ctx, db.ListAuditEventsByUserWithPayloadParams{
			UserID: userUUID,
			Limit:  exportAuditPageSize,
			Offset: offset,
		})
		if err != nil {
			return nil, fmt.Errorf("identity: export: list audit events: %w", err)
		}
		for _, row := range rows {
			entry := AuditEventEntry{
				EventType: row.EventType,
				ClientID:  row.ClientID,
			}
			if row.OccurredAt.Valid {
				entry.OccurredAt = row.OccurredAt.Time
			}
			if len(row.PayloadEncrypted) > 0 {
				plain, err := b.cipher.Decrypt(dek, row.PayloadEncrypted, aad)
				if err != nil {
					return nil, fmt.Errorf("identity: export: decrypt audit event payload: %w", err)
				}
				if len(plain) > 0 {
					entry.Detail = json.RawMessage(plain)
				}
			}
			out = append(out, entry)
		}
		if int32(len(rows)) < exportAuditPageSize {
			break
		}
	}
	return out, nil
}

// assembleRelay loads relay address rows and decrypts each enc_mapping under
// the caller's DEK. The relay AAD formula ("relay-mapping-v1:"+region) matches
// the formula used in internal/relay/store.go to ensure cross-package consistency.
func (b *ExportBundler) assembleRelay(ctx context.Context, userUUID pgtype.UUID, dek crypto.DEK) ([]RelayMappingEntry, error) {
	rows, err := b.relay.ListRelayAddressesByUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("identity: export: list relay addresses: %w", err)
	}
	out := make([]RelayMappingEntry, 0, len(rows))
	for _, row := range rows {
		aad := []byte("relay-mapping-v1:" + row.Region)
		realEmail, err := b.cipher.Decrypt(dek, row.EncMapping, aad)
		if err != nil {
			return nil, fmt.Errorf("identity: export: decrypt relay mapping: %w", err)
		}
		entry := RelayMappingEntry{
			Token:     row.RelayToken,
			ClientID:  row.ClientID,
			State:     row.State,
			Region:    row.Region,
			RealEmail: string(realEmail),
		}
		if row.CreatedAt.Valid {
			entry.CreatedAt = row.CreatedAt.Time
		}
		out = append(out, entry)
	}
	return out, nil
}
