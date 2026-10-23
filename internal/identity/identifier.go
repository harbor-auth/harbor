package identity

import (
	"context"
	"errors"
	"fmt"
)

var ErrIdentifierExists = errors.New("identity: identifier already belongs to an account")

// IdentifierRecord contains only sealed storage material. Identifiers never
// replace the account UUID or authorize authentication by themselves.
type IdentifierRecord struct {
	Kind           string
	LookupHash     []byte
	EncryptedValue []byte
}

type IdentifiedUserPersister interface {
	PersistIdentifiedUser(context.Context, UserRecord, IdentifierRecord) error
}

func IdentifierAAD(userID, kind string) []byte {
	return []byte("harbor-identifier-v1:" + userID + ":" + kind)
}

// EnrollIdentified is used only after the signup service verifies ownership.
// Persistence commits the account and identifier together, or neither.
func (e *Enroller) EnrollIdentified(ctx context.Context, reg, kind, value string, lookup []byte, persist IdentifiedUserPersister) (EnrollResult, error) {
	if kind != "email" || value == "" || len(lookup) != 32 || persist == nil {
		return EnrollResult{}, errors.New("identity: invalid verified identifier")
	}
	rec, err := e.seal(ctx, reg)
	if err != nil {
		return EnrollResult{}, err
	}
	rec.RecoveryRequired = true
	dek, err := e.keys.UnwrapDEK(ctx, rec.Region, rec.DekWrapped)
	if err != nil {
		return EnrollResult{}, err
	}
	sealed, err := e.cipher.Encrypt(dek, []byte(value), IdentifierAAD(rec.ID, kind))
	if err != nil {
		return EnrollResult{}, err
	}
	if err := persist.PersistIdentifiedUser(ctx, rec, IdentifierRecord{kind, lookup, sealed}); err != nil {
		return EnrollResult{}, fmt.Errorf("identity: persist identified user: %w", err)
	}
	return EnrollResult{UserID: rec.ID, Region: rec.Region}, nil
}
