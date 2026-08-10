package webauthn

import (
	"testing"

	"github.com/google/uuid"
)

// TestCanonicalUserIDAlwaysParsesAsUUID pins the contract that broke sign-in.
//
// FinishDiscoverableLogin's return value is written into the BFF session as
// user_id and then parsed as a UUID by GrantStore.FindGrant during the consent
// check. It used to return base64.RawURLEncoding of the raw handle, which
// contains no dashes and therefore can never parse — so every discoverable
// passkey login (the default path) died at the consent lookup with
// "could not check consent status", after a fully successful ceremony.
func TestCanonicalUserIDAlwaysParsesAsUUID(t *testing.T) {
	id := uuid.MustParse("bf047095-6561-463e-bbfa-2b35535df2e4")

	for name, handle := range map[string][]byte{
		"16 raw UUID bytes":    id[:],
		"UUID string as bytes": []byte(id.String()),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := canonicalUserID(handle)
			if err != nil {
				t.Fatalf("canonicalUserID(%s): %v", name, err)
			}
			if _, err := uuid.Parse(got); err != nil {
				t.Fatalf("returned %q, which does not parse as a UUID: %v", got, err)
			}
			if got != id.String() {
				t.Fatalf("returned %q, want the canonical %q", got, id.String())
			}
		})
	}
}
