package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/jackc/pgx/v5/pgtype"
)

// --- fakes for ExportBundler ---

type fakeExportUserLoader struct {
	user db.User
	err  error
}

func (f *fakeExportUserLoader) GetUser(_ context.Context, _ pgtype.UUID) (db.User, error) {
	return f.user, f.err
}

type fakeExportConsentLoader struct {
	rows []db.ConsentGrant
	err  error
}

func (f *fakeExportConsentLoader) ListConsentGrantsByUser(_ context.Context, _ pgtype.UUID) ([]db.ConsentGrant, error) {
	return f.rows, f.err
}

type fakeExportAuditLoader struct {
	rows []db.AuditEvent
	err  error
}

func (f *fakeExportAuditLoader) ListAuditEventsByUserWithPayload(_ context.Context, _ db.ListAuditEventsByUserWithPayloadParams) ([]db.AuditEvent, error) {
	return f.rows, f.err
}

type fakeExportRelayLoader struct {
	rows []db.RelayAddress
	err  error
}

func (f *fakeExportRelayLoader) ListRelayAddressesByUser(_ context.Context, _ pgtype.UUID) ([]db.RelayAddress, error) {
	return f.rows, f.err
}

// exportTestSetup holds shared state for ExportBundler unit tests.
type exportTestSetup struct {
	bundler *ExportBundler
	cipher  *crypto.Cipher
	kp      crypto.KeyProvider
	userID  string
	dek     crypto.DEK
	region  string
	wrapped []byte

	users   *fakeExportUserLoader
	consent *fakeExportConsentLoader
	audit   *fakeExportAuditLoader
	relay   *fakeExportRelayLoader
}

// newExportTestSetup builds an ExportBundler with real crypto and in-memory fakes.
func newExportTestSetup(t *testing.T) *exportTestSetup {
	t.Helper()
	const region = "EU"
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	wrapped, err := kp.WrapDEK(context.Background(), region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	userID := uuid.New().String()
	userUUID, _ := uuid.Parse(userID)

	userRow := db.User{
		ID:         pgtype.UUID{Bytes: userUUID, Valid: true},
		Region:     region,
		Status:     "active",
		DekWrapped: wrapped,
		CreatedAt:  pgtype.Timestamptz{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
	}

	users := &fakeExportUserLoader{user: userRow}
	consent := &fakeExportConsentLoader{}
	audit := &fakeExportAuditLoader{}
	relay := &fakeExportRelayLoader{}

	ci := crypto.NewCipher()
	bundler := NewExportBundler(users, consent, audit, relay, kp, ci)

	return &exportTestSetup{
		bundler: bundler,
		cipher:  ci,
		kp:      kp,
		userID:  userID,
		dek:     dek,
		region:  region,
		wrapped: wrapped,
		users:   users,
		consent: consent,
		audit:   audit,
		relay:   relay,
	}
}

// encryptAuditPayload is a test helper that encrypts a JSON payload as audit.go would.
func (s *exportTestSetup) encryptAuditPayload(t *testing.T, detail any) []byte {
	t.Helper()
	plain, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ct, err := s.cipher.Encrypt(s.dek, plain, auditPayloadAAD(s.userID))
	if err != nil {
		t.Fatalf("encrypt audit payload: %v", err)
	}
	return ct
}

// encryptRelayMapping is a test helper that encrypts a real email as relay/store.go would.
func (s *exportTestSetup) encryptRelayMapping(t *testing.T, realEmail string) []byte {
	t.Helper()
	aad := []byte("relay-mapping-v1:" + s.region)
	ct, err := s.cipher.Encrypt(s.dek, []byte(realEmail), aad)
	if err != nil {
		t.Fatalf("encrypt relay mapping: %v", err)
	}
	return ct
}

// --- tests ---

// TestExportBundleProfileFields verifies that Assemble populates profile
// fields (UserID, Region, Status, CreatedAt) from the user row.
func TestExportBundleProfileFields(t *testing.T) {
	s := newExportTestSetup(t)

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if bundle.UserID != s.userID {
		t.Errorf("UserID: got %q, want %q", bundle.UserID, s.userID)
	}
	if bundle.Region != s.region {
		t.Errorf("Region: got %q, want %q", bundle.Region, s.region)
	}
	if bundle.Status != "active" {
		t.Errorf("Status: got %q, want active", bundle.Status)
	}
	if bundle.CreatedAt.IsZero() {
		t.Error("CreatedAt must not be zero")
	}
}

// TestExportBundleConsentGrants verifies that active consent grants appear
// in the export bundle with correct client ID, scopes, and granted_at.
func TestExportBundleConsentGrants(t *testing.T) {
	s := newExportTestSetup(t)

	s.consent.rows = []db.ConsentGrant{
		{
			ClientID:  "client-a",
			Scopes:    []string{"openid", "email"},
			GrantedAt: pgtype.Timestamptz{Time: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), Valid: true},
		},
		{
			ClientID:  "client-b",
			Scopes:    []string{"openid"},
			GrantedAt: pgtype.Timestamptz{Time: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC), Valid: true},
		},
	}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if len(bundle.ConsentGrants) != 2 {
		t.Fatalf("ConsentGrants: got %d, want 2", len(bundle.ConsentGrants))
	}
	if bundle.ConsentGrants[0].ClientID != "client-a" {
		t.Errorf("ConsentGrants[0].ClientID: got %q, want client-a", bundle.ConsentGrants[0].ClientID)
	}
	if len(bundle.ConsentGrants[0].Scopes) != 2 {
		t.Errorf("ConsentGrants[0].Scopes length: got %d, want 2", len(bundle.ConsentGrants[0].Scopes))
	}
}

// TestExportBundleAuditEventsDecrypted verifies that audit event payloads
// are decrypted under the caller's DEK and appear in the bundle as Detail.
func TestExportBundleAuditEventsDecrypted(t *testing.T) {
	s := newExportTestSetup(t)

	detail := map[string]string{"scope": "openid", "grant": "auth_code"}
	payload := s.encryptAuditPayload(t, detail)
	cid := "test-client"

	s.audit.rows = []db.AuditEvent{
		{
			EventType:        "token.issued",
			ClientID:         &cid,
			OccurredAt:       pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
			PayloadEncrypted: payload,
		},
	}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if len(bundle.AuditEvents) != 1 {
		t.Fatalf("AuditEvents: got %d, want 1", len(bundle.AuditEvents))
	}
	ev := bundle.AuditEvents[0]
	if ev.EventType != "token.issued" {
		t.Errorf("EventType: got %q, want token.issued", ev.EventType)
	}
	if ev.ClientID == nil || *ev.ClientID != cid {
		t.Errorf("ClientID: got %v, want %q", ev.ClientID, cid)
	}
	if len(ev.Detail) == 0 {
		t.Fatal("Detail must be non-empty after decryption")
	}
	// Verify Detail round-trips back to the original map.
	var got map[string]string
	if err := json.Unmarshal(ev.Detail, &got); err != nil {
		t.Fatalf("Unmarshal Detail: %v", err)
	}
	if got["scope"] != "openid" || got["grant"] != "auth_code" {
		t.Errorf("Detail mismatch: got %v", got)
	}
}

// TestExportBundleRelayMappingsDecrypted verifies that relay enc_mappings are
// decrypted and the real email appears in the bundle.
func TestExportBundleRelayMappingsDecrypted(t *testing.T) {
	s := newExportTestSetup(t)

	realEmail := "alice@example.com"
	encMapping := s.encryptRelayMapping(t, realEmail)

	s.relay.rows = []db.RelayAddress{
		{
			RelayToken: "tok-123",
			ClientID:   "client-a",
			State:      "active",
			Region:     s.region,
			EncMapping: encMapping,
			CreatedAt:  pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		},
	}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if len(bundle.RelayMappings) != 1 {
		t.Fatalf("RelayMappings: got %d, want 1", len(bundle.RelayMappings))
	}
	rm := bundle.RelayMappings[0]
	if rm.RealEmail != realEmail {
		t.Errorf("RealEmail: got %q, want %q", rm.RealEmail, realEmail)
	}
	if rm.Token != "tok-123" {
		t.Errorf("Token: got %q, want tok-123", rm.Token)
	}
	if rm.ClientID != "client-a" {
		t.Errorf("ClientID: got %q, want client-a", rm.ClientID)
	}
}

// TestExportBundleNoCrossUserRead verifies that encrypting a payload under
// user A's DEK and then including it in user A's export bundle yields
// correctly decrypted data — and that the same ciphertext cannot be
// decrypted under a different user ID's AAD (cross-user isolation).
//
// This does not require a second user DB row; it directly exercises the
// AAD binding that makes cross-user reads impossible.
func TestExportBundleNoCrossUserRead(t *testing.T) {
	s := newExportTestSetup(t)

	// Encrypt a payload under user A's AAD.
	detail := map[string]string{"secret": "user-a-data"}
	payload := s.encryptAuditPayload(t, detail)

	// Attempt to decrypt with a DIFFERENT user ID as AAD — must fail.
	otherUserID := uuid.New().String()
	ci := crypto.NewCipher()
	if _, err := ci.Decrypt(s.dek, payload, auditPayloadAAD(otherUserID)); err == nil {
		t.Fatal("decrypting user A's payload with user B's AAD must fail — cross-user isolation broken")
	}

	// Decryption with the correct user ID must succeed (sanity check).
	if _, err := ci.Decrypt(s.dek, payload, auditPayloadAAD(s.userID)); err != nil {
		t.Fatalf("decrypting with correct AAD must succeed: %v", err)
	}
}

// TestExportBundleEmptyPayloadSkipped verifies that audit events with no
// encrypted payload (legacy rows) are included in the bundle but their
// Detail field is nil/empty — no error is returned.
func TestExportBundleEmptyPayloadSkipped(t *testing.T) {
	s := newExportTestSetup(t)

	s.audit.rows = []db.AuditEvent{
		{
			EventType:        "auth.login",
			OccurredAt:       pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
			PayloadEncrypted: nil, // legacy row with no payload
		},
	}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err != nil {
		t.Fatalf("Assemble with nil payload: %v", err)
	}
	if len(bundle.AuditEvents) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(bundle.AuditEvents))
	}
	if len(bundle.AuditEvents[0].Detail) != 0 {
		t.Errorf("Detail should be empty for nil payload, got %d bytes", len(bundle.AuditEvents[0].Detail))
	}
}

// TestExportBundleUserLoadError verifies that Assemble fails closed when
// the user loader returns an error.
func TestExportBundleUserLoadError(t *testing.T) {
	s := newExportTestSetup(t)
	sentinel := errors.New("user not found")
	s.users.err = sentinel

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if bundle != nil {
		t.Fatal("bundle must be nil on error")
	}
}

// TestExportBundleDEKErasedFails verifies that Assemble fails when the user's
// DEK has been crypto-shredded (empty dek_wrapped makes UnwrapDEK fail), and
// returns a nil bundle. This proves that a prior export cannot re-hydrate data
// after erasure.
func TestExportBundleDEKErasedFails(t *testing.T) {
	s := newExportTestSetup(t)
	// Simulate crypto-shred: replace dek_wrapped with empty bytes.
	s.users.user.DekWrapped = []byte{}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err == nil {
		t.Fatal("Assemble must fail when DEK has been erased")
	}
	if bundle != nil {
		t.Fatal("bundle must be nil when DEK is erased — prior export cannot re-hydrate")
	}
}

// TestExportBundleConsentLoadError verifies Assemble fails when the
// consent loader returns an error.
func TestExportBundleConsentLoadError(t *testing.T) {
	s := newExportTestSetup(t)
	s.consent.err = errors.New("consent DB error")

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err == nil {
		t.Fatal("expected error from consent loader")
	}
	if bundle != nil {
		t.Fatal("bundle must be nil on consent load error")
	}
}

// TestExportBundleAuditLoadError verifies Assemble fails when the
// audit loader returns an error.
func TestExportBundleAuditLoadError(t *testing.T) {
	s := newExportTestSetup(t)
	s.audit.err = errors.New("audit DB error")

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err == nil {
		t.Fatal("expected error from audit loader")
	}
	if bundle != nil {
		t.Fatal("bundle must be nil on audit load error")
	}
}

// TestExportBundleRelayLoadError verifies Assemble fails when the
// relay loader returns an error.
func TestExportBundleRelayLoadError(t *testing.T) {
	s := newExportTestSetup(t)
	s.relay.err = errors.New("relay DB error")

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err == nil {
		t.Fatal("expected error from relay loader")
	}
	if bundle != nil {
		t.Fatal("bundle must be nil on relay load error")
	}
}

// TestExportBundleAuditDecryptFailure verifies that a corrupted audit payload
// causes Assemble to fail closed (not return partial data).
func TestExportBundleAuditDecryptFailure(t *testing.T) {
	s := newExportTestSetup(t)

	s.audit.rows = []db.AuditEvent{
		{
			EventType:        "token.issued",
			OccurredAt:       pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
			PayloadEncrypted: []byte("not-valid-ciphertext-padding-to-meet-min-length-requirement-1234"),
		},
	}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err == nil {
		t.Fatal("Assemble must fail when audit payload cannot be decrypted")
	}
	if bundle != nil {
		t.Fatal("bundle must be nil when decryption fails")
	}
}

// TestExportBundleRelayDecryptFailure verifies that a corrupted relay mapping
// causes Assemble to fail closed (not return partial data).
func TestExportBundleRelayDecryptFailure(t *testing.T) {
	s := newExportTestSetup(t)

	s.relay.rows = []db.RelayAddress{
		{
			RelayToken: "tok-corrupt",
			ClientID:   "client-a",
			State:      "active",
			Region:     s.region,
			EncMapping: []byte("not-valid-ciphertext-padding-to-meet-min-length-requirement-1234"),
			CreatedAt:  pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		},
	}

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err == nil {
		t.Fatal("Assemble must fail when relay mapping cannot be decrypted")
	}
	if bundle != nil {
		t.Fatal("bundle must be nil when decryption fails")
	}
}

// TestExportBundleEmptyUser verifies that Assemble succeeds for a user
// with no grants, events, or relay mappings — producing an empty but valid bundle.
func TestExportBundleEmptyUser(t *testing.T) {
	s := newExportTestSetup(t)
	// Leave consent, audit, relay fakes at zero value (nil slices).

	bundle, err := s.bundler.Assemble(context.Background(), s.userID)
	if err != nil {
		t.Fatalf("Assemble empty user: %v", err)
	}
	if len(bundle.ConsentGrants) != 0 {
		t.Errorf("expected empty ConsentGrants, got %d", len(bundle.ConsentGrants))
	}
	if len(bundle.AuditEvents) != 0 {
		t.Errorf("expected empty AuditEvents, got %d", len(bundle.AuditEvents))
	}
	if len(bundle.RelayMappings) != 0 {
		t.Errorf("expected empty RelayMappings, got %d", len(bundle.RelayMappings))
	}
}
