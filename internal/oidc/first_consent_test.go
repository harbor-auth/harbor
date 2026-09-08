package oidc

import (
	"context"
	"errors"
	"testing"
)

// Migration 0018 exposes consent as a view: an update cannot create a grant.
type updateOnlyConsentStore struct {
	*InMemoryConsentStore
	grants *InMemoryGrantStore
}

func (s updateOnlyConsentStore) Upsert(ctx context.Context, userID, clientID string, scopes []string) (ConsentGrant, error) {
	if _, found, err := s.grants.FindGrant(ctx, userID, clientID); err != nil || !found {
		return ConsentGrant{}, errors.New("canonical grant does not exist")
	}
	return s.InMemoryConsentStore.Upsert(ctx, userID, clientID, scopes)
}

func TestFirstConsentCreatesCanonicalGrantBeforeUpdatingView(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	resolver, grants := newTestResolver(t, userID, resolverTestSecret())
	clients := NewInMemoryClientRegistry()
	client := testClient()
	client.SectorID = "rp.example.com"
	clients.Put(client)
	consents := updateOnlyConsentStore{NewInMemoryConsentStore(), grants}
	svc := mustNewService(ServiceConfig{Issuer: "https://eu.harbor.id", Clients: clients, Codes: NewInMemoryAuthCodeStore(), Tokens: NewPlaceholderIssuer(), Sessions: resolver, Grants: grants, Consents: consents})
	ctx := context.Background()
	if err := svc.ApproveConsent(ctx, userID, client.ID, "openid profile"); err != nil {
		t.Fatalf("first consent failed: %v", err)
	}
	grant, found, err := grants.FindGrant(ctx, userID, client.ID)
	if err != nil || !found || grant.PairwiseSub == "" || grant.PairwiseSub == userID {
		t.Fatal("approval did not create a grant with a pairwise subject")
	}
	required, aerr := svc.ConsentRequired(ctx, userID, client.ID, "openid profile", "")
	if aerr != nil || required {
		t.Fatalf("approved scopes still require consent: required=%v error=%v", required, aerr)
	}
}
