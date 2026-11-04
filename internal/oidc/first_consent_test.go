package oidc

import (
	"context"
	"testing"
)

func TestFirstConsentCreatesCanonicalGrantBeforeUpdatingView(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	resolver, grants := newTestResolver(t, userID, resolverTestSecret())
	clients := NewInMemoryClientRegistry()
	client := testClient()
	client.SectorID = "rp.example.com"
	clients.Put(client)
	svc := mustNewService(t, ServiceConfig{Issuer: "https://eu.harbor.id", Clients: clients, Codes: newRedisAuthCodeStore(t), Tokens: NewPlaceholderIssuer(), Sessions: resolver, Grants: grants})
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
