package oidc

import (
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
)

// BuildJWKS constructs the JWKS document from the provided signers. In v1
// exactly one signer is wired; the slice form supports key rotation
// (docs/DESIGN.md §7.3): publish a new kid alongside the old one while tokens
// signed by the old key drain. It returns the spec-generated openapi.JWKSet so
// the served document cannot drift from the OpenAPI contract.
func BuildJWKS(signers []crypto.Signer) openapi.JWKSet {
	keys := make([]openapi.JWK, 0, len(signers))
	for _, s := range signers {
		j := s.PublicJWK()
		keys = append(keys, openapi.JWK{
			Kty: j.Kty,
			Crv: j.Crv,
			Kid: j.Kid,
			X:   j.X,
			Y:   j.Y,
			Use: j.Use,
			Alg: j.Alg,
		})
	}
	return openapi.JWKSet{Keys: keys}
}
