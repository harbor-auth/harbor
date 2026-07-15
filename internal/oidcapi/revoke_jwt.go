package oidcapi

import (
	"net/http"
)

// PostAdminRevokeJwt handles POST /admin/revoke-jwt — emergency JWT revocation.
// This adds a JTI to the revocation bloom filter for immediate invalidation
// (DESIGN §3.5, §7.4).
//
// SCAFFOLD: This is a stub implementation. The full implementation will:
// 1. Parse and validate the RevokeJwtRequest body
// 2. Insert the JTI into the revoked_jtis table via DBRevokedJTIStore
// 3. Add the JTI to the in-process bloom filter
// 4. Publish to Redis pub/sub for cross-replica propagation
// 5. Return RevokeJwtResponse with the revocation timestamp
//
// The handler implementation is deferred to task 12 of the bloom-filter-revocation
// feature; this stub satisfies the generated ServerInterface contract.
func (s *Server) PostAdminRevokeJwt(w http.ResponseWriter, r *http.Request) {
	// TODO(bloom-filter-revocation): Implement full handler in task 12
	writeError(w, http.StatusNotImplemented, "not_implemented", "emergency JWT revocation endpoint not yet implemented")
}
