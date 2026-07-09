// Package oidcapi is the HTTP layer for Harbor's OIDC endpoints — discovery,
// /authorize, /token, and /healthz (docs/DESIGN.md §11.2). Its handlers are the
// spec-generated OpenAPI surface (api/openapi/harbor.yaml → internal/gen/openapi)
// and delegate the actual flow logic to the pure internal/oidc package; this
// layer only marshals HTTP ⇄ domain and never re-implements the security rules.
//
// The composed authorize→token→JWKS flow (including the §11.7 negatives) is
// exercised end-to-end by the agent-runnable e2e harness in e2e/ (Foundation F8).
package oidcapi
