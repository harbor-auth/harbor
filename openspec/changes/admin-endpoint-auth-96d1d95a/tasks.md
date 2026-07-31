# Tasks: admin-endpoint-auth-96d1d95a

Derived from `docs/plans/admin-endpoint-auth.md` (expanded 2026-07-30 audit scope).
Audit finding C2 in `docs/plans/audit-2026-07-30-wiring-and-auth.md`.

## Implementation Tasks

- [ ] **T1** Add `EndpointAdminRotate` and `EndpointAdminRevoke` to `internal/telemetry/labels.go`
- [ ] **T2** Create `internal/oidcapi/admin_auth.go` with `AdminAuthConfig` and `AdminAuthMiddleware`
- [ ] **T3** Create `internal/oidcapi/admin_auth_test.go` with comprehensive tests
- [ ] **T4** Add `WithAdminAuth` dispatcher to `internal/oidcapi/server.go`
- [ ] **T5** Wire boot guard + `WithAdminAuth` + admin rate limits in `cmd/harbor-hot/main.go`
- [ ] **T6** Add `security: [{bearerAuth: []}]` to both admin operations in `api/openapi/harbor.yaml`
- [ ] **T7** Block `/admin/` at ingress in `deploy/k8s/ingress.yaml`
- [ ] **T8** Add `ADMIN_API_TOKEN` to `deploy/k8s/secret-hot.yaml`, `deploy/helm/templates/secret-hot.yaml`, and `deploy/helm/values.yaml`
- [ ] **T9** Clean up stale comments in `admin_keys.go` and `revoke_jwt.go`
- [ ] **T10** Mark blocker 1.5 resolved in `docs/plans/production-readiness.md`

## Validation

- `go build ./...` green
- `go vet ./...` green
- `go test ./internal/oidcapi/... ./cmd/harbor-hot/...` green
- `make generate-check` green
- `openspec validate admin-endpoint-auth-96d1d95a --strict`
