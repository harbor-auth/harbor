# Test Coverage Report

Generated: 2026-07-11

## Summary

All non-generated internal packages exceed the **80% coverage target**.

## Coverage by Package

| Package | Coverage | Target | Status |
|---------|----------|--------|--------|
| `internal/arch` | [no statements] | N/A | ✅ Test-only package |
| `internal/clients` | 95.9% | 80% | ✅ |
| `internal/crypto` | 85.6% | 80% | ✅ |
| `internal/httpserver` | 95.7% | 80% | ✅ |
| `internal/identity` | 95.9% | 80% | ✅ |
| `internal/oidc` | 87.8% | 80% | ✅ |
| `internal/oidcapi` | 85.4% | 80% | ✅ |
| `internal/region` | 100.0% | 80% | ✅ |
| `internal/telemetry` | 87.5% | 80% | ✅ |
| `internal/webauthn` | 85.9% | 80% | ✅ |

## Excluded Packages (Generated Code)

The following packages are auto-generated and excluded from coverage targets:

| Package | Coverage | Justification |
|---------|----------|---------------|
| `internal/gen/db` | 0.0% | sqlc-generated database queries |
| `internal/gen/openapi` | 0.0% | oapi-codegen generated OpenAPI types |
| `internal/gen/proto/harbor/v1` | 0.0% | protoc-generated gRPC stubs |

These packages contain no hand-written code and are regenerated from schema definitions. Testing the generators themselves is out of scope; the generated code is exercised transitively through tests of packages that consume it.

## Notes

- **`internal/arch`**: Contains only architecture tests (`arch_test.go`) with no production statements to cover.
- Coverage was improved through targeted error path and edge case tests added in this feature branch.
