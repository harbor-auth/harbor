# Spec: Increase test coverage

## Overview

This change adds targeted error path and edge case tests across all internal
packages to achieve 80%+ test coverage.

## Requirements

### REQ-1: Coverage target
All non-generated internal packages must reach 80% or higher test coverage.

### REQ-2: Error path coverage
Error paths (DB failures, crypto failures, validation errors) must be explicitly
tested, not just happy paths.

### REQ-3: Fail-closed verification
Tests must verify that error conditions:
1. Return appropriate error values.
2. Do not produce partial state (no DB writes on failure).

### REQ-4: Generated code exclusion
Generated packages (`internal/gen/*`) are excluded from coverage targets with
documented justification.

## Acceptance Criteria

- [x] `internal/clients`: 95.9% (target: 80%)
- [x] `internal/crypto`: 85.6% (target: 80%)
- [x] `internal/httpserver`: 95.7% (target: 80%)
- [x] `internal/identity`: 95.9% (target: 80%)
- [x] `internal/oidc`: 87.8% (target: 80%)
- [x] `internal/oidcapi`: 85.4% (target: 80%)
- [x] `internal/region`: 100.0% (target: 80%)
- [x] `internal/telemetry`: 87.5% (target: 80%)
- [x] `internal/webauthn`: 85.9% (target: 80%)
