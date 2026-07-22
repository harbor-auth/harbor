// Package mgmtapi implements harbor-mgmt's cold-path HTTP handlers
// (docs/DESIGN.md §4.2): the enrollment front door (§11.1) and, in later work,
// consent/audit/admin. It is transport-only — request parsing, validation, and
// JSON responses — delegating all domain logic to internal/identity so the
// wiring stays thin and independently testable.
package mgmtapi
