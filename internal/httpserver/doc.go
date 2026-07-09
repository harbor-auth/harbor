// Package httpserver holds Harbor's shared HTTP server bootstrap — graceful
// startup/shutdown wiring and the liveness/health mux reused by both binaries
// (docs/DESIGN.md §4.1). It is deliberately thin and transport-only: it carries
// no auth, persistence, or domain logic, so the hot and cold paths share a
// single, well-tested server lifecycle.
package httpserver
