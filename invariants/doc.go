// Package invariants holds Harbor's Executable Invariants Registry
// (Foundation F1) and the meta-test that enforces it.
//
// registry.yaml is the single source of truth mapping each §A.8/§11.7/§6.5.7
// non-negotiable to the test(s) that enforce it. registry_test.go parses that
// file and FAILS the build if any invariant lacks a real, `//harbor:invariant`
// -tagged enforcing test — so an invariant can never quietly become prose-only.
//
// See docs/plans/agentic-foundations.md (F1) and docs/DESIGN.md §A.8.
package invariants
