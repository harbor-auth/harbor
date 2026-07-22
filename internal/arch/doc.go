// Package arch holds Harbor's architecture FITNESS TESTS (Foundation F9).
//
// These are executable guardrails that enforce the import boundaries the DESIGN
// mandates, so an agent taking the shortest path can't silently couple layers
// that must stay separated:
//
//   - §4.1 / §6.1  HOT vs COLD split: the stateless hot path (cmd/harbor-hot)
//     must never import a database driver — it does pure, in-memory
//     token verification, and a DB import would wreck its SLO and
//     its stateless deploy story.
//   - §5.3 / §5.4  Control plane vs data plane / region isolation: region
//     resolution is pure logic and must not reach into persistence
//     or the OIDC flow.
//   - §1.3         Codegen everywhere: internal/gen/** is generated; it is a
//     leaf that hand-written code imports, never the reverse.
//
// The tests use `go list -deps` (the canonical, module-aware way to compute a
// package's full transitive import set) rather than go/build, which does not
// understand Go modules. See docs/plans/agentic-foundations.md (F9).
package arch
