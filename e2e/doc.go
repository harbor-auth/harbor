// Package e2e holds Harbor's agent-runnable, end-to-end OIDC harness
// (Foundation F8). It drives a live harbor-hot through the composed
// authorize→token→JWKS flow — including the §11.7 negatives — to catch the
// class of bug where every unit test is green but the assembled flow is broken.
//
// The actual harness lives in flow_test.go behind a `//go:build e2e` tag, so it
// is EXCLUDED from the default `go test ./...` run (it needs a live server). Run
// it against the local stack:
//
//	docker compose -f e2e/docker-compose.yml up -d
//	go test -tags e2e ./e2e/...
//
// This file exists only so the package compiles cleanly under the default tags;
// it carries no logic. See e2e/README.md and docs/plans/agentic-foundations.md.
package e2e
