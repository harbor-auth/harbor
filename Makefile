# Harbor — one-command entry points.
#
# This Makefile wires the workflows documented in `.agents/*.md` and
# `docs/DESIGN.md` §1.8 into single commands. Each target mirrors a skill:
#
#   build / build-static ....... @go-build       (.agents/go-build.md)
#   test / test-* .............. @go-test        (.agents/go-test.md)
#   generate / generate-check .. @codegen        (.agents/codegen.md)
#   validate ................... @validate       (.agents/validate.md)
#   docs-check ................. @docs           (.agents/docs.md)
#   migrate / migrate-* ........ @db-migrate     (.agents/db-migrate.md)
#   conformance ................ @oidc-conformance (.agents/oidc-conformance.md)
#   load-test .................. @load-test      (.agents/load-test.md)
#
# A stale target is a bug: if a skill's commands change, update this file too.
#
# ---------------------------------------------------------------------------
# Foundation F3 — Fail-Closed Hermetic Toolchain
# ---------------------------------------------------------------------------
# A skipped check that passes is a LIE to the agent. Every tool-dependent
# recipe below FAILS CLOSED: if a required tool is missing, the target exits 1
# with an install hint instead of silently "skipping" and exiting 0. The
# pinned toolchain that guarantees these tools are present lives in `flake.nix`
# (`nix develop`); CI runs `nix develop -c make agent-check` so local and CI
# verdicts are identical.
#
# Human-only escape hatch: `SOFT=1 make <target>` downgrades a missing tool
# from a hard error to a warning + skip. Agents and CI MUST NOT set SOFT.

.DEFAULT_GOAL := help

GO             ?= go
BIN_DIR        ?= bin
MODULE         := github.com/harbor-auth/harbor
DATABASE_URL   ?=
MIGRATIONS_DIR := db/migrations
OPENAPI_SPEC   := api/openapi/harbor.yaml
OAPI_CONFIG    := api/openapi/oapi-codegen.yaml

# SOFT — human-only escape hatch (see F3 note above). Empty by default; never
# set by agents or CI.
SOFT ?=

# BASE — the git ref the anti-Goodhart tamper detector (F5) diffs against.
BASE ?= origin/main

# COVERAGE_FLOOR — the minimum total coverage (%) on the security-critical
# packages (identity/oidc/crypto) enforced by the F5 ratchet.
#
# RATCHET-ONLY-GOES-UP: this value must MONOTONICALLY INCREASE. Never lower it to
# make a red build pass — that is exactly the Goodhart failure the F5 guards
# exist to prevent. The correct response to a coverage drop is to ADD TESTS, not
# to relax the floor. Raise it as coverage grows.
#
# Current measured baseline: ~78.8% (as of 2026-07-09); floor set to 75% to
# leave a small buffer against minor fluctuation.
COVERAGE_FLOOR ?= 75

# REQUIRE expands to a shell `_require <tool> <install-hint>` function used by
# tool-dependent recipes. Semantics:
#   - tool present            -> returns 0 (caller runs it)
#   - tool missing + SOFT=1   -> warns, returns 1 (caller skips gracefully)
#   - tool missing (default)  -> prints an error with the hint and `exit 1`
# It is re-defined per recipe (cheap) because each recipe runs its own shell.
REQUIRE = _require() { if command -v "$$1" >/dev/null 2>&1; then return 0; fi; if [ -n "$(SOFT)" ]; then echo "  [SOFT] skipping $$1 (not installed — required)"; return 1; fi; echo "==> ERROR: $$1 not installed (required). Install: $$2. (human-only escape: SOFT=1 make <target>)"; exit 1; }

.PHONY: help build build-static test test-race test-cover test-integration \
        generate generate-check validate docs-check migrate migrate-down migrate-status \
        e2e conformance load-test agent-check tamper-check coverage-ratchet clean

## ---------------------------------------------------------------------------
## Help
## ---------------------------------------------------------------------------

help: ## Show this help
	@echo 'Harbor — make targets (mirror the .agents skills):'
	@echo ''
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ''

## ---------------------------------------------------------------------------
## Build (@go-build)
## ---------------------------------------------------------------------------

build: ## Compile everything and build harbor-hot + harbor-mgmt into $(BIN_DIR)
	$(GO) build ./...
	$(GO) build -o $(BIN_DIR)/harbor-hot  ./cmd/harbor-hot
	$(GO) build -o $(BIN_DIR)/harbor-mgmt ./cmd/harbor-mgmt

build-static: ## Static (CGO-off) linux builds for tiny images
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags='-s -w' -o $(BIN_DIR)/harbor-hot  ./cmd/harbor-hot
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags='-s -w' -o $(BIN_DIR)/harbor-mgmt ./cmd/harbor-mgmt

## ---------------------------------------------------------------------------
## Test (@go-test)
## ---------------------------------------------------------------------------

test: ## Run Go unit tests
	$(GO) test ./...

test-race: ## Run Go tests with the race detector
	$(GO) test -race ./...

test-cover: ## Run Go tests with coverage
	$(GO) test -cover ./...

test-integration: ## Run integration tests (real Postgres/Redis; -tags=integration)
	$(GO) test -tags=integration ./...

## ---------------------------------------------------------------------------
## Codegen (@codegen) — fail-closed on missing tools (F3)
## ---------------------------------------------------------------------------

generate: ## Regenerate all code from the api/ contracts (spec-first, zero drift)
	@echo '==> generate: regenerating from api/ contracts'
	@$(REQUIRE); if _require sqlc 'go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest (or: nix develop)'; then \
		echo '  sqlc generate'; sqlc generate; fi
	@$(REQUIRE); if _require oapi-codegen 'go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest (or: nix develop)'; then \
		echo '  oapi-codegen -config $(OAPI_CONFIG) $(OPENAPI_SPEC)'; \
		oapi-codegen -config $(OAPI_CONFIG) $(OPENAPI_SPEC); fi
	@$(REQUIRE); if _require buf 'go install github.com/bufbuild/buf/cmd/buf@latest (or: nix develop)'; then \
		echo '  buf generate'; buf generate; fi
	@if [ -f package.json ] || [ -f web/package.json ]; then \
		$(REQUIRE); if _require pnpm 'npm i -g pnpm (or: nix develop)'; then \
			echo '  pnpm codegen'; pnpm codegen; fi; \
	else echo '  [skip] no web package.json — pnpm codegen not applicable'; fi

generate-check: ## Fail if generated code is stale (codegen drift)
	@$(MAKE) generate
	@git diff --exit-code -- internal/gen && \
		[ -z "$$(git status --porcelain -- internal/gen)" ] || \
		{ echo 'ERROR: generated code is stale (modified or untracked) — run `make generate` and commit.'; git status --short -- internal/gen; exit 1; }

## ---------------------------------------------------------------------------
## Validate (@validate) — the fast inner loop (§1.8 Stage 1–2), fail-closed (F3)
## ---------------------------------------------------------------------------

validate: ## Fast local checks: fmt, vet, lint, spec-lint, codegen-drift
	@echo '==> validate: fmt'
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo 'gofmt needed on:'; echo "$$out"; exit 1; fi
	@echo '==> validate: vet'
	$(GO) vet ./...
	@echo '==> validate: lint'
	@$(REQUIRE); if _require golangci-lint 'go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest (or: nix develop)'; then \
		golangci-lint run; fi
	@echo '==> validate: spec-lint'
	@# spectral-cli was removed from nixpkgs (can't be pinned in flake.nix), so we
	@# run it via version-pinned npx — the SAME command CI uses (.github/workflows/ci.yml).
	@$(REQUIRE); if _require npx 'https://nodejs.org (or: nix develop)'; then \
		npx --yes @stoplight/spectral-cli@6.16.1 lint 'api/openapi/**/*.yaml'; fi
	@$(REQUIRE); if _require buf 'go install github.com/bufbuild/buf/cmd/buf@latest (or: nix develop)'; then \
		buf lint; fi
	@echo '==> validate: codegen-drift'
	@$(MAKE) generate-check

## ---------------------------------------------------------------------------
## Docs check (@docs reconcile) — design_refs integrity
## ---------------------------------------------------------------------------

docs-check: ## Validate docs integrity: design_refs resolve in DESIGN.md's § → file map + no broken relative links
	@echo '==> docs-check: validating docs integrity (design_refs + relative links)'
	@$(REQUIRE); if _require python3 'https://www.python.org/downloads/ (or: nix develop)'; then \
		echo '  [1/2] design_refs resolve in DESIGN.md § → file map' && \
		python3 tools/check-design-refs.py && \
		echo '  [2/2] relative links resolve across the docs tree' && \
		python3 tools/check-doc-links.py; \
	fi

## ---------------------------------------------------------------------------
## Agent check (@validate + more) — the single trusted verdict (F6)
## ---------------------------------------------------------------------------

agent-check: ## Run ALL checks, emit check-results.json (the one trusted verdict; F6)
	@echo '==> agent-check: single source of truth (F6)'
	$(GO) run ./tools/agentcheck --out check-results.json

## ---------------------------------------------------------------------------
## Anti-Goodhart guards (F5) — companions to agent-check, run by CI (F7) with
## the real PR base. Kept OUT of agent-check so agent-check has no git-history
## dependency; CI invokes these explicitly.
## ---------------------------------------------------------------------------

tamper-check: ## Detect test-weakening vs base (anti-Goodhart; F5)
	@echo '==> tamper-check: scanning diff vs $(BASE) for test-weakening (F5)'
	$(GO) run ./tools/lint/testweakening --base $(BASE)

coverage-ratchet: ## Fail if coverage on security-critical pkgs drops below the floor (F5)
	@echo '==> coverage-ratchet: identity/oidc/crypto must stay >= $(COVERAGE_FLOOR)% (F5)'
	@$(GO) test -coverprofile=cover.out -covermode=atomic ./internal/identity/... ./internal/oidc/... ./internal/crypto/... >/dev/null
	@total=$$($(GO) tool cover -func=cover.out | awk '/^total:/ {gsub(/%/,"",$$3); print $$3}'); \
		echo "  total coverage: $$total% (floor: $(COVERAGE_FLOOR)%)"; \
		awk -v t="$$total" -v f="$(COVERAGE_FLOOR)" 'BEGIN { if (t+0 < f+0) { printf "==> ERROR: coverage %.1f%% is below floor %d%% (F5 ratchet) — add tests, do not lower the floor\n", t, f; exit 1 } }'

## ---------------------------------------------------------------------------
## Migrations (@db-migrate)
## ---------------------------------------------------------------------------

migrate: ## Apply all pending DB migrations (needs DATABASE_URL)
	@if [ -z "$(DATABASE_URL)" ]; then echo 'ERROR: DATABASE_URL is required, e.g. make migrate DATABASE_URL=postgres://...'; exit 1; fi
	@if ! command -v migrate >/dev/null 2>&1; then echo 'ERROR: golang-migrate not installed — install: go install -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@latest'; exit 1; fi
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down: ## Roll back the most recent migration (needs DATABASE_URL)
	@if [ -z "$(DATABASE_URL)" ]; then echo 'ERROR: DATABASE_URL is required, e.g. make migrate-down DATABASE_URL=postgres://...'; exit 1; fi
	@if ! command -v migrate >/dev/null 2>&1; then echo 'ERROR: golang-migrate not installed — install: go install -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@latest'; exit 1; fi
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-status: ## Show the current migration version (needs DATABASE_URL)
	@if [ -z "$(DATABASE_URL)" ]; then echo 'ERROR: DATABASE_URL is required, e.g. make migrate-status DATABASE_URL=postgres://...'; exit 1; fi
	@if ! command -v migrate >/dev/null 2>&1; then echo 'ERROR: golang-migrate not installed — install: go install -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@latest'; exit 1; fi
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version

## ---------------------------------------------------------------------------
## Release gates (@oidc-conformance, @load-test)
## ---------------------------------------------------------------------------
## Distinction (F3): the HARNESS may legitimately not exist yet, so an ABSENT
## harness is an informative skip. But when the harness IS present, a missing
## required binary (docker / k6) FAILS CLOSED — you asked to run it and can't.
##
## `e2e` (F8) runs the in-repo OIDC e2e harness (e2e/docker-compose.yml +
## `go test -tags=e2e ./e2e/...`) — the fast composed-flow smoke gate run on
## every PR by CI's Docker-enabled `e2e` job.
##
## `conformance` (§1.8 Stage 7) is the full release gate: it FIRST runs `make
## e2e` and THEN the OIDF OP + WebAuthn suites via the conformance/ harness
## (run-plan.sh -> assert-pass.sh + manual run-webauthn.sh). Requires a
## prebuilt OIDF suite image (CONFORMANCE_SUITE_IMAGE). Both blocks FAIL CLOSED
## when their harness is present but docker is missing.

e2e: ## Run F8 Go e2e tests (authorize→token→JWKS + §11.7 negatives) against a live harbor-hot
	@echo '==> e2e: [F8] composed OIDC harness (authorize->token->JWKS + §11.7 negatives)'
	@$(REQUIRE); if _require docker 'https://docs.docker.com/get-docker/ (or: nix develop)'; then \
		echo '  bringing up e2e/docker-compose.yml (harbor-hot on :8080)'; \
		trap 'docker compose -f e2e/docker-compose.yml down -v >/dev/null 2>&1 || true' EXIT; \
		docker compose -f e2e/docker-compose.yml up -d --wait --wait-timeout 180 \
			|| { echo '==> ERROR: harbor-hot did not become healthy (see compose logs)'; exit 1; }; \
		echo '  running go test -tags=e2e ./e2e/...'; \
		HARBOR_E2E_BASE_URL=http://localhost:8080 $(GO) test -tags=e2e ./e2e/...; \
	fi

conformance: e2e ## Run OIDC OP + WebAuthn conformance suites (release gate, §1.8 Stage 7)
	@echo '==> conformance: OIDC OP + WebAuthn suites (must pass to release)'
	@echo '==> conformance: OIDF OP + WebAuthn suites'
	@# Present-harness branch is FAIL-CLOSED (mirrors the e2e block): no `|| exit 0`.
	@# The OIDC OP run (run-plan.sh -> assert-pass.sh) and the WebAuthn gate
	@# (run-webauthn.sh, which runs the internal/webauthn ceremony tests fail-
	@# closed) run INDEPENDENTLY: WebAuthn executes even while the OIDF plan is
	@# honest-red, and the recipe fails if EITHER gate fails. run-plan.sh owns the
	@# full suite + harbor-hot lifecycle (bring up, run headless, tear down).
	@if [ -f conformance/run-plan.sh ]; then \
		$(REQUIRE); if _require docker 'https://docs.docker.com/get-docker/ (or: nix develop)'; then \
			echo '  [OIDC OP] certification plan -> assert (honest red until harbor-hot conforms); WebAuthn gate runs independently'; \
			oidc_rc=0; bash conformance/run-plan.sh && bash conformance/assert-pass.sh conformance/out/results.json || oidc_rc=$$?; \
			wa_rc=0; bash conformance/run-webauthn.sh || wa_rc=$$?; \
			[ "$$oidc_rc" -eq 0 ] && [ "$$wa_rc" -eq 0 ] || { echo "==> conformance: FAILED (oidc_rc=$$oidc_rc webauthn_rc=$$wa_rc)"; exit 1; }; \
		fi; \
	else echo '  [skip] OIDF harness not present (conformance/run-plan.sh) — see .agents/oidc-conformance.md'; fi

load-test: ## Hot-path throughput & p99 load tests (release gate, §1.8 Stage 8)
	@echo '==> load-test: hot-path throughput & p99 budgets (must pass to release)'
	@if [ -d loadtest ]; then \
		$(REQUIRE); _require k6 'https://k6.io/docs/get-started/installation/ (or: nix develop)' || exit 0; \
		k6 run loadtest/verify.js; \
		k6 run loadtest/token.js; \
	else echo '  [skip] loadtest harness not present (loadtest/) — see .agents/load-test.md'; fi

## ---------------------------------------------------------------------------
## Housekeeping
## ---------------------------------------------------------------------------

clean: ## Remove build/coverage artifacts
	$(RM) -r $(BIN_DIR)
	$(RM) cover.out
	$(RM) check-results.json
