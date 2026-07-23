#!/usr/bin/env bash
# Harbor — OIDC OP conformance runner (§1.8 Stage 7).
#
# Drives harbor-hot (the OP under test) through the OpenID Foundation conformance
# suite's OIDC OP test plan, HEADLESSLY, and archives results as compliance
# evidence (§12). This is the full certification run that follows the fast F8
# e2e smoke gate in `make conformance`.
#
# The runner's exit code is AUTHORITATIVE: a non-zero exit fails the release
# gate (honest red). harbor-hot now uses real ES256 signing (DB-persisted ECDSA
# key via signingkeys store) and a PKCE-only authorization code flow; it will
# stay RED on tests that require features not yet implemented (e.g. pairwise
# subject identifiers, prompt=none). Do NOT waive — fix the implementation.
#
# The OIDF suite (mongodb + server + nginx on :8443) is a heavy external
# dependency built from a large Java jar; there is no official prebuilt image.
# So this script:
#   PRIMARY   — if CONFORMANCE_SUITE_IMAGE is set, run that prebuilt image.
#   SECONDARY — else shallow-clone the suite at a pinned ref and, because the
#               jar build is too heavy to reliably script here, STOP at a single
#               clearly-marked, fail-closed manual step (echo the wiki URL, exit
#               1). Honest fail-closed beats a flaky half-build.
#
# Overridable knobs (env):
#   CONFORMANCE_SUITE_IMAGE  Spring Boot server image (primary path; see prebuilt compose)
#   CONFORMANCE_NGINX_IMAGE  nginx TLS-terminator image (default: derived from suite image tag)
#   CONFORMANCE_SUITE_REF    pinned git ref to clone (secondary path)
#   CONFORMANCE_SERVER       suite base URL (default https://localhost.emobix.co.uk:8443)
#   HARBOR_ISSUER            issuer the suite drives (default http://host.docker.internal:8080)
#   PLAN                     OIDF test plan name + variant string
#                             (default oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client])
set -euo pipefail

# --- Config (pinned defaults; override via env) ------------------------------
CONFORMANCE_SUITE_IMAGE="${CONFORMANCE_SUITE_IMAGE:-}"
CONFORMANCE_SUITE_REF="${CONFORMANCE_SUITE_REF:-release-v5.1.45}"
# Derive the nginx image from the suite image tag (same GitLab registry, /nginx sub-path).
# Override with CONFORMANCE_NGINX_IMAGE if using a custom registry.
_suite_tag="${CONFORMANCE_SUITE_IMAGE##*:}"
_suite_registry="${CONFORMANCE_SUITE_IMAGE%%:*}"
CONFORMANCE_NGINX_IMAGE="${CONFORMANCE_NGINX_IMAGE:-${_suite_registry}/nginx:${_suite_tag}}"
CONFORMANCE_SUITE_REPO="${CONFORMANCE_SUITE_REPO:-https://github.com/openid-certification/conformance-suite.git}"
CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443}"
HARBOR_ISSUER="${HARBOR_ISSUER:-http://host.docker.internal:8080}"
# Variants are required by run-test-plan.py to enumerate the correct test modules.
#   server_metadata=discovery   — harbor-hot serves /.well-known/openid-configuration
#   client_registration=static_client — harbor-hot has no DCR endpoint yet
PLAN="${PLAN:-oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]}"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
SUITE_DIR="$HERE/.suite"
HARBOR_COMPOSE="$HERE/docker-compose.yml"
SUITE_PROJECT="harbor-oidf-suite"

mkdir -p "$OUT"

log() { printf '  %s\n' "$*"; }
die() { printf '==> ERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not installed (https://docs.docker.com/get-docker/ or: nix develop)"
command -v git    >/dev/null 2>&1 || die "git not installed (required to fetch the OIDF suite)"

# Shallow-clone the pinned OIDF suite into .suite/ for its runner scripts
# (scripts/run-test-plan.py). Required by BOTH the prebuilt-image path (which
# uses those scripts to drive the running image) and the build-from-source path.
ensure_suite_clone() {
  if [ ! -d "$SUITE_DIR/.git" ]; then
    log "cloning OIDF conformance suite @ $CONFORMANCE_SUITE_REF (shallow)"
    git clone --depth 1 --branch "$CONFORMANCE_SUITE_REF" "$CONFORMANCE_SUITE_REPO" "$SUITE_DIR" \
      || die "failed to clone $CONFORMANCE_SUITE_REPO @ $CONFORMANCE_SUITE_REF"
  fi
}

# --- Teardown that PRESERVES the real runner exit code -----------------------
# Capture rc before any teardown command can clobber $?, tear everything down,
# then exit rc so a failed conformance run cannot be masked by a clean teardown.
SUITE_UP=0
cleanup() {
  rc=$?
  log 'tearing down harbor-hot + OIDF suite'
  docker compose -f "$HARBOR_COMPOSE" down -v >/dev/null 2>&1 || true
  if [ "$SUITE_UP" = "1" ] && [ -f "$OUT/suite-compose.yml" ]; then
    docker compose -p "$SUITE_PROJECT" -f "$OUT/suite-compose.yml" down -v >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

# --- 1. Bring up harbor-hot (the OP under test) ------------------------------
log "bringing up harbor-hot (OP under test) — issuer $HARBOR_ISSUER"
docker compose -f "$HARBOR_COMPOSE" up -d --wait --wait-timeout 180 \
  || die 'harbor-hot did not become healthy (see: docker compose -f conformance/docker-compose.yml logs)'

# --- 2. Bring up the OIDF conformance suite ----------------------------------
# The runner scripts (scripts/run-test-plan.py) live in the upstream checkout, so
# we ALWAYS clone .suite/ at the pinned ref — even on the prebuilt-image path,
# which uses those scripts to drive the running image.
ensure_suite_clone

if [ -n "$CONFORMANCE_SUITE_IMAGE" ]; then
  # PRIMARY: prebuilt suite image (Spring Boot server) + nginx TLS terminator + MongoDB.
  # Mirrors the upstream docker-compose-prebuilt.yml exactly:
  #   mongodb  — data store (mongo:6.0.13 as pinned by upstream)
  #   server   — Spring Boot app (CONFORMANCE_SUITE_IMAGE); talks to mongodb
  #   nginx    — TLS terminator; publishes :8443 and proxies to server
  # platform: linux/amd64 forces Rosetta/QEMU on ARM64 hosts (images are amd64-only).
  # We add host.docker.internal to the nginx container so the suite can reach
  # harbor-hot on the host via the host-gateway (see docker-compose.yml NETWORKING note).
  log "starting OIDF suite (server=$CONFORMANCE_SUITE_IMAGE, nginx=$CONFORMANCE_NGINX_IMAGE)"
  cat > "$OUT/suite-compose.yml" <<YAML
services:
  mongodb:
    image: mongo:6.0.13
    platform: linux/amd64
  server:
    image: ${CONFORMANCE_SUITE_IMAGE}
    platform: linux/amd64
    environment:
      BASE_URL: https://localhost.emobix.co.uk:8443
      MONGODB_HOST: mongodb
      SPRING_PROFILES_ACTIVE: dev
      OIDC_GOOGLE_CLIENTID: google-client
      OIDC_GOOGLE_SECRET: google-secret
      OIDC_GITLAB_CLIENTID: gitlab-client
      OIDC_GITLAB_SECRET: gitlab-secret
    depends_on:
      - mongodb
    extra_hosts:
      - "host.docker.internal:host-gateway"
  nginx:
    image: ${CONFORMANCE_NGINX_IMAGE}
    platform: linux/amd64
    ports:
      - "8443:8443"
    depends_on:
      - server
    extra_hosts:
      - "host.docker.internal:host-gateway"
YAML
  docker compose -p "$SUITE_PROJECT" -f "$OUT/suite-compose.yml" up -d
  SUITE_UP=1
else
  # SECONDARY: no prebuilt image. The jar build (maven) is too heavy to reliably
  # script here, so fail closed with the exact build instructions rather than a
  # flaky half-build. The pinned .suite/ clone already exists (ensure_suite_clone
  # above); provide CONFORMANCE_SUITE_IMAGE to take the primary path.
  cat >&2 <<MANUAL
==> ERROR: no prebuilt OIDF suite image provided (CONFORMANCE_SUITE_IMAGE unset).
    The suite must be built from source (a large Java jar) before it can run.
    This step is intentionally fail-closed rather than a fragile scripted build.

    To run the full OIDC OP certification, either:
      1. Provide a prebuilt image (primary path):
           CONFORMANCE_SUITE_IMAGE=<registry/suite:tag> make conformance
      2. Or build the suite once from the pinned clone at:
           $SUITE_DIR
         following the OpenID Foundation Build & Run guide:
           https://gitlab.com/openid/conformance-suite/wikis/Developers/Build-&-Run
         then re-run with CONFORMANCE_SUITE_IMAGE pointing at your built image.
MANUAL
  exit 1
fi

# --- 3. Wait for the suite API to answer on :8443 ----------------------------
log "waiting for the OIDF suite at $CONFORMANCE_SERVER ..."
# Poll for up to 300s (60 × 5s). Spring Boot under Rosetta/QEMU emulation on
# ARM64 hosts takes ~2-3 min to start; native amd64 (CI) is much faster.
ready=
for _ in $(seq 1 60); do
  if curl -fsSk "$CONFORMANCE_SERVER/api/runner/available" >/dev/null 2>&1 \
     || curl -fsSk "$CONFORMANCE_SERVER/" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 5
done
[ -n "$ready" ] || die "OIDF suite never became reachable at $CONFORMANCE_SERVER (waited $(( 60 * 5 ))s; Spring Boot may need more time under emulation)"

# --- 4. Render the OP config (inject harbor-hot's discovery URL) --------------
# run-test-plan.py substitutes its own {BASEURL}-style tokens; the harbor issuer
# is OURS, so we render {HARBOR_DISCOVERY_URL} here into conformance/out/.
RENDERED="$OUT/harbor-op-config.rendered.json"
sed "s|{HARBOR_DISCOVERY_URL}|$HARBOR_ISSUER/.well-known/openid-configuration|g" \
  "$HERE/harbor-op-config.json" > "$RENDERED"
log "rendered OP config -> $RENDERED (discovery: $HARBOR_ISSUER/.well-known/openid-configuration)"

# --- 5. Run the OIDF test plan headlessly ------------------------------------
# scripts/run-test-plan.py lives in the cloned checkout; export per-test results
# so assert-pass.sh has structured evidence. The runner's exit code is the gate.
command -v python3 >/dev/null 2>&1 || die "python3 not installed (required by the OIDF run-test-plan.py)"
[ -f "$SUITE_DIR/scripts/run-test-plan.py" ] || die "run-test-plan.py not found in $SUITE_DIR (pinned clone incomplete?)"
# Install the runner's Python dependency (pyparsing) if not already present.
# This is a lightweight package; pip3 is always available when python3 is.
python3 -c 'import pyparsing' 2>/dev/null || pip3 install pyparsing --quiet

export CONFORMANCE_SERVER
export EXTERNAL_URL="$CONFORMANCE_SERVER"
# Set dev mode so the runner uses token=None (no auth). Without this the
# runner reads CONFORMANCE_TOKEN from the environment which is not set for a
# local/CI headless run against our own dev-mode suite instance.
export CONFORMANCE_DEV_MODE=1

log "running OIDF plan '$PLAN' against harbor-hot (headless)"
runner_rc=0
( cd "$SUITE_DIR" && python3 scripts/run-test-plan.py \
    --export-dir "$OUT/export" \
    "$PLAN" "$RENDERED" ) 2>&1 | tee "$OUT/run.log" || runner_rc=${PIPESTATUS[0]}

# --- 6. Normalize results into conformance/out/results.json ------------------
# Prefer the runner's per-test export (each file carries a status); fall back to
# an empty module list (assert-pass.sh then leans on runnerExit). Never fabricate
# a PASS: runnerExit is the real signal and is carried through verbatim.
modules='[]'
if [ -d "$OUT/export" ] && command -v jq >/dev/null 2>&1; then
  modules="$(find "$OUT/export" -type f -name '*.json' -print0 2>/dev/null \
    | xargs -0 jq -c 'select(.testName? and .status?) | {testName, status}' 2>/dev/null \
    | jq -s '.' 2>/dev/null || echo '[]')"
  [ -n "$modules" ] || modules='[]'
fi

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if command -v jq >/dev/null 2>&1; then
  jq -n \
    --arg plan "$PLAN" \
    --arg issuer "$HARBOR_ISSUER" \
    --argjson runnerExit "$runner_rc" \
    --arg generatedAt "$generated_at" \
    --argjson modules "$modules" \
    '{plan:$plan, issuer:$issuer, runnerExit:$runnerExit, generatedAt:$generatedAt, modules:$modules}' \
    > "$OUT/results.json"
else
  # jq unavailable: emit a minimal, valid results.json so assert-pass.sh can
  # still gate on runnerExit (it fails closed on a missing/invalid file).
  printf '{"plan":"%s","issuer":"%s","runnerExit":%s,"generatedAt":"%s","modules":[]}\n' \
    "$PLAN" "$HARBOR_ISSUER" "$runner_rc" "$generated_at" > "$OUT/results.json"
fi

log "results archived -> $OUT/results.json (runner exit: $runner_rc)"

# Propagate the runner's verdict as this script's exit code (honest red). The
# EXIT trap tears down while preserving this code.
exit "$runner_rc"
