#!/usr/bin/env bash
set -euo pipefail

# One-time OpenBao initialization/configuration. Run from this directory with a
# kubeconfig that targets the HARBOR cluster. Never run it against Harbor Cloud.

KUBECTL_BIN=${KUBECTL_BIN:-kubectl}
OPENBAO_NAMESPACE=${OPENBAO_NAMESPACE:-openbao}
HARBOR_NAMESPACE=${HARBOR_NAMESPACE:-harbor}
OPENBAO_POD=${OPENBAO_POD:-openbao-0}
INIT_OUTPUT=${OPENBAO_INIT_OUTPUT:-}
POLICY_FILE=${POLICY_FILE:-harbor-hot-policy.hcl}

if [[ -z "$INIT_OUTPUT" || "$INIT_OUTPUT" != /* ]]; then
  echo "OPENBAO_INIT_OUTPUT must be an absolute path on encrypted operator storage" >&2
  exit 1
fi
if [[ ! -f "$POLICY_FILE" ]]; then
  echo "policy file not found: $POLICY_FILE" >&2
  exit 1
fi

bao() {
  "$KUBECTL_BIN" exec -i -n "$OPENBAO_NAMESPACE" "$OPENBAO_POD" -- \
    env BAO_ADDR=https://openbao.openbao.svc:8200 BAO_CACERT=/openbao/tls/ca.crt bao "$@"
}

"$KUBECTL_BIN" wait -n "$OPENBAO_NAMESPACE" --for=jsonpath='{.status.phase}'=Running \
  "pod/$OPENBAO_POD" --timeout=5m

status_json=$(bao status -format=json 2>/dev/null || true)
if [[ "$status_json" != *'"initialized": true'* ]]; then
  if [[ -e "$INIT_OUTPUT" ]]; then
    echo "refusing to overwrite existing init output: $INIT_OUTPUT" >&2
    exit 1
  fi
  umask 077
  bao operator init -key-shares=5 -key-threshold=3 -format=json >"$INIT_OUTPUT"
  echo "OpenBao initialized; split and move the five unseal shares offline: $INIT_OUTPUT"
fi

if [[ ! -s "$INIT_OUTPUT" ]]; then
  echo "OpenBao is initialized; point OPENBAO_INIT_OUTPUT at its protected init JSON to unseal/configure" >&2
  exit 1
fi

if bao status -format=json 2>/dev/null | grep -q '"sealed": true'; then
  for index in 0 1 2; do
    # The OpenBao CLI deliberately rejects piped shares. Expanding a shell
    # variable keeps the share out of shell history and script output, though
    # it is briefly visible in the local process table during this call.
    unseal_share=$(jq -r ".unseal_keys_b64[$index]" "$INIT_OUTPUT")
    bao operator unseal "$unseal_share" >/dev/null
    unset unseal_share
  done
fi

root_token=$(jq -r '.root_token' "$INIT_OUTPUT")
if [[ -z "$root_token" || "$root_token" == null ]]; then
  echo "init JSON does not contain a root token" >&2
  exit 1
fi

# Feed the root token through stdin so it never appears in argv or shell traces.
root_bao() {
  printf '%s\n' "$root_token" | "$KUBECTL_BIN" exec -i -n "$OPENBAO_NAMESPACE" "$OPENBAO_POD" -- \
    sh -ec 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=https://openbao.openbao.svc:8200 BAO_CACERT=/openbao/tls/ca.crt; exec bao "$@"' sh "$@"
}

if ! root_bao secrets list -format=json | grep -q '"transit/"'; then
  root_bao secrets enable -path=transit transit >/dev/null
fi
root_bao write -f transit/keys/harbor-eu >/dev/null

{
  printf '%s\n' "$root_token"
  cat "$POLICY_FILE"
} | "$KUBECTL_BIN" exec -i -n "$OPENBAO_NAMESPACE" "$OPENBAO_POD" -- \
  sh -ec 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=https://openbao.openbao.svc:8200 BAO_CACERT=/openbao/tls/ca.crt; exec bao policy write harbor-hot -' >/dev/null

if ! root_bao auth list -format=json | grep -q '"kubernetes/"'; then
  root_bao auth enable kubernetes >/dev/null
fi

root_bao write auth/kubernetes/config \
  kubernetes_host=https://kubernetes.default.svc:443 \
  disable_iss_validation=true >/dev/null

root_bao write auth/kubernetes/role/harbor-hot \
  bound_service_account_names=harbor-hot-sa \
  bound_service_account_namespaces="$HARBOR_NAMESPACE" \
  audience=openbao \
  policies=harbor-hot \
  token_ttl=15m \
  token_max_ttl=1h >/dev/null

# Copy only the public CA certificate into Harbor. No OpenBao token, unseal
# share, server key, or root token crosses the namespace boundary.
"$KUBECTL_BIN" get namespace "$HARBOR_NAMESPACE" >/dev/null
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
"$KUBECTL_BIN" get secret openbao-server-tls -n "$OPENBAO_NAMESPACE" \
  -o jsonpath='{.data.ca\.crt}' | base64 -d >"$temp_dir/ca.crt"
"$KUBECTL_BIN" create configmap openbao-ca -n "$HARBOR_NAMESPACE" \
  --from-file=ca.crt="$temp_dir/ca.crt" --dry-run=client -o yaml | "$KUBECTL_BIN" apply -f - >/dev/null

echo "OpenBao Transit is configured for harbor-hot. The initial root token remains protected in $INIT_OUTPUT."
