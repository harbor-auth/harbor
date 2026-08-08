// SPDX-FileCopyrightText: 2026 Harbor Authors
// SPDX-License-Identifier: AGPL-3.0-only

package contract

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var digestImage = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

type object map[string]any

func TestRawSecurityContract(t *testing.T) {
	objects := loadFiles(t, filepath.Join("..", "k8s", "*.yaml"))
	assertWorkloadContract(t, "raw", objects)
	assertRuntimeConfigurationContract(t, objects, true)
	assertPublicLoginRoute(t, objects)
}

func TestHelmSecurityContract(t *testing.T) {
	path := os.Getenv("HELM_RENDERED")
	if path == "" {
		assertHelmSourceSecurityContract(t)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var objects []object
	for _, document := range bytes.Split(data, []byte("\n---")) {
		text := string(document)
		if !strings.Contains(text, "\nkind: Deployment\n") &&
			!strings.Contains(text, "\nkind: ConfigMap\n") &&
			!strings.Contains(text, "\nkind: Secret\n") &&
			!strings.Contains(text, "\nkind: NetworkPolicy\n") &&
			!strings.Contains(text, "\nkind: Ingress\n") &&
			// ServiceAccount and Job are needed by
			// assertServiceAccountsExist; without them every workload's
			// serviceAccountName would look unresolvable.
			!strings.Contains(text, "\nkind: ServiceAccount\n") &&
			!strings.Contains(text, "\nkind: Job\n") {
			continue
		}
		objects = append(objects, decode(t, document)...)
	}
	assertWorkloadContract(t, "helm", objects)
	// The chart defaults intentionally leave deployer-owned credentials empty,
	// but the rendered Secret must expose every exact runtime key.
	assertRuntimeConfigurationContract(t, objects, false)
	assertEnvNameParity(t, loadFiles(t, filepath.Join("..", "k8s", "*.yaml")), objects)
	assertPublicLoginRoute(t, objects)
	assertServiceAccountsExist(t, objects)
}

// assertServiceAccountsExist checks that every workload's serviceAccountName is
// actually created by the same render.
//
// deployment-relay.yaml named harbor-relay-sa, which serviceaccounts.yaml never
// created — it only ever made the hot and mgmt accounts. A pod referencing a
// missing ServiceAccount is not admitted at all, so this did not degrade the
// relay, it stopped it from ever starting. helm lint and helm template both
// pass, because neither resolves a name to an object.
//
// The relay-enabled matrix entry is what gives this teeth: with the relay off
// its templates never render, and the gap is invisible.
func assertServiceAccountsExist(t *testing.T, objects []object) {
	t.Helper()
	accounts := map[string]bool{"": true, "default": true}
	for _, item := range objects {
		if kind, _ := item["kind"].(string); kind == "ServiceAccount" {
			accounts[pathString(t, item, "metadata", "name")] = true
		}
	}

	var checked int
	for _, item := range objects {
		kind, _ := item["kind"].(string)
		if kind != "Deployment" && kind != "Job" {
			continue
		}
		podSpec := pathMap(t, item, "spec", "template", "spec")
		checked++
		name, _ := podSpec["serviceAccountName"].(string)
		if !accounts[name] {
			t.Errorf("%s/%s references ServiceAccount %q, which this render never creates; "+
				"the pod would not be admitted at all",
				kind, pathString(t, item, "metadata", "name"), name)
		}
	}
	if checked == 0 {
		t.Error("no workloads examined for ServiceAccount references; the render or filter changed")
	}
}

func assertPublicLoginRoute(t *testing.T, objects []object) {
	t.Helper()
	ingress := find(t, objects, "Ingress", "harbor-hot")
	rules := pathSlice(t, pathMap(t, ingress, "spec"), "rules")
	if len(rules) != 1 {
		t.Fatalf("public ingress rules = %d, want 1", len(rules))
	}
	rule, ok := asObject(rules[0])
	if !ok {
		t.Fatal("public ingress rule is not a map")
	}
	paths := pathSlice(t, pathMap(t, rule, "http"), "paths")
	want := map[string]string{
		"/login":     "harbor-mgmt",
		"/signup":    "harbor-mgmt",
		"/signin":    "harbor-mgmt",
		"/enroll":    "harbor-mgmt",
		"/webauthn":  "harbor-mgmt",
		"/recovery":  "harbor-mgmt",
		"/dashboard": "harbor-mgmt", // M2: SSO_DASHBOARD_PATH's default landing target (GET /login/sso, and the post-registration handoff) must resolve to harbor-mgmt, not fall through to harbor-hot's catch-all.
		"/":          "harbor-hot",
	}
	for _, item := range paths {
		path, ok := asObject(item)
		if !ok {
			t.Fatal("public ingress path is not a map")
		}
		name := pathString(t, path, "backend", "service", "name")
		delete(want, matchingRoute(fmt.Sprint(path["path"]), name, want))
	}
	if len(want) != 0 {
		t.Fatalf("public ingress routes missing or incorrect: %v", want)
	}
}

func matchingRoute(path, service string, want map[string]string) string {
	if want[path] == service {
		return path
	}
	return ""
}

func assertHelmSourceSecurityContract(t *testing.T) {
	t.Helper()
	values, err := os.ReadFile(filepath.Join("..", "helm", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(values, []byte(`digest: "sha256:`)); count < 3 {
		t.Fatalf("Helm defaults contain %d immutable workload digests, want at least 3", count)
	}
	for _, template := range []string{"deployment-hot.yaml", "deployment-mgmt.yaml", "job-migrate.yaml"} {
		data, readErr := os.ReadFile(filepath.Join("..", "helm", "templates", template))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Contains(data, []byte(`required "`)) || !bytes.Contains(data, []byte(`image.digest`)) {
			t.Errorf("%s does not fail closed when its immutable image digest is absent", template)
		}
	}

	configContract := map[string][]string{
		"configmap-hot.yaml": {
			`LOGIN_URL: {{ required "hot.loginURL is required in production" .Values.hot.loginURL`,
			`REGION: {{ .Values.region`,
		},
		"configmap-mgmt.yaml": {
			`REGISTRATION_BASE_URL: {{ required "mgmt.registrationBaseURL is required in production" .Values.mgmt.registrationBaseURL`,
			`WEBAUTHN_RP_DISPLAY_NAME:`,
			`WEBAUTHN_RP_ORIGINS:`,
			`REGION: {{ .Values.region`,
		},
	}
	for template, required := range configContract {
		data, readErr := os.ReadFile(filepath.Join("..", "helm", "templates", template))
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, fragment := range required {
			if !bytes.Contains(data, []byte(fragment)) {
				t.Errorf("%s is missing required runtime contract %q", template, fragment)
			}
		}
		if bytes.Contains(data, []byte("HARBOR_DEV_MODE")) {
			t.Errorf("%s still emits obsolete HARBOR_DEV_MODE", template)
		}
	}
}

// TestEveryWorkloadCanPullItsImage guards the image-pull path.
//
// Both clusters run on private GHCR packages with no registry credentials, so
// a workload whose pod spec omits imagePullSecrets can only start while its
// image happens to be cached on the node — it cannot survive image garbage
// collection or a node rebuild. The migrate Job is the sharpest case: it runs
// as an Argo CD PreSync hook under the default ServiceAccount, so when it
// alone cannot pull, the hook never completes and the entire sync stalls
// before any workload rolls.
//
// Asserted against template source rather than a render so it holds without a
// helm binary, and so a NEW workload template cannot quietly skip it.
func TestEveryWorkloadCanPullItsImage(t *testing.T) {
	templates, err := filepath.Glob(filepath.Join("..", "helm", "templates", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) == 0 {
		t.Fatal("no chart templates found; this test would pass vacuously")
	}

	var checked int
	for _, template := range templates {
		data, readErr := os.ReadFile(template)
		if readErr != nil {
			t.Fatal(readErr)
		}
		// Only pod-bearing templates pull images.
		if !bytes.Contains(data, []byte("image: {{ include")) {
			continue
		}
		checked++
		if !bytes.Contains(data, []byte(`include "harbor.imagePullSecrets"`)) {
			t.Errorf("%s runs an image but its pod spec omits imagePullSecrets; "+
				"on a private registry this workload cannot pull once its image "+
				"leaves the node cache", filepath.Base(template))
		}
	}
	if checked < 4 {
		t.Fatalf("only %d image-bearing templates found, want at least 4 "+
			"(hot, mgmt, relay, migrate) — the detection pattern has drifted", checked)
	}

	helpers, err := os.ReadFile(filepath.Join("..", "helm", "templates", "_helpers.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(helpers, []byte(`define "harbor.imagePullSecrets"`)) {
		t.Error("_helpers.tpl no longer defines harbor.imagePullSecrets")
	}

	values, err := os.ReadFile(filepath.Join("..", "helm", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(values, []byte("imagePullSecrets: []")) {
		t.Error("values.yaml no longer declares global.imagePullSecrets, so the knob is undiscoverable")
	}
}

func TestHarborImagesRequireKeylessSignatures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "kyverno", "policies", "verify-harbor-images.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	policy := string(data)
	for _, required := range []string{
		"validationFailureAction: Enforce",
		"ghcr.io/harbor-auth/harbor/*",
		"requiredDigest: true",
		"verifyDigest: true",
		"https://token.actions.githubusercontent.com",
		"https://github.com/harbor-auth/harbor/.github/workflows/publish.yml@refs/heads/main",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("signature policy missing %q", required)
		}
	}
}

func assertWorkloadContract(t *testing.T, variant string, objects []object) {
	t.Helper()
	for _, component := range []string{"harbor-hot", "harbor-mgmt"} {
		t.Run(variant+"/"+component, func(t *testing.T) {
			deployment := find(t, objects, "Deployment", component)
			pod := pathMap(t, deployment, "spec", "template", "spec")
			container := named(t, pathSlice(t, pod, "containers"), component)
			image := stringValue(t, container, "image")
			if !digestImage.MatchString(image) {
				t.Errorf("image %q is not pinned to sha256 digest", image)
			}
			if stringValue(t, container, "imagePullPolicy") != "IfNotPresent" {
				t.Error("digest-pinned workload must use IfNotPresent")
			}
			podSecurity := pathMap(t, pod, "securityContext")
			if value(t, podSecurity, "runAsNonRoot") != true || pathString(t, podSecurity, "seccompProfile", "type") != "RuntimeDefault" {
				t.Error("pod must run non-root with RuntimeDefault seccomp")
			}
			security := pathMap(t, container, "securityContext")
			if value(t, security, "allowPrivilegeEscalation") != false || value(t, security, "readOnlyRootFilesystem") != true {
				t.Error("container privilege escalation/root filesystem hardening missing")
			}
			if strings.Join(stringsValue(t, pathMap(t, security, "capabilities"), "drop"), ",") != "ALL" {
				t.Error("container must drop ALL capabilities")
			}

			config := find(t, objects, "ConfigMap", component+"-config")
			configData := pathMap(t, config, "data")
			for _, key := range []string{"REGION", "KMS_KEY_MAP"} {
				if strings.TrimSpace(fmt.Sprint(value(t, configData, key))) == "" {
					t.Errorf("required config %s missing", key)
				}
			}

			secret := find(t, objects, "Secret", component+"-secrets")
			secretData := pathMap(t, secret, "stringData")
			for _, key := range []string{"DATABASE_URL", "REDIS_URL"} {
				if _, ok := secretData[key]; !ok {
					t.Errorf("required secret %s missing", key)
				}
			}
			for _, forbidden := range []string{"KEK_SECRET", "HARBOR_KEK_SECRET"} {
				if _, ok := secretData[forbidden]; ok {
					t.Errorf("obsolete crypto secret %s is reachable", forbidden)
				}
			}

			policy := find(t, objects, "NetworkPolicy", component)
			ports := networkPorts(t, policy)
			for _, required := range []int{53, 5432, 6379, 443} {
				if !ports[required] {
					t.Errorf("required narrowly-scoped egress port %d missing", required)
				}
			}
			for port := range ports {
				if port != 53 && port != 5432 && port != 6379 && port != 443 && port != 8080 && port != 8086 && port != 8090 && port != 8200 {
					t.Errorf("unexpected egress port %d", port)
				}
			}
		})
	}
}

func assertRuntimeConfigurationContract(t *testing.T, objects []object, requireSecretValues bool) {
	t.Helper()
	requiredConfig := map[string][]string{
		"harbor-hot":  {"ISSUER", "LOGIN_URL", "REGION"},
		"harbor-mgmt": {"AUTHORIZE_COMPLETE_URL", "REGISTRATION_BASE_URL", "REGION", "WEBAUTHN_RP_DISPLAY_NAME", "WEBAUTHN_RP_ID", "WEBAUTHN_RP_ORIGINS"},
	}
	requiredSecrets := map[string][]string{
		"harbor-hot":  {"DATABASE_URL", "HARBOR_KMS_SECRET", "REDIS_URL"},
		"harbor-mgmt": {"DATABASE_URL", "HARBOR_KMS_SECRET", "INITIAL_ACCESS_TOKEN", "REDIS_URL"},
	}

	for _, component := range []string{"harbor-hot", "harbor-mgmt"} {
		config := pathMap(t, find(t, objects, "ConfigMap", component+"-config"), "data")
		secret := pathMap(t, find(t, objects, "Secret", component+"-secrets"), "stringData")
		for _, key := range requiredConfig[component] {
			if strings.TrimSpace(fmt.Sprint(value(t, config, key))) == "" {
				t.Errorf("%s required config %s is empty", component, key)
			}
		}
		for _, key := range requiredSecrets[component] {
			secretValue, ok := secret[key]
			if !ok {
				t.Errorf("%s required secret %s is missing", component, key)
				continue
			}
			if requireSecretValues && strings.TrimSpace(fmt.Sprint(secretValue)) == "" {
				t.Errorf("%s required secret %s is empty", component, key)
			}
		}

		deployment := find(t, objects, "Deployment", component)
		container := named(t, pathSlice(t, pathMap(t, deployment, "spec", "template", "spec"), "containers"), component)
		envFrom := referencedEnvSources(t, container)
		for _, name := range []string{component + "-config", component + "-secrets"} {
			if !envFrom[name] {
				t.Errorf("%s does not project %s", component, name)
			}
		}

		for _, legacy := range []string{"HARBOR_DEV_MODE", "HARBOR_KEK_SECRET", "WEBAUTHN_ORIGIN", "WEBAUTHN_RP_NAME"} {
			if _, ok := config[legacy]; ok {
				t.Errorf("%s config still exposes obsolete %s", component, legacy)
			}
			if _, ok := secret[legacy]; ok {
				t.Errorf("%s secret still exposes obsolete %s", component, legacy)
			}
		}
	}

	hotSecret := pathMap(t, find(t, objects, "Secret", "harbor-hot-secrets"), "stringData")
	mgmtSecret := pathMap(t, find(t, objects, "Secret", "harbor-mgmt-secrets"), "stringData")
	if hotSecret["HARBOR_KMS_SECRET"] != mgmtSecret["HARBOR_KMS_SECRET"] {
		t.Error("hot and management must receive the same HARBOR_KMS_SECRET user-DEK KEK")
	}
}

func referencedEnvSources(t *testing.T, container object) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, item := range pathSlice(t, container, "envFrom") {
		source, ok := asObject(item)
		if !ok {
			t.Fatal("envFrom source is not a map")
		}
		for _, kind := range []string{"configMapRef", "secretRef"} {
			ref, ok := asObject(source[kind])
			if ok {
				names[fmt.Sprint(ref["name"])] = true
			}
		}
	}
	return names
}

func assertEnvNameParity(t *testing.T, raw, helm []object) {
	t.Helper()
	for _, component := range []string{"harbor-hot", "harbor-mgmt"} {
		for _, resource := range []struct{ kind, suffix, field string }{
			{"ConfigMap", "-config", "data"},
			{"Secret", "-secrets", "stringData"},
		} {
			rawKeys := mapKeys(pathMap(t, find(t, raw, resource.kind, component+resource.suffix), resource.field))
			helmKeys := mapKeys(pathMap(t, find(t, helm, resource.kind, component+resource.suffix), resource.field))
			if strings.Join(rawKeys, ",") != strings.Join(helmKeys, ",") {
				t.Errorf("%s %s env names differ: raw=%v helm=%v", component, resource.kind, rawKeys, helmKeys)
			}
		}
	}
}

func mapKeys(values object) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func loadFiles(t *testing.T, pattern string) []object {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var objects []object
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, decode(t, data)...)
	}
	return objects
}

func decode(t *testing.T, data []byte) []object {
	t.Helper()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var objects []object
	for {
		var obj object
		err := decoder.Decode(&obj)
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			t.Fatal(err)
		}
		if len(obj) > 0 {
			objects = append(objects, obj)
		}
	}
	return objects
}

func find(t *testing.T, objects []object, kind, name string) object {
	t.Helper()
	for _, obj := range objects {
		if fmt.Sprint(obj["kind"]) == kind && pathString(t, obj, "metadata", "name") == name {
			return obj
		}
	}
	t.Fatalf("%s %s not found", kind, name)
	return nil
}

func pathMap(t *testing.T, root object, keys ...string) object {
	t.Helper()
	current := root
	for _, key := range keys {
		next, ok := asObject(current[key])
		if !ok {
			t.Fatalf("%s is not a map", strings.Join(keys, "."))
		}
		current = next
	}
	return current
}

func asObject(value any) (object, bool) {
	switch typed := value.(type) {
	case object:
		return typed, true
	case map[string]any:
		return object(typed), true
	default:
		return nil, false
	}
}

func pathSlice(t *testing.T, root object, key string) []any {
	t.Helper()
	items, ok := root[key].([]any)
	if !ok {
		t.Fatalf("%s is not a list", key)
	}
	return items
}

func named(t *testing.T, items []any, name string) object {
	t.Helper()
	for _, item := range items {
		obj, ok := asObject(item)
		if ok && fmt.Sprint(obj["name"]) == name {
			return obj
		}
	}
	t.Fatalf("named item %s not found", name)
	return nil
}

func value(t *testing.T, root object, key string) any {
	t.Helper()
	v, ok := root[key]
	if !ok {
		t.Fatalf("key %s missing", key)
	}
	return v
}

func stringValue(t *testing.T, root object, key string) string {
	t.Helper()
	return fmt.Sprint(value(t, root, key))
}
func pathString(t *testing.T, root object, keys ...string) string {
	t.Helper()
	return fmt.Sprint(value(t, pathMap(t, root, keys[:len(keys)-1]...), keys[len(keys)-1]))
}

func stringsValue(t *testing.T, root object, key string) []string {
	t.Helper()
	items := pathSlice(t, root, key)
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, fmt.Sprint(item))
	}
	return result
}

func networkPorts(t *testing.T, policy object) map[int]bool {
	t.Helper()
	ports := map[int]bool{}
	spec := pathMap(t, policy, "spec")
	for _, rawRule := range pathSlice(t, spec, "egress") {
		rule, ok := asObject(rawRule)
		if !ok {
			t.Fatal("egress rule is not a map")
		}
		for _, rawPort := range pathSlice(t, rule, "ports") {
			portObject, ok := asObject(rawPort)
			if !ok {
				t.Fatal("egress port is not a map")
			}
			port := portObject["port"]
			var n int
			if _, err := fmt.Sscan(fmt.Sprint(port), &n); err != nil {
				t.Fatalf("invalid port %v", port)
			}
			ports[n] = true
		}
	}
	return ports
}
