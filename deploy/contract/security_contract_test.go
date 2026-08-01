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
			!strings.Contains(text, "\nkind: NetworkPolicy\n") {
			continue
		}
		objects = append(objects, decode(t, document)...)
	}
	assertWorkloadContract(t, "helm", objects)
	assertEnvNameParity(t, loadFiles(t, filepath.Join("..", "k8s", "*.yaml")), objects)
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
			for _, key := range []string{"REGION", "KMS_KEY_MAP", "HARBOR_DEV_MODE"} {
				if strings.TrimSpace(fmt.Sprint(value(t, configData, key))) == "" {
					t.Errorf("required config %s missing", key)
				}
			}
			if fmt.Sprint(value(t, configData, "HARBOR_DEV_MODE")) != "false" {
				t.Error("production manifest must explicitly disable development mode")
			}

			secret := find(t, objects, "Secret", component+"-secrets")
			secretData := pathMap(t, secret, "stringData")
			for _, key := range []string{"DATABASE_URL", "REDIS_URL"} {
				if _, ok := secretData[key]; !ok {
					t.Errorf("required secret %s missing", key)
				}
			}
			for _, forbidden := range []string{"KEK_SECRET", "HARBOR_KEK_SECRET", "HARBOR_KMS_SECRET"} {
				if _, ok := secretData[forbidden]; ok {
					t.Errorf("development-only local crypto secret %s is reachable", forbidden)
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
				if port != 53 && port != 5432 && port != 6379 && port != 443 && port != 8080 && port != 8086 && port != 8090 {
					t.Errorf("unexpected egress port %d", port)
				}
			}
		})
	}
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
