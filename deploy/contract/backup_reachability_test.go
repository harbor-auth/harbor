// SPDX-FileCopyrightText: 2026 Harbor Authors
// SPDX-License-Identifier: AGPL-3.0-only

package contract

import (
	"path/filepath"
	"testing"
)

// TestLocalBackupCanActuallyReachTheDatabase pins the two namespace-scoped
// facts the on-cluster pg_dump depends on.
//
// As first written, that CronJob ran in the harbor-backup namespace while
// naming a Secret (harbor-postgresql-auth) and needing a network path that
// both live in harbor. Neither crosses a namespace: a secretKeyRef resolves
// only within its own, and harbor-postgresql's NetworkPolicy ingress rules are
// bare podSelectors with no namespaceSelector, so they only ever match pods in
// harbor. The job could not have taken a single backup.
//
// Nothing caught it because nothing had run it — the Application was never
// applied, so the manifest sat in git looking correct. A backup that fails is
// worse than no backup, because it is mistaken for a recovery point.
func TestLocalBackupCanActuallyReachTheDatabase(t *testing.T) {
	backup := loadFiles(t, filepath.Join("..", "backup", "*.yaml"))
	if len(backup) == 0 {
		t.Fatal("no backup manifests found; this test would pass vacuously")
	}

	job := findByName(backup, "CronJob", "harbor-pgdump-local")
	if job == nil {
		t.Fatal("harbor-pgdump-local CronJob not found")
	}

	podSpec := dig(job, "spec", "jobTemplate", "spec", "template", "spec")
	if podSpec == nil {
		t.Fatal("harbor-pgdump-local has no pod spec")
	}
	jobNamespace := stringAt(job, "metadata", "namespace")

	// 1. Every secretKeyRef must name a Secret reachable from this pod, which
	//    means one declared in the same namespace.
	platform := loadFiles(t, filepath.Join("..", "platform", "*.yaml"))
	containers, _ := podSpec["containers"].([]any)
	for _, raw := range containers {
		container, _ := asObject(raw)
		env, _ := container["env"].([]any)
		for _, rawVar := range env {
			variable, _ := asObject(rawVar)
			ref := dig(variable, "valueFrom", "secretKeyRef")
			if ref == nil {
				continue
			}
			secretName, _ := ref["name"].(string)
			secret := findByName(platform, "Secret", secretName)
			if secret == nil {
				// Created out of band; namespace cannot be checked here.
				continue
			}
			if got := stringAt(secret, "metadata", "namespace"); got != jobNamespace {
				t.Errorf("harbor-pgdump-local runs in namespace %q but its %s env var reads "+
					"Secret %q from namespace %q; a secretKeyRef does not cross namespaces, "+
					"so the pod would start with no password",
					jobNamespace, variable["name"], secretName, got)
			}
		}
	}

	// 2. The pod must be a named peer of the database's default-deny policy.
	policy := findByName(platform, "NetworkPolicy", "harbor-postgresql")
	if policy == nil {
		t.Fatal("harbor-postgresql NetworkPolicy not found")
	}
	if got := stringAt(policy, "metadata", "namespace"); got != jobNamespace {
		t.Errorf("harbor-pgdump-local runs in namespace %q but harbor-postgresql's NetworkPolicy "+
			"is in %q; its ingress podSelectors carry no namespaceSelector, so they cannot match "+
			"a pod outside that namespace", jobNamespace, got)
	}

	podLabels := map[string]string{}
	if meta := dig(job, "spec", "jobTemplate", "spec", "template", "metadata"); meta != nil {
		if labels, ok := asObject(meta["labels"]); ok {
			for key, value := range labels {
				text, _ := value.(string)
				podLabels[key] = text
			}
		}
	}

	if !policyAdmits(policy, podLabels) {
		t.Errorf("harbor-postgresql's NetworkPolicy does not admit harbor-pgdump-local (labels %v); "+
			"the policy is default-deny, so the dump would hang and time out against the very "+
			"database it exists to copy", podLabels)
	}
}

// policyAdmits reports whether any ingress rule's podSelector matches labels.
func policyAdmits(policy object, labels map[string]string) bool {
	spec, _ := asObject(policy["spec"])
	ingress, _ := spec["ingress"].([]any)
	for _, rawRule := range ingress {
		rule, _ := asObject(rawRule)
		peers, _ := rule["from"].([]any)
		for _, rawPeer := range peers {
			peer, _ := asObject(rawPeer)
			selector, ok := asObject(peer["podSelector"])
			if !ok {
				continue
			}
			match, ok := asObject(selector["matchLabels"])
			if !ok {
				continue
			}
			matched := len(match) > 0
			for key, value := range match {
				text, _ := value.(string)
				if labels[key] != text {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func findByName(objects []object, kind, name string) object {
	for _, item := range objects {
		if k, _ := item["kind"].(string); k != kind {
			continue
		}
		if stringAt(item, "metadata", "name") == name {
			return item
		}
	}
	return nil
}

// dig walks a nested mapping. It goes through asObject because yaml.v3
// decodes nested maps as the named `object` type, and a Go type assertion to
// map[string]any does not match a named map type — asserting the underlying
// type directly silently yields nil for every nested lookup.
func dig(item object, path ...string) object {
	current := item
	for _, key := range path {
		next, ok := asObject(current[key])
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

func stringAt(item object, path ...string) string {
	parent := dig(item, path[:len(path)-1]...)
	if parent == nil {
		return ""
	}
	text, _ := parent[path[len(path)-1]].(string)
	return text
}
