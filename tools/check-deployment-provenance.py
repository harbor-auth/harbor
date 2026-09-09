#!/usr/bin/env python3
"""Require image-pin changes to identify matching source already on main."""
import json
import os
import re
import subprocess
import sys

VALUES = "deploy/argocd/values-prod.yaml"
SOURCES = ["cmd", "internal", "web", "db/migrations", "go.mod", "go.sum",
           "deploy/Dockerfile.hot", "deploy/Dockerfile.mgmt", "deploy/Dockerfile.migrate"]


def values(ref):
    def merge(a, b):
        for key, value in b.items():
            if isinstance(value, dict) and isinstance(a.get(key), dict):
                merge(a[key], value)
            else:
                a[key] = value
        return a
    result = {}
    for path in ("deploy/helm/values.yaml", VALUES):
        raw = subprocess.check_output(["git", "show", f"{ref}:{path}"])
        parsed = json.loads(subprocess.check_output(["yq", "eval", "-o=json", "-"], input=raw))
        result = merge(result, parsed)
    return result


def identity(config):
    return [config["global"]["image"].get("registry"),
            config["global"]["image"].get("sourceRevision"),
            *[(config[k]["image"].get("repository"), config[k]["image"].get("digest"))
              for k in ("hot", "mgmt", "migrate")]]


def output(changed):
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a") as stream:
            stream.write(f"changed={'true' if changed else 'false'}\n")


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    before, after = values(base), values("HEAD")
    if identity(before) == identity(after):
        output(False)
        print("No production image identity changes.")
        return
    revision = after.get("global", {}).get("image", {}).get("sourceRevision", "")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit("Image changes require a full global.image.sourceRevision commit SHA.")
    if subprocess.run(["git", "merge-base", "--is-ancestor", revision, "origin/main"]).returncode:
        raise SystemExit("Image source must be a revision already merged into main.")
    if subprocess.run(["git", "diff", "--quiet", revision, "HEAD", "--", *SOURCES]).returncode:
        raise SystemExit("Pinned images were built from different source; publish a new set.")
    if after["global"]["image"]["registry"] != "ghcr.io/harbor-auth/harbor":
        raise SystemExit("Production images must use the verified Harbor registry.")
    for component in ("hot", "mgmt", "migrate"):
        image = after[component]["image"]
        if image["repository"] != f"harbor-{component}" or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"]):
            raise SystemExit("Production image repository/digest is invalid.")
        if "--verify-signatures" in sys.argv:
            subprocess.run([
                "cosign", "verify", "--certificate-identity",
                "https://github.com/harbor-auth/harbor/.github/workflows/publish.yml@refs/heads/main",
                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-sha", revision,
                f"ghcr.io/harbor-auth/harbor/harbor-{component}@{image['digest']}",
            ], check=True, stdout=subprocess.DEVNULL)
    output(True)
    print(f"Image source {revision} matches this change.")


if __name__ == "__main__":
    main()
