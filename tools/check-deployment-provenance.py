#!/usr/bin/env python3
"""Require image-pin changes to identify matching source already on main."""
import json
import re
import subprocess
import sys

VALUES = "deploy/argocd/values-prod.yaml"
SOURCES = ["cmd", "internal", "web", "db/migrations", "go.mod", "go.sum",
           "deploy/Dockerfile.hot", "deploy/Dockerfile.mgmt", "deploy/Dockerfile.migrate"]


def values(ref):
    raw = subprocess.check_output(["git", "show", f"{ref}:{VALUES}"])
    return json.loads(subprocess.check_output(["yq", "eval", "-o=json", "-"], input=raw))


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    before, after = values(base), values("HEAD")
    if all(before[k]["image"].get("digest") == after[k]["image"].get("digest")
           for k in ("hot", "mgmt", "migrate")):
        print("No production image digest changes.")
        return
    revision = after.get("global", {}).get("image", {}).get("sourceRevision", "")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit("Image changes require a full global.image.sourceRevision commit SHA.")
    if subprocess.run(["git", "merge-base", "--is-ancestor", revision, "origin/main"]).returncode:
        raise SystemExit("Image source must be a revision already merged into main.")
    if subprocess.run(["git", "diff", "--quiet", revision, "HEAD", "--", *SOURCES]).returncode:
        raise SystemExit("Pinned images were built from different source; publish a new set.")
    print(f"Image source {revision} matches this change. Signature admission remains mandatory.")


if __name__ == "__main__":
    main()
