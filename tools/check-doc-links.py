#!/usr/bin/env python3
"""
tools/check-doc-links.py — Verify every relative markdown link in docs/ resolves
to a real file on disk.

Exit 0: all links resolve.  Exit 1: one or more links are broken.

Checks:
  - Every [text](path) in a .md file under docs/
  - Skips http/https/mailto links (external — not our problem)
  - Skips anchor-only links (#section)
  - Strips the fragment (#anchor) from mixed path+anchor links before checking
  - Resolves paths relative to the file that contains the link

Run from the repo root:
    python3 tools/check-doc-links.py
"""

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

# Match [any text](target) — captures the link target.
_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def check_links() -> int:
    if not DOCS_DIR.is_dir():
        print(f"ERROR: {DOCS_DIR} not found — run from the repo root.", file=sys.stderr)
        return 1

    # Display name for prose output (DOCS_DIR is now an absolute path).
    docs_label = "docs"

    broken = []
    total = 0
    checked_files = 0

    for root, _dirs, files in os.walk(DOCS_DIR):
        for fname in files:
            if not fname.endswith(".md"):
                continue
            checked_files += 1
            filepath = Path(root) / fname

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                print(f"WARNING: could not read {filepath}: {exc}", file=sys.stderr)
                continue

            for m in _LINK_RE.finditer(content):
                raw_target = m.group(1).strip()

                # Skip external links and mailto
                if raw_target.startswith(("http://", "https://", "mailto:")):
                    continue

                # Skip bare anchors
                if raw_target.startswith("#"):
                    continue

                # Strip title attribute (e.g. `path "Title"`) and fragment
                target_path = raw_target.split("#")[0].split('"')[0].split("'")[0].strip()
                if not target_path:
                    continue

                total += 1

                # Resolve relative to the containing file's directory
                resolved = (filepath.parent / target_path).resolve()

                if not resolved.exists():
                    broken.append((str(filepath), raw_target, str(resolved)))

    print(f"  Checked {total} relative links across {checked_files} markdown files in {docs_label}/")

    if broken:
        print(f"\nERROR: {len(broken)} broken link(s) found:\n")
        for src, target, resolved in broken:
            print(f"  {src}")
            print(f"    → {target}")
            print(f"       (resolved: {resolved})")
        print(
            "\nFix: update the link target so it resolves to an existing file, "
            "or remove the link."
        )
        return 1

    print(f"  All {total} relative links resolve. ✓")
    return 0


if __name__ == "__main__":
    sys.exit(check_links())
