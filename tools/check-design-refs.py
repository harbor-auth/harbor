#!/usr/bin/env python3
"""
tools/check-design-refs.py — Validate that every design_refs § in feature doc
frontmatter resolves within docs/DESIGN.md's § → file map.

Exit 0: all refs resolve.  Exit 1: one or more refs are unmapped.

A ref is considered resolved if ANY of these hold:

  1. Exact match  — the ref appears verbatim in a map entry  (e.g. §1.7).
  2. Within range — the ref falls numerically inside a range entry
                    (e.g. §7.1 within §7.1–7.4, §1.2 within §1.1–1.6,
                     §9 within §8–9).
  3. Parent of map — the ref is a parent section of a map entry, meaning the
                    design tree covers sub-sections of it
                    (e.g. §3.2 when map has §3.2.1–3.2.3 and §3.2.4–3.2.7).
  4. Child of map — the ref is a more-specific sub-section of a map entry
                    (e.g. §5.3 when map has §5, §6.5.7 when map has §6.5).
  5. Appendix     — for §A.N refs, the number N falls within an "Appendix A.M–P"
                    range in the map (e.g. §A.8 within Appendix A.6–8).

Run from the repo root:
    python3 tools/check-design-refs.py
"""

import re
import sys
from pathlib import Path

REPO_ROOT    = Path(__file__).resolve().parent.parent
DESIGN_MD    = REPO_ROOT / "docs" / "DESIGN.md"
FEATURES_DIR = REPO_ROOT / "docs" / "features"


# ---------------------------------------------------------------------------
# Section-number helpers
# ---------------------------------------------------------------------------

def parse_section(s: str) -> tuple:
    """
    Parse a dotted section string into a tuple of ints.
    '3.2.1' -> (3, 2, 1),  '12' -> (12,),  '' -> ()
    """
    s = s.strip().lstrip("§").strip()
    if not s:
        return ()
    try:
        return tuple(int(x) for x in s.split("."))
    except ValueError:
        return ()


def _pad(a: tuple, b: tuple):
    """Pad both tuples to the same length with trailing zeros."""
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def section_lte(a: tuple, b: tuple) -> bool:
    a, b = _pad(a, b)
    return a <= b


def section_gte(a: tuple, b: tuple) -> bool:
    return section_lte(b, a)


def is_prefix_of(parent: tuple, child: tuple) -> bool:
    """Return True if parent is a proper prefix of child (parent is less specific)."""
    return len(parent) < len(child) and child[: len(parent)] == parent


# ---------------------------------------------------------------------------
# Map entry — one § token from DESIGN.md's map table
# ---------------------------------------------------------------------------

# Em-dash (U+2013) or ASCII hyphen used in range notation.
_RANGE_RE = re.compile(r"^([\d.]+)\s*[–\-]\s*([\d.]+)$")

# Appendix map-entry pattern: "Appendix A.M–N" or "Appendix A.M"
_APP_MAP_RE = re.compile(
    r"^[Aa]ppendix\s+[Aa]\.?(\d+)(?:\s*[–\-]\s*(\d+))?$", re.IGNORECASE
)


class MapEntry:
    """Represents one §-token extracted from the DESIGN.md map."""

    def __init__(self, raw: str):
        self.raw = raw.strip()              # e.g. '§3.2.1–3.2.3'
        self._body = self.raw.lstrip("§").strip()

    # ------------------------------------------------------------------
    def covers_appendix(self, sub: int) -> bool:
        """Return True if this entry is an appendix range covering sub-number `sub`."""
        m = _APP_MAP_RE.match(self._body)
        if not m:
            return False
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        return lo <= sub <= hi

    def covers(self, ref: tuple) -> bool:
        """
        Return True if this entry covers the given numeric section tuple.

        Cases checked:
          a) Range — lo ≤ ref ≤ hi
          b) Range parent — ref is a proper prefix of lo (ref is broader than range)
          c) Exact match
          d) ref is a parent of this entry (map has child, ref is the parent)
          e) This entry is a parent of ref (map has broader section)
        """
        raw = self._body

        m = _RANGE_RE.match(raw)
        if m:
            lo = parse_section(m.group(1))
            hi = parse_section(m.group(2))
            if not (lo and hi):
                return False
            # Case a: ref within range
            if section_gte(ref, lo) and section_lte(ref, hi):
                return True
            # Case b: ref is a parent of the range
            #   e.g. ref=(3,2) and lo=(3,2,1) → ref is a parent section
            if is_prefix_of(ref, lo):
                return True
            return False

        single = parse_section(raw)
        if not single:
            return False

        # Case c: exact match
        if single == ref:
            return True

        # Case d: ref is a parent of this entry (map entry is more specific)
        #   e.g. ref=(3,2) and single=(3,2,1) → ref is the parent
        if is_prefix_of(ref, single):
            return True

        # Case e: this entry is a parent of ref (map entry is less specific)
        #   e.g. single=(5,) and ref=(5,3) → §5 covers §5.3
        if is_prefix_of(single, ref):
            return True

        return False


# ---------------------------------------------------------------------------
# Parse the DESIGN.md § → file map
# ---------------------------------------------------------------------------

def parse_design_map() -> list:
    """
    Return a list of MapEntry objects parsed from the § → file table in
    docs/DESIGN.md.  Each table row may have multiple comma-separated §s in the
    first column (e.g. '§3.1, §3.3–3.5').
    """
    text = DESIGN_MD.read_text(encoding="utf-8")
    entries = []

    for line in text.splitlines():
        # Table row: | §… | path |  or  | Appendix … | path |
        m = re.match(r"\|\s*((?:§|Appendix)[^|]+)\|", line, re.IGNORECASE)
        if not m:
            continue
        cell = m.group(1).strip()
        for part in re.split(r",\s*", cell):
            part = part.strip()
            if part.startswith("§") or part.lower().startswith("appendix"):
                entries.append(MapEntry(part))
            elif _RANGE_RE.match(part):  # bare range like "11.3–11.6" split off a §-cell
                entries.append(MapEntry("§" + part))

    return entries


# ---------------------------------------------------------------------------
# Parse design_refs from feature doc YAML frontmatter
# ---------------------------------------------------------------------------

_FM_RE   = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
_REFS_RE = re.compile(r"design_refs:\s*\[([^\]]*)\]")

# Appendix ref in a feature doc: §A or §A.8
_APP_REF_RE = re.compile(r"^§[Aa]\.?(\d+)?$")


def parse_design_refs(path: Path) -> list:
    """Extract the list of §-strings from a feature doc's design_refs field."""
    content = path.read_text(encoding="utf-8")
    fm = _FM_RE.match(content)
    if not fm:
        return []
    m = _REFS_RE.search(fm.group(1))
    if not m:
        return []
    return [r.strip() for r in m.group(1).split(",") if r.strip()]


# ---------------------------------------------------------------------------
# Resolution check
# ---------------------------------------------------------------------------

def ref_resolves(ref: str, entries: list) -> bool:
    """
    Return True if `ref` (e.g. '§3.2', '§5.3', '§A.8') is covered by at
    least one map entry.
    """
    ref = ref.strip()

    # Appendix ref: §A or §A.N
    am = _APP_REF_RE.match(ref)
    if am:
        sub_str = am.group(1)
        if sub_str is None:
            # Bare §A — any appendix entry counts
            return any(e._body.lower().startswith("appendix") for e in entries)
        sub_num = int(sub_str)
        return any(e.covers_appendix(sub_num) for e in entries)

    # Numeric ref
    stripped = ref.lstrip("§").strip()
    ref_tuple = parse_section(stripped)
    if not ref_tuple:
        return False

    return any(e.covers(ref_tuple) for e in entries)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if not DESIGN_MD.exists():
        print(f"ERROR: {DESIGN_MD} not found — run from the repo root.", file=sys.stderr)
        return 1

    entries = parse_design_map()
    if not entries:
        print(f"ERROR: No § entries found in {DESIGN_MD}'s map table.", file=sys.stderr)
        return 1

    print(f"  Loaded {len(entries)} § entries from {DESIGN_MD}")

    feature_files = sorted(FEATURES_DIR.glob("*.md"))
    if not feature_files:
        print(f"  No feature docs found in {FEATURES_DIR} — nothing to check.")
        return 0

    failures = []
    ok_count = 0

    for feat in feature_files:
        refs = parse_design_refs(feat)
        for ref in refs:
            if ref_resolves(ref, entries):
                ok_count += 1
            else:
                failures.append((feat.name, ref))

    if failures:
        print(
            f"\nERROR: {len(failures)} design_refs "
            f"do not resolve in {DESIGN_MD} § → file map:\n"
        )
        for fname, ref in failures:
            print(f"  docs/features/{fname}: {ref}")
        print(
            "\nFix: update the feature doc's design_refs to use valid § numbers "
            "listed in docs/DESIGN.md, or add the missing § to the map."
        )
        return 1

    total = ok_count + len(failures)
    print(f"  {total} design_refs checked — all resolve. ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
