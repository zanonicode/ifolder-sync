"""R2 drift guard — keep invariants.yaml honest against the code it describes.

Each invariant entry names a `source_symbol` (`file::symbol`) and an `anchor_test`
(a pytest nodeid `file::test_name`). A refactor that renames or removes either would
leave the Guardian's contract silently pointing at nothing. This asserts both still
exist. It runs in two places:

  - the unit-test job (`tests/test_invariants_drift.py`) — so drift fails a PR immediately;
  - weekly (`.github/workflows/ai-repo-scan.yml`) — belt-and-suspenders + opens an issue.

Stdlib + `ast` only (no network, no google-genai).
Run:  python -m scripts.ai_guardian.check_invariants_drift
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from .prompt import load_invariants


def _defined_names(path: Path) -> set[str]:
    """Every function / async-function / class name defined anywhere in a Python file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def find_drift(invariants: list[dict], root: Path) -> list[str]:
    """Return human-readable drift problems (empty == healthy). Pure: unit-testable."""
    problems: list[str] = []
    cache: dict[Path, set[str] | None] = {}

    def names(relfile: str) -> set[str] | None:
        p = root / relfile
        if p not in cache:
            cache[p] = _defined_names(p) if p.exists() else None
        return cache[p]

    for entry in invariants:
        for field in ("source_symbol", "anchor_test"):
            ref = str(entry.get(field, ""))
            if "::" not in ref:
                problems.append(f"{entry.get('id')}: {field} is not 'file::symbol': {ref!r}")
                continue
            relfile, symbol = ref.split("::", 1)
            defined = names(relfile)
            if defined is None:
                problems.append(f"{entry.get('id')}: {field} file missing: {relfile}")
            elif symbol not in defined:
                problems.append(f"{entry.get('id')}: {field} symbol not found: {ref}")
    return problems


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    invariants = load_invariants(root / "scripts" / "ai_guardian" / "invariants.yaml")
    problems = find_drift(invariants, root)
    if problems:
        print("invariants.yaml DRIFT detected:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"invariants.yaml OK: {len(invariants)} invariants; all anchors resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
