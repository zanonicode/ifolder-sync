"""R2: the shipped invariants.yaml must not drift from the code it describes.

This runs in the normal pytest job, so renaming/removing a `source_symbol` or
`anchor_test` referenced by invariants.yaml fails a PR immediately — the Guardian's
contract can never silently point at code that no longer exists.
"""

from __future__ import annotations

from pathlib import Path

from scripts.ai_guardian.check_invariants_drift import find_drift
from scripts.ai_guardian.prompt import load_invariants

ROOT = Path(__file__).resolve().parents[1]


def test_real_invariants_have_no_drift():
    invariants = load_invariants(ROOT / "scripts" / "ai_guardian" / "invariants.yaml")
    assert find_drift(invariants, ROOT) == []


def test_find_drift_flags_missing_symbol_and_test():
    bad = [
        {
            "id": "BOGUS",
            "source_symbol": "ifolder_sync/syncer.py::_this_symbol_does_not_exist",
            "anchor_test": "tests/test_safety.py::test_this_does_not_exist",
        }
    ]
    problems = find_drift(bad, ROOT)
    assert any("source_symbol" in p for p in problems)
    assert any("anchor_test" in p for p in problems)


def test_find_drift_flags_missing_file():
    bad = [
        {
            "id": "X",
            "source_symbol": "ifolder_sync/does_not_exist.py::foo",
            "anchor_test": "tests/test_safety.py::test_walk_guard_aborts_without_deletions",
        }
    ]
    problems = find_drift(bad, ROOT)
    assert any("file missing" in p for p in problems)


def test_find_drift_flags_malformed_ref():
    bad = [{"id": "Y", "source_symbol": "no-colons-here", "anchor_test": "also-bad"}]
    problems = find_drift(bad, ROOT)
    assert len(problems) == 2
