"""Aggregate gate for the Invariant Guardian eval (Phase 4).

Reads two promptfoo JSON outputs (the eval run twice) plus the fixtures' expected.json,
and enforces three things the per-test asserts cannot:

  1. Consistency: a fixture whose set of FAILed invariants differs between the two runs is
     a non-deterministic flip -> fail. An advisory reviewer may vary its wording, but its
     FAIL/PASS verdict on a seeded fixture must be stable (temperature=0 discipline).
  2. Recall: across the POSITIVE fixtures, the fraction whose expected invariant(s) were
     all flagged FAIL must be >= RECALL_FLOOR.
  3. False positives: across the NEGATIVE (control) fixtures, the fraction that produced
     ANY FAIL must be <= FP_CEILING.

Exit 0 if all gates pass, 1 otherwise — so the eval job fails on a regression of the
*reviewer's* quality, never on the product code. Run twice to catch flips:

    python evals/assert_consistent.py run1.json run2.json [--fixtures evals/fixtures]
    python evals/assert_consistent.py --selftest
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RECALL_FLOOR = 0.85
FP_CEILING = 0.10
DEFAULT_FIXTURES = Path("evals/fixtures")


def _load_expected(fixtures_dir: Path) -> dict[str, dict]:
    """fixture id -> its expected.json record ({id, kind, expect_fail})."""
    out: dict[str, dict] = {}
    for exp in sorted(fixtures_dir.glob("*/expected.json")):
        data = json.loads(exp.read_text())
        out[data["id"]] = data
    return out


def _fails_from_output(output: object) -> set[str]:
    """The set of invariant_ids the model marked FAIL, from one model output (a JSON
    Verdict string or an already-parsed dict)."""
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except (ValueError, TypeError):
            return set()
    if not isinstance(output, dict):
        return set()
    fails: set[str] = set()
    for finding in output.get("findings", []) or []:
        if (
            isinstance(finding, dict)
            and finding.get("status") == "FAIL"
            and finding.get("invariant_id")
        ):
            fails.add(finding["invariant_id"])
    return fails


def _parse_run(path: Path) -> dict[str, set[str]]:
    """fixture id -> set of FAILed invariant ids, from a promptfoo JSON output. Defensive
    about the result-list nesting, which has varied across promptfoo versions."""
    raw = json.loads(path.read_text())
    results = raw.get("results", raw)
    if isinstance(results, dict):
        results = results.get("results", [])
    out: dict[str, set[str]] = {}
    for r in results or []:
        vars_ = r.get("vars", {}) or {}
        fid = vars_.get("fixture") or vars_.get("id")
        if not fid:
            continue
        output = (r.get("response", {}) or {}).get("output", r.get("output", ""))
        out[fid] = _fails_from_output(output)
    return out


def evaluate(
    run1: dict[str, set[str]],
    run2: dict[str, set[str]],
    expected: dict[str, dict],
) -> tuple[bool, list[str]]:
    """Return (passed, human-readable lines). Pure function — unit-testable offline."""
    msgs: list[str] = []
    ok = True

    flips = sorted(fid for fid in expected if run1.get(fid, set()) != run2.get(fid, set()))
    if flips:
        ok = False
        msgs.append(f"FLIP: {len(flips)} fixture(s) differed across the two runs: {flips}")

    positives = [fid for fid, e in expected.items() if e.get("kind") == "positive"]
    negatives = [fid for fid, e in expected.items() if e.get("kind") == "negative"]

    hits = sum(1 for fid in positives if set(expected[fid]["expect_fail"]) <= run1.get(fid, set()))
    recall = hits / len(positives) if positives else 1.0
    if recall < RECALL_FLOOR:
        ok = False
    msgs.append(f"recall = {hits}/{len(positives)} = {recall:.2f} (floor {RECALL_FLOOR})")

    fp_hits = sum(1 for fid in negatives if run1.get(fid, set()))
    fp = fp_hits / len(negatives) if negatives else 0.0
    if fp > FP_CEILING:
        ok = False
    msgs.append(f"false-positive = {fp_hits}/{len(negatives)} = {fp:.2f} (ceiling {FP_CEILING})")

    return ok, msgs


def _selftest() -> int:
    expected = {
        "p1": {"id": "p1", "kind": "positive", "expect_fail": ["A"]},
        "p2": {"id": "p2", "kind": "positive", "expect_fail": ["B"]},
        "n1": {"id": "n1", "kind": "negative", "expect_fail": []},
    }
    clean = {"p1": {"A"}, "p2": {"B"}, "n1": set()}
    flipped = {"p1": {"A"}, "p2": set(), "n1": set()}
    false_pos = {"p1": {"A"}, "p2": {"B"}, "n1": {"A"}}
    zero_recall: dict[str, set[str]] = {"p1": set(), "p2": set(), "n1": set()}
    assert evaluate(clean, clean, expected)[0], "clean run should pass"
    assert not evaluate(clean, flipped, expected)[0], "flip must fail"
    assert not evaluate(false_pos, false_pos, expected)[0], "false positive must fail"
    assert not evaluate(zero_recall, zero_recall, expected)[0], "zero recall must fail"
    print("assert_consistent selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return _selftest()
    fixtures_dir = DEFAULT_FIXTURES
    positional: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--fixtures":
            fixtures_dir = Path(argv[i + 1])
            i += 2
            continue
        positional.append(argv[i])
        i += 1
    if len(positional) < 2:
        print("usage: assert_consistent.py run1.json run2.json [--fixtures DIR]", file=sys.stderr)
        return 2

    expected = _load_expected(fixtures_dir)
    run1 = _parse_run(Path(positional[0]))
    run2 = _parse_run(Path(positional[1]))
    ok, msgs = evaluate(run1, run2, expected)
    for m in msgs:
        print(m)
    print("EVAL GATE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
