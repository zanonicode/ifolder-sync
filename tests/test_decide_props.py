"""P5-6: property-based tests over the pure file-decision table (`Syncer._decide_file`).

The decide step is where a wrong answer deletes user data, so it earns invariants that hold
for ALL inputs, not just the hand-picked matrix in test_sync.py.

The strategy draws a `changed` flag per side and builds the baseline from the side's EXACT
(size, mtime) when "unchanged" — otherwise the delete cells (size==base AND mtime within tol)
are reached only by rare float collision and the dangerous decisions go unsampled. Three
families of property are asserted:
  - closure: the result is always one of the ops `_decide_file` is allowed to emit;
  - safety (invariant 1): with NO baseline, a path missing on one side is a CREATE, never a
    delete — so no destructive op may be returned;
  - liveness: with a baseline and an UNCHANGED orphan, the engine MUST delete (the positive
    counterpart the no-baseline property structurally cannot reach).
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ifolder_sync.icloud_client import RemoteEntry
from ifolder_sync.state import BaselineEntry
from ifolder_sync.syncer import _FILE_DECISION_OPS, LocalEntry, Op

REL = "note.md"
_DESTRUCTIVE = {Op.DELETE_LOCAL, Op.DELETE_REMOTE, Op.DROP_BASELINE}

_size = st.integers(min_value=0, max_value=64)
_mtime = st.floats(min_value=0, max_value=1_000_000, allow_nan=False, allow_infinity=False)
_etag = st.sampled_from(["", "etag-a", "etag-b"])


@pytest.fixture
def decider(make_syncer):
    syncer, store = make_syncer()
    yield syncer
    store.close()


@st.composite
def scenarios(draw):
    """(local, remote, baseline, present_local, present_remote, present_base) with the
    baseline built so each present side is unchanged/changed with ~50% frequency."""
    pl, pr, pb = draw(st.booleans()), draw(st.booleans()), draw(st.booleans())
    ls, lm = draw(_size), draw(_mtime)
    rs, rm, et = draw(_size), draw(_mtime), draw(_etag)
    local = {REL: LocalEntry(REL, "file", ls, lm)} if pl else {}
    remote = {REL: RemoteEntry(REL, "file", rs, rm, et)} if pr else {}
    baseline = {}
    if pb:
        # "unchanged" -> baseline EXACTLY matches the side; "changed" -> guaranteed-different.
        l_changed, r_changed = draw(st.booleans()), draw(st.booleans())
        b_ls, b_lm = (ls + 1, lm + 100.0) if l_changed else (ls, lm)
        b_rs, b_rm = (rs + 1, rm + 100.0) if r_changed else (rs, rm)
        b_et = "base-etag" if r_changed else et
        baseline = {REL: BaselineEntry(REL, "file", b_ls, b_lm, b_rs, b_rm, b_et)}
    return local, remote, baseline, pl, pr, pb


_SET = settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=500)


@_SET
@given(sc=scenarios())
def test_decide_file_returns_a_known_op(decider, sc):
    local, remote, baseline, pl, pr, pb = sc
    if not (pl or pr or pb):
        return  # a path absent from every side is never handed to _decide_file
    assert decider._decide_file(REL, local, remote, baseline) in _FILE_DECISION_OPS


@_SET
@given(sc=scenarios())
def test_decide_file_never_deletes_without_baseline(decider, sc):
    # Invariant 1: with no baseline row, "missing on one side" means "newly created on the
    # other", never "deleted". (Guards a two-way-diff collapse regression.)
    local, remote, baseline, pl, pr, pb = sc
    if pb or not (pl or pr):
        return
    assert decider._decide_file(REL, local, remote, baseline) not in _DESTRUCTIVE


@_SET
@given(sc=scenarios())
def test_decide_file_is_deterministic(decider, sc):
    local, remote, baseline, pl, pr, pb = sc
    if not (pl or pr or pb):
        return
    first = decider._decide_file(REL, local, remote, baseline)
    second = decider._decide_file(REL, local, remote, baseline)
    assert first == second


# --- liveness: the POSITIVE delete decisions the no-baseline property cannot reach ----------
@_SET
@given(size=_size, mtime=_mtime, etag=_etag)
def test_unchanged_local_orphan_is_deleted(decider, size, mtime, etag):
    # local present & unchanged, remote gone, baseline present -> propagate the remote delete.
    base = {REL: BaselineEntry(REL, "file", size, mtime, size, mtime, etag)}
    local = {REL: LocalEntry(REL, "file", size, mtime)}
    assert decider._decide_file(REL, local, {}, base) == Op.DELETE_LOCAL


@_SET
@given(size=_size, mtime=_mtime, etag=_etag)
def test_unchanged_remote_orphan_is_deleted(decider, size, mtime, etag):
    # remote present & unchanged, local gone, baseline present -> propagate the local delete.
    base = {REL: BaselineEntry(REL, "file", size, mtime, size, mtime, etag)}
    remote = {REL: RemoteEntry(REL, "file", size, mtime, etag)}
    assert decider._decide_file(REL, {}, remote, base) == Op.DELETE_REMOTE


def test_both_absent_with_baseline_drops_row(decider):
    base = {REL: BaselineEntry(REL, "file", 5, 1.0, 5, 1.0, "")}
    assert decider._decide_file(REL, {}, {}, base) == Op.DROP_BASELINE


def test_changed_local_orphan_is_rescued_not_deleted(decider):
    # The safety counterpart: a LOCAL edit after the remote was deleted re-uploads, never
    # deletes the just-edited file.
    base = {REL: BaselineEntry(REL, "file", 5, 1.0, 5, 1.0, "")}
    local = {REL: LocalEntry(REL, "file", 99, 5000.0)}  # changed vs baseline
    assert decider._decide_file(REL, local, {}, base) == Op.RESCUE_UPLOAD
