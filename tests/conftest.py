"""Pytest fixtures shared across the suite."""

from __future__ import annotations

import pytest

from ifolder_sync.config import Config
from ifolder_sync.state import StateStore
from ifolder_sync.syncer import Syncer

from .helpers import PERMISSIVE_THRESHOLDS, FakeICloud


@pytest.fixture
def fake():
    return FakeICloud()


@pytest.fixture
def local_dir(tmp_path):
    d = tmp_path / "local"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def make_syncer(tmp_path, fake, local_dir):
    """Build a Syncer wired to the fake client. Delete thresholds default to
    permissive so plain-sync tests are not suppressed; threshold tests override them."""

    def _make(policy="newer", **cfg_kw):
        defaults = dict(PERMISSIVE_THRESHOLDS)
        defaults.update(cfg_kw)
        cfg = Config(
            apple_id="x@y.com",
            remote_folder="",
            local_folder=str(local_dir),
            conflict_policy=policy,
            **defaults,
        )
        store = StateStore(tmp_path / "state.sqlite3")
        syncer = Syncer(cfg, fake, store, trash_dir=tmp_path / "trash")
        return syncer, store

    return _make
