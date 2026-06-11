"""Phase D regression anchors (refactor + perf, no behavior change).

D2: download mtime restore (P2-6), the _is_safe_rel cached-root realpath + symlink
escape (P2-3), SyncClient Protocol conformance (P3-6).
D3: max_file_size_mb upload guard + snapshot mtime preservation (P2-4), and the
extracted twofa helpers (P3-4).
D4: shared vault-access TCC hint (P3-5), watcher ignore-filtering (P2-1), and the
~/Library/Logs log location (P2-5).
D5: config hygiene (P3-7) and the walk-cache persistence + 3600 cadence (P2-2). The
lock PID-reuse hardening (P2-7) lives in tests/test_safety.py.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from ifolder_sync import twofa
from ifolder_sync.config import Config, log_file, vault_access_error
from ifolder_sync.icloud_client import ICloudClient
from ifolder_sync.syncer import SyncClient
from ifolder_sync.watcher import _DebouncedHandler

from .helpers import write_file


# --------------------------------------------------------------- P2-6 mtime ---
def test_download_restores_remote_mtime(make_syncer, fake, local_dir):
    """A downloaded file carries the REMOTE mtime, not the download instant — so
    Obsidian recent-files and Dataview `file.mtime` show the real edit time vault-wide,
    and the baseline records that value so the next pass is a no-op (no phantom change)."""
    syncer, store = make_syncer()
    fake.put("note.md", b"# hello", mtime=1_234_567.0)

    s = syncer.sync_once()
    p = local_dir / "note.md"
    assert s.downloaded == 1, s.summary()
    assert p.read_bytes() == b"# hello"
    assert p.stat().st_mtime == pytest.approx(1_234_567.0, abs=1e-4)

    s2 = syncer.sync_once()
    assert s2.uploaded == 0 and s2.downloaded == 0, s2.summary()
    store.close()


def test_download_zero_remote_mtime_is_not_stamped_to_epoch(make_syncer, fake, local_dir):
    """A 0/unknown remote mtime is left as the download time, never stamped to the
    1970 epoch (which would read as an ancient file across the vault)."""
    syncer, store = make_syncer()
    fake.put("z.md", b"x", mtime=0.0)

    syncer.sync_once()
    assert (local_dir / "z.md").stat().st_mtime > 1_000_000_000  # not 1970
    store.close()


# ------------------------------------------------- P2-3 cached-root realpath ---
def test_is_safe_rel_semantics_unchanged(make_syncer):
    """Caching the resolved root must not weaken invariant 5: contained paths stay safe,
    traversal and absolute paths stay unsafe, and a '..' that cancels back inside still
    resolves to contained."""
    syncer, store = make_syncer()
    assert syncer._is_safe_rel("Obsidian/note.md")
    assert syncer._is_safe_rel("a/../b.md")  # '..' cancels -> resolves inside
    assert not syncer._is_safe_rel("../outside.md")
    assert not syncer._is_safe_rel("/abs/outside.md")
    store.close()


def test_unsafe_remote_path_is_excluded_from_scan(make_syncer, fake):
    """End to end: an escaping remote relpath is dropped from the remote snapshot rather
    than written outside the vault."""
    syncer, store = make_syncer()
    fake.put("safe.md", b"ok", mtime=1000.0)
    fake.put("../escape.md", b"evil", mtime=1000.0)
    remote = syncer._scan_remote()
    assert "safe.md" in remote
    assert "../escape.md" not in remote
    store.close()


def test_remote_path_through_symlinked_subdir_is_excluded(make_syncer, fake, local_dir, tmp_path):
    """invariant 5, the case a purely-lexical check would miss: a remote relpath whose
    parent is a symlinked vault subdir pointing OUTSIDE the vault must be rejected by
    _scan_remote (resolve() follows the symlink and sees it escape), so a download can
    never write remote-controlled bytes outside local_root."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (local_dir / "link").symlink_to(outside, target_is_directory=True)

    syncer, store = make_syncer()
    fake.put("link/escape.md", b"PWNED", mtime=1000.0)
    fake.put("kept.md", b"ok", mtime=1000.0)
    remote = syncer._scan_remote()

    assert "kept.md" in remote
    assert "link/escape.md" not in remote
    syncer.sync_once()
    assert not (outside / "escape.md").exists(), "must never write through the symlink"
    store.close()


# ------------------------------------------------------- P2-4 upload guard ---
def test_max_file_size_skips_oversize_upload(make_syncer, fake, local_dir):
    """An over-limit local file is skipped (pyicloud buffers it whole in RAM); a small
    sibling still uploads, and the skip is counted as an error."""
    syncer, store = make_syncer(max_file_size_mb=1)
    write_file(local_dir, "big.bin", b"x" * (2 * 1024 * 1024), mtime=1000)
    write_file(local_dir, "small.md", b"ok", mtime=1000)

    s = syncer.sync_once()
    assert "big.bin" not in fake.files
    assert fake.files["small.md"]["content"] == b"ok"
    assert s.errors >= 1, s.summary()
    store.close()


def test_max_file_size_zero_is_unlimited(make_syncer, fake, local_dir):
    """The default (0) imposes no limit, so a large file still uploads."""
    syncer, store = make_syncer()  # max_file_size_mb defaults to 0
    write_file(local_dir, "big.bin", b"x" * (2 * 1024 * 1024), mtime=1000)
    syncer.sync_once()
    assert "big.bin" in fake.files
    store.close()


def test_upload_snapshot_preserves_mtime(make_syncer, fake, local_dir):
    """The snapshot (APFS clonefile or copy2 fallback) preserves the source mtime, so the
    remote mtime equals the local mtime (invariant 6) and the next pass is a no-op."""
    syncer, store = make_syncer()
    write_file(local_dir, "m.md", b"content", mtime=7000)
    s = syncer.sync_once()
    assert s.uploaded == 1, s.summary()
    assert fake.files["m.md"]["mtime"] == pytest.approx(7000, abs=1e-4)
    s2 = syncer.sync_once()
    assert s2.uploaded == 0 and s2.downloaded == 0, s2.summary()
    store.close()


# ------------------------------------------------------------ P3-4 twofa ---
def test_twofa_extract_phone_numbers_recursive_and_deduped():
    """The extracted pure helper finds trustedPhoneNumbers at any nesting (Apple moved
    it under bridgeInitiateData in 2026), dedups by id keeping the first, and falls back
    to a synthetic label. Now trivially unit-testable as a module function."""
    data = {
        "a": {
            "bridgeInitiateData": {
                "trustedPhoneNumbers": [
                    {"id": 1, "numberWithDialCode": "+1 (...) ...-1234"},
                    {"id": 2, "obfuscatedNumber": "...-5678"},
                ]
            }
        },
        "b": {"trustedPhoneNumbers": [{"id": 1, "numberWithDialCode": "dup"}]},
        "c": [{"trustedPhoneNumbers": [{"id": 3}]}],
    }
    out = twofa._extract_phone_numbers(data)
    assert [p["id"] for p in out] == [1, 2, 3]  # id 1 deduped, order preserved
    labels = {p["id"]: p["label"] for p in out}
    assert labels[1] == "+1 (...) ...-1234"
    assert labels[2] == "...-5678"
    assert labels[3] == "phone #3"  # neither field present -> fallback


def test_twofa_extract_phone_numbers_tolerates_garbage():
    assert twofa._extract_phone_numbers({}) == []
    assert twofa._extract_phone_numbers([]) == []
    assert twofa._extract_phone_numbers("nonsense") == []
    assert twofa._extract_phone_numbers({"trustedPhoneNumbers": ["not-a-dict"]}) == []


def test_print_diagnostics_delegator_handles_no_connection(capsys):
    """The thin ICloudClient.print_diagnostics delegator forwards to twofa and the
    api-is-None guard still prints the no-connection notice (cli `status` relies on it)."""
    ICloudClient("x@y.com").print_diagnostics()
    assert "(no connection)" in capsys.readouterr().out


# ------------------------------------------------- P3-5 shared access hint ---
def test_vault_access_error_adds_tcc_hint_only_when_relevant(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    protected = tmp_path / "Downloads" / "vault"
    safe = tmp_path / "vaults" / "obs"
    perm = PermissionError(13, "Permission denied")

    assert "TCC" in vault_access_error(protected, perm)  # protected + permission -> hint
    assert "TCC" not in vault_access_error(safe, perm)  # outside protected -> no hint
    assert "TCC" not in vault_access_error(protected, FileNotFoundError(2, "missing"))


# --------------------------------------------------- P2-1 watcher filtering ---
def _handler(root, is_ignored):
    return _DebouncedHandler(lambda: None, 0.1, root, is_ignored)


def test_watcher_suppresses_only_all_ignored_events(tmp_path):
    ignored = lambda rel: rel.endswith(".part") or rel == ".obsidian/workspace.json"  # noqa: E731
    h = _handler(tmp_path, ignored)

    def ev(src, dest=None):
        return SimpleNamespace(
            src_path=str(tmp_path / src), **({"dest_path": str(tmp_path / dest)} if dest else {})
        )

    assert h._all_ignored(ev(".obsidian/workspace.json"))  # volatile -> suppress
    assert h._all_ignored(ev("note.md.part"))  # download tempfile -> suppress
    assert not h._all_ignored(ev("note.md"))  # real edit -> wake
    # a move out of an ignored file INTO a watched one must still wake
    assert not h._all_ignored(ev(".obsidian/workspace.json", dest="note.md"))


def test_watcher_no_filter_when_predicate_absent(tmp_path):
    h = _handler(tmp_path, None)
    assert not h._all_ignored(SimpleNamespace(src_path=str(tmp_path / "anything.part")))


def test_watcher_does_not_suppress_path_outside_root(tmp_path):
    h = _handler(tmp_path, lambda rel: True)  # would suppress everything classifiable
    assert not h._all_ignored(SimpleNamespace(src_path="/etc/passwd"))  # unclassifiable -> wake


# ------------------------------------------------------- P2-5 log location ---
def test_log_file_is_under_library_logs(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    p = log_file("work")
    assert p == tmp_path / "Library" / "Logs" / "ifolder-sync" / "work.log"
    assert not p.parent.exists()  # read-only helper: no mkdir side effect


# --------------------------------------------------------- P3-7 config hygiene ---
def test_config_load_warns_on_unknown_keys(tmp_path, caplog):
    """A typo'd key is dropped (as before) but now warned about instead of silently
    swallowed; known keys still load."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"apple_id": "a@b.com", "local_folder": "/x", "intervall_seconds": 99}))
    with caplog.at_level("WARNING"):
        cfg = Config.load(p)
    assert not hasattr(cfg, "intervall_seconds")
    assert "intervall_seconds" in caplog.text
    assert cfg.apple_id == "a@b.com" and cfg.local_folder == "/x"


def test_config_validate_rejects_bool_and_non_numbers():
    base = dict(apple_id="a@b.com", local_folder="/x")
    with pytest.raises(ValueError):
        Config(**base, walk_workers=True).validate()  # bool is not an int
    with pytest.raises(ValueError):
        Config(**base, retry_base_delay="fast").validate()  # not a number
    with pytest.raises(ValueError):
        Config(**base, debounce_seconds=True).validate()  # bool is not a number
    Config(**base, retry_base_delay=2, debounce_seconds=1.5).validate()  # int/float OK


# ------------------------------------------------------- P2-2 walk cache ---
def test_full_walk_interval_default_raised_to_3600():
    assert Config().full_walk_interval_seconds == 3600


def test_walk_cache_export_import_roundtrip_and_tolerates_garbage():
    c = ICloudClient("x@y.com")
    assert c.export_walk_cache() is None  # empty cache -> nothing to persist
    c._etag_cache = {"": "root-etag", "sub": "sub-etag"}
    c._children_cache = {"": [], "sub": []}
    blob = c.export_walk_cache()

    c2 = ICloudClient("x@y.com")
    c2.import_walk_cache(blob)
    assert c2._etag_cache == {"": "root-etag", "sub": "sub-etag"}
    assert c2._last_full_walk > 0  # restored cache is eligible immediately

    c2.import_walk_cache("not json{")  # corrupt JSON -> ignored
    c2.import_walk_cache(None)  # absent -> ignored
    c2.import_walk_cache(json.dumps(["not", "a", "dict"]))  # wrong top-level shape
    c2.import_walk_cache(
        json.dumps({"etags": {"": "e"}, "children": [["x"]]})
    )  # children not a dict
    c2.import_walk_cache(
        json.dumps({"etags": {"": "e"}, "children": {"": [["a", "b"]]}})
    )  # bad arity
    assert c2._etag_cache == {"": "root-etag", "sub": "sub-etag"}  # all ignored, cache intact


# ----------------------------------------------------- P3-6 SyncClient proto ---
def test_syncclient_protocol_conformance(fake):
    """The runtime-checkable Protocol is the contract both the real client and the test
    fake honor; a partial stub does not."""
    assert isinstance(fake, SyncClient)
    assert isinstance(ICloudClient("x@y.com"), SyncClient)

    class Partial:
        def refresh(self) -> None: ...

    assert not isinstance(Partial(), SyncClient)
