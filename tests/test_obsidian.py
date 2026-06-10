"""Obsidian taxonomy: the ignore matcher plus the 'assets sync, config local' rule
(AT-01 theme persistence, AT-02 plugin code propagation, AT-03 volatile config ignored).
"""

from __future__ import annotations

from ifolder_sync.syncer import path_is_ignored

from .helpers import write_file


def _ign(pattern, relpath):
    return path_is_ignored(pattern, relpath.split("/"))


def test_ignore_matcher():
    must_ignore = [
        # Obsidian volatile config (per-device) at root and nested depth
        (".obsidian/workspace.json", ".obsidian/workspace.json"),
        (".obsidian/workspace.json", "notes/sub/.obsidian/workspace.json"),
        (".obsidian/appearance.json", ".obsidian/appearance.json"),
        (".obsidian/app.json", ".obsidian/app.json"),
        (".obsidian/community-plugins.json", ".obsidian/community-plugins.json"),
        # cache: the item AND (if a folder) everything below it, at any depth
        (".obsidian/cache", ".obsidian/cache"),
        (".obsidian/cache", "vault/.obsidian/cache/blob.bin"),
        # simple names match in any segment
        (".DS_Store", "a/b/.DS_Store"),
        ("*.icloud", "a/b/file.icloud"),
        ("*.conflict-*", "c.conflict-20260101-000000.txt"),
    ]
    for pat, rel in must_ignore:
        assert _ign(pat, rel), f"should IGNORE {rel!r} via {pat!r}"

    must_keep = [
        (".obsidian/appearance.json", ".obsidian/plugins/foo/main.js"),  # plugin code
        (".obsidian/workspace.json", ".obsidian/app.json"),  # other config
        (".obsidian/community-plugins.json", ".obsidian/plugins/calendar/data.json"),
        ("*.icloud", "notes/icloud.md"),  # not a .icloud
    ]
    for pat, rel in must_keep:
        assert not _ign(pat, rel), f"should NOT ignore {rel!r} via {pat!r}"


def test_volatile_config_not_synced(make_syncer, fake, local_dir):
    """appearance.json differs on each side; neither overwrites the other (no revert)."""
    syncer, store = make_syncer(obsidian=True)
    write_file(local_dir, ".obsidian/appearance.json", b'{"cssTheme":"Minimal"}', mtime=1000)
    fake.put(".obsidian/appearance.json", b'{"cssTheme":"Default"}', mtime=2000)

    syncer.sync_once()

    assert (local_dir / ".obsidian/appearance.json").read_bytes() == b'{"cssTheme":"Minimal"}'
    assert fake.files[".obsidian/appearance.json"]["content"] == b'{"cssTheme":"Default"}'
    assert not list((local_dir / ".obsidian").glob("appearance.conflict-*"))
    store.close()


def test_plugin_code_syncs_but_enabled_list_does_not(make_syncer, fake, local_dir):
    syncer, store = make_syncer(obsidian=True)
    fake.put(".obsidian/plugins/foo/main.js", b"code", mtime=2000)
    fake.put(".obsidian/community-plugins.json", b'["foo"]', mtime=2000)

    syncer.sync_once()

    assert (local_dir / ".obsidian/plugins/foo/main.js").read_bytes() == b"code"
    assert not (local_dir / ".obsidian/community-plugins.json").exists()
    store.close()


def test_obsidian_off_syncs_config(make_syncer, fake, local_dir):
    """With obsidian=False (default), .obsidian config is not special -- it syncs."""
    syncer, store = make_syncer(obsidian=False)
    fake.put(".obsidian/appearance.json", b'{"cssTheme":"X"}', mtime=2000)

    syncer.sync_once()

    assert (local_dir / ".obsidian/appearance.json").read_bytes() == b'{"cssTheme":"X"}'
    store.close()
