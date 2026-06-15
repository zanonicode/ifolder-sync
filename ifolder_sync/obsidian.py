"""Obsidian vault sync profile.

Classifies paths under ``.obsidian/`` as per-device/ephemeral config (never synced)
or shared assets (synced normally). Every device rewrites the volatile config, so
syncing it makes a theme set on one device revert on another and leaves the enabled
plugin list incoherent. Excluding these paths on both sides fixes that while still
propagating plugin code, themes, and snippets.
"""

from __future__ import annotations

# Per-device or ephemeral: rewritten by each device -> conflicts if synced.
# Matched at any depth by the ignore engine (see path_is_ignored in syncer.py).
OBSIDIAN_VOLATILE: tuple[str, ...] = (
    ".obsidian/workspace.json",  # desktop pane layout
    ".obsidian/workspace-mobile.json",  # mobile pane layout
    ".obsidian/appearance.json",  # active theme + UI (the theme-revert culprit)
    ".obsidian/app.json",  # core editor settings
    ".obsidian/core-plugins.json",  # enabled core plugins
    ".obsidian/community-plugins.json",  # enabled community plugins
    ".obsidian/hotkeys.json",  # keybindings
    ".obsidian/cache",  # link/metadata cache (whole subtree)
    ".obsidian/graph.json",  # graph view state
    # Per-plugin settings/state. Like community-plugins.json above (the enabled-plugin list,
    # already volatile), a plugin's data.json is per-device: plugins rewrite it on nearly every
    # app launch -- especially on mobile -- so syncing it produces constant conflicts and it is
    # the main victim of iCloud's publish-before-content lag. manifest.json and the plugin code
    # (main.js/styles.css) still sync, so a plugin a device enables still has working files.
    ".obsidian/plugins/*/data.json",  # per-plugin settings (per-device, churn/lag-prone)
)

# Shared assets under .obsidian/ (plugins/, themes/, snippets/, icons/, plugin code)
# are intentionally absent here so they sync and stay consistent across devices.
