# Changelog

All notable changes to ifolder-sync are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may
carry behavior changes).

## [Unreleased]

Phase D — refactor & performance, no behavior change beyond the items called out below.

### Added
- `max_file_size_mb` config option: skip uploading a file too large to buffer in memory
  (pyicloud builds the whole multipart body in RAM). Default `0` = no limit.
- The walk etag cache is persisted across restarts, so a restart skips the uncached full
  walk; the cadence (`full_walk_interval_seconds`) default rose from 600 to 3600 with a
  small per-instance jitter.
- `SyncClient` Protocol typing the engine's iCloud surface; `py.typed` marker so the
  package ships its inline types; `CHANGELOG.md`; a pre-commit config; a committed
  `uv.lock`.

### Changed
- Downloaded files now keep the **remote** modification time (was the download instant),
  fixing Obsidian recent-files / Dataview `file.mtime` across devices.
- The daemon log moved to `~/Library/Logs/ifolder-sync/<profile>.log` (Console.app-
  discoverable) with size-bounded rotation; no-op passes log at DEBUG with an hourly INFO
  heartbeat. The launchd `daemon.err.log` is now only a crash capture.
- The local watcher ignores events for engine-ignored paths (volatile `.obsidian`
  configs, `*.part`), so Obsidian's churn no longer triggers no-op passes.
- The single-instance lock records the boot time, so a stale lock left by a previous boot
  (whose PID may have been recycled) no longer blocks startup.
- Config load warns on unknown keys (typos were dropped silently); validation rejects a
  bool where an integer is expected and validates float options.
- Internal: the engine's per-path actions are a typed `Op` enum with an exhaustive apply
  dispatch; the interactive 2FA/2SA terminal flow moved to `ifolder_sync/twofa.py`; the
  upload snapshot uses an APFS clonefile (`cp -c`); the vault-root access hint is shared
  between the daemon preflight and the syncer scan guard.

## [0.10.3] - 2026-06-11

### Fixed
- Daemon self-heals a lapsed iCloud login token (HTTP 421 `LOGIN_TOKEN_EXPIRED`, surfaced
  as a generic API error): it reconnects in place (bounded by `max_session_reconnects` /
  `min_reconnect_interval_seconds`) instead of looping every poll. `status` no longer
  reports a healthy session while sync is dead.

## [0.10.2] - 2026-06-11

### Fixed
- A broken remote blob in active conflict no longer loops: `_backup_remote_then` shares the
  download-failure backoff, resolving without a backup after repeated failures so the good
  local copy can win and heal the remote.

## [0.10.1] - 2026-06-11

### Fixed
- Per-file download backoff for a broken iCloud blob (HTTP 200 + a content-length that
  exceeds the bytes actually served): after repeated failures against an unchanged remote,
  stop re-attempting (and writing a `.part` that re-triggers the watcher) until it changes.

## [0.10.0] - 2026-06-11

### Changed
- Engine-safety hardening (18 items across six reviewed batches): NFC filename identity on
  both boundaries, content-verified adopt-identical, per-side mtime tolerance, empty-side-
  never-wins conflict invariant, kind-conflict and case-collision exclusion, settle
  escalation, atomic 0600 session writes, download size verification, WAL + per-action
  commits, corrupt-baseline clean stop, and a directory-deletion baseline guard.

## [0.9.0] - 2026-06-10

### Changed
- pyicloud floor raised to `>=2.6.5,<3` (canonical `timlaing/pyicloud` fork; older versions
  cannot authenticate modern accounts); Python floor raised to `>=3.10`. Added a weekly
  pyicloud canary to CI.

## [0.8.2] - 2026-06-10

### Fixed
- Packaging: `dependencies` were nested under `[project.urls]`, so a fresh `pip install`
  installed no dependencies. Moved into `[project]`, added an SPDX license and a CI build
  gate (build + install across Python 3.10–3.14, ruff + mypy + pytest).

[Unreleased]: https://github.com/zanonicode/ifolder-sync/compare/v0.10.3...HEAD
[0.10.3]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.3
[0.10.2]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.2
[0.10.1]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.1
[0.10.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.0
[0.9.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.9.0
[0.8.2]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.8.2
