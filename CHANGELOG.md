# Changelog

All notable changes to ifolder-sync are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may
carry behavior changes).

## [Unreleased]

### Added
- **Live status dashboard — `ifolder-sync status --watch`.** A redrawing dashboard of the
  daemon's in-flight transfers, the full pending queue, recently-synced files, and any path
  re-syncing in a loop (flapping), with a compact multi-profile overview when no `--profile`
  is given. It is read-only and network-free: it polls an atomic `status.json` snapshot the
  daemon (and a foreground `sync`) writes — gated by the new `inflight_surface` (default on),
  coalesced by `inflight_min_write_interval_ms` (default 200), and redrawn every
  `dashboard_interval_seconds` (default 1.0, `--interval` overrides). The optional `rich`
  extra (`pip install "ifolder-sync[dashboard]"`) upgrades the frame; without it a plain ANSI
  frame is used.
- **Sync doctor — `ifolder-sync doctor`.** A read-only consistency audit (the decide phase of
  a sync pass with no apply, via `Syncer.plan()`): it reports orphan baseline rows, would-be
  conflicts, unsettled/pending paths, and the planned upload/download/delete tallies without
  changing any local, remote, or baseline state. `doctor --fix-orphans` is the one opt-in
  write — it drops only the provably-orphan baseline rows after backing up the baseline and
  clearing the stale walk cache, holding the single-instance lock (so it refuses while the
  daemon is running). Both accept `--json` (schema 1) and `--non-interactive`.
- **Modern launchd control plane** for the lifecycle commands. `start --background`, `stop`,
  `restart`, and `uninstall` drive launchd through the modern domain-target verbs
  (`bootout`/`enable`/`bootstrap`/`kickstart -k` against `gui/<uid>/com.ifolder-sync.<profile>`)
  instead of the legacy `load`/`unload`, and each **verifies its post-condition** (polls
  `launchctl print` until the daemon is really up/down) before reporting success — no more
  false "started"/"stopped".
  - **`ifolder-sync restart`** is a new first-class, atomic verb (not `stop && start`): it
    converges the job (regenerate plist → `bootout` → settle → `enable` → `bootstrap` →
    `kickstart -k`) and verifies it came back up, so a restart never ends with the daemon
    stopped. It accepts `--background` for symmetry with `start`.
  - **`ifolder-sync uninstall`** stops the job (idempotent) and removes its LaunchAgent
    `.plist`, leaving config/baseline/vault untouched.
  - New tunables: `throttle_interval_seconds` (the plist `ThrottleInterval`) and
    `lifecycle_verify_timeout_seconds` (the post-condition verify bound).

### Changed
- **Lazy, bounded Keychain auth.** The daemon now validates its saved trust token **first**
  and reads the password from the macOS Keychain only when a real SRP login is needed, with a
  **bounded read** (`keyring_timeout_seconds`, default 10.0s). Under launchd a venv Python is
  ad-hoc signed, so a non-interactive Keychain authorization cannot be auto-granted and the
  read could block forever (once observed wedging the daemon ~17h); the bound turns that hang
  into a clean auth error and a tidy stop. Interactive reads stay unbounded.
- **Idle sync passes are much cheaper (~9x).** When nothing has changed, the engine no longer
  rewrites every baseline row with identical values — the SQLite baseline skips a byte-identical
  write (and its commit), so a steady-state pass over a large vault drops from ~1.5s to ~0.17s. A
  *real* change still writes and commits per-action exactly as before (crash-safety unchanged).
- **Faster ignore matching on every sync pass.** The `ignore` patterns are now compiled to
  regex once when the engine starts, instead of re-running `fnmatch` for every pattern on every
  scanned path (local + remote walk + the file watcher). ~3.6x faster on the matching loop —
  meaningful on large vaults. Matching is byte-identical (including `*.part` case-sensitivity).
- **Cheap commands fail faster.** The global exit-code classifier no longer imports `pyicloud`
  (~1.8s) unconditionally — it only consults the pyicloud/engine exception types when those
  modules are already loaded. A `status`/`stop`/`restart` that errors with a plain `OSError` now
  reports its exit code without paying that import. Exit-code mapping is unchanged.
- **Cheaper baseline commits.** The SQLite baseline now runs `synchronous=NORMAL` under WAL, so
  each per-op commit is a WAL append instead of a full fsync (~2-3x cheaper; ~60-180ms saved on a
  full-vault bootstrap). Still crash-safe (durable against app/OS crash; only a power loss could
  drop the last txn).
- **`start --background` no longer pays the heavy daemon import.** `cmd_start` only imports the
  sync engine (`.daemon`, which transitively pulls `pyicloud` + `watchdog`, ~1.8s) on the
  foreground path that actually runs it; the `--background` path hands off to launchd and
  returns, so the eager import was pure waste (~0.6s CPU / ~1.5s wall per `start --background`).
  Moved the import past the `--background` early-return.
- **`start --background` and `restart` are much faster (~70s → ~20s).** launchd throttles a
  job's respawn by its plist `ThrottleInterval`, and `start`/`restart` wait for that throttled
  spawn before reporting success (so a real failure isn't masked). The interval was a hardcoded
  60s; it is now the configurable `throttle_interval_seconds` (default **15**, down from 60).
  Lower = snappier start/restart and faster crash-recovery; raise it for more conservative
  crash-loop spacing. The value is single-sourced into both the launchd plist and the verify
  wait. (Takes effect on the next `start`/`restart`, which regenerates the plist.)
- **Single-instance lock now uses a kernel advisory lock (`fcntl.flock`)** instead of a
  PID file with a `kern.boottime` stale-reclaim heuristic. The lock is held on a file
  descriptor kept open for the daemon's whole lifetime, and the kernel releases it
  automatically on **any** exit — clean shutdown, crash, or `SIGKILL`. This retires the
  PID-liveness probe and the boot-time drift band (`_BOOT_TOL`) entirely: no more false
  "stale" reclaim and no boot-time-drift false "stopped". The PID in the lock file is now a
  human-readable label only — never a liveness decision (flock acquirability is the
  authority). Public API (`SingleInstanceLock`, `AlreadyRunning`, `holder_pid`) is unchanged.

  **Upgrade note (required action):** **stop or restart the daemon** as part of this
  upgrade — run `ifolder-sync restart` (or `stop` then `start`) for every active profile
  (`--profile …`). A daemon started by the previous version holds the lock file *without* a
  kernel `flock`, so a new-code process cannot see it and would wrongly consider the lock
  free — risking two writers on one baseline. Restarting replaces the old process with one
  that takes the kernel lock; this is a one-time action at upgrade. (The lock file must live
  on a local filesystem; `flock` is unreliable over NFS/SMB.)

## [0.13.0] - 2026-06-15

Engine-safety fix for iCloud's publish-before-content propagation lag, plus the Obsidian
plugin-state exclusion that the lag made necessary.

### Fixed
- **iCloud publish-before-content lag no longer errors or clobbers.** A remote whose
  record lists size N > 0 but whose body fetches as 0 bytes (transient propagation lag,
  typically a file an iPhone just rewrote) now raises a typed `UnreadableRemoteError` and
  is **deferred** — counted as `pending`, never an error, the baseline left untouched —
  and retried each pass. A conflict is **never** resolved against an unreadable remote
  (the resolver probes readability first, for every policy). Only after
  `unreadable_max_passes` against an unchanged remote signature is the blob judged a
  genuine empty husk and the good local side allowed to win (one warning). This removes
  the v0.10.2 "resolve without backup" heal path, which was a data-loss clobber of an
  in-flight edit from another device.
- Partial reads (`0 < got < N`) remain a transient, retried `OSError` — not silenced.

### Changed
- **`.obsidian/plugins/*/data.json` is now excluded from sync** under `obsidian: true`.
  These per-plugin state files are rewritten on nearly every app launch (especially on
  mobile) and are the chief victim of the lag above; `manifest.json`, the plugin code, and
  `.obsidian/types.json` still sync. *(Behavior change: a plugin `data.json` that synced
  before will stop syncing.)*

### Added
- `unreadable_max_passes` config option (default `20`): the sustained-failure window
  before an unreadable remote blob is treated as genuine corruption. Distinct from
  `settle_max_passes` (which governs 0-byte husks); intentionally long so a slow-
  propagating real edit is never mistaken for corruption.

### Tests
- 255 → 264 tests: unreadable-remote defer/never-clobber, conflict readability probe,
  sustained-escalation one-warning, fast-churn no-false-corruption, partial-read still
  transient, and the `plugins/*/data.json` ignore matrix. Coverage ~79%.

### Docs
- New **[docs/ADVANCED_USAGE.md](docs/ADVANCED_USAGE.md)**: complete configuration
  reference (every option), worked example configs, and a conflicts & recovery playbook.
- README: corrected the `full_walk_interval_seconds` default (600 → 3600); documented the
  propagation-lag / unreadable-remote handling under Safety & resilience; refreshed the
  Obsidian `data.json` behavior; fixed the dev `black` → `ruff format` command.
- ARCHITECTURE: propagation-lag guards in the safety model; `errors.py` on the component map.

## [0.12.0] - 2026-06-12

Phase E — CLI/UX surface and test debt. User-visible additions (exit codes, `--json`, shell
completion, friendlier prompts) plus a large coverage expansion (163 → 255 tests).

### Added
- **Exit-code taxonomy** so scripts/monitoring can tell *why* a command ended: `0` ok,
  `2` usage, `3` auth-required, `4` scan-guard abort, `5` vault-identity mismatch,
  `6` deletions suppressed by the safety threshold, `7` sync ran but some file ops failed,
  `130` interrupted. Documented in `--help`. (`sync` no longer exits `0` when every upload
  failed.)
- **`--json`** for `status` and `sync`: machine-readable JSON to stdout, human/diagnostic
  text to stderr — for menu-bar / Raycast / Obsidian-plugin integrations.
- **Shell completion** via the optional `shtab` dependency:
  `ifolder-sync --print-completion zsh|bash` (install `ifolder-sync[completion]`).
- **First-sync feedback** (`Connecting…` / `Scanning…`) on a TTY so the slow bootstrap is
  visible; never on stdout, so `--json` stays pure.

### Changed
- `init` re-prompts on a bad value — a typo like `60s` for the interval no longer discards
  the whole interview.
- `purge-trash` confirms before emptying the soft-delete trash (`-y`/`--yes` to skip; a
  non-interactive run without `--yes` refuses rather than silently deleting the safety net).
- `main()` catches `PyiCloudException` (a 503/429 prints one clean line, not a multi-screen
  traceback; `-v` re-raises). A rejected/absent password or a cancelled 2FA now exits `3`
  consistently. `Ctrl-D` at a prompt exits cleanly instead of dumping a traceback.
- The launchd agent runs `start … --launchd`, keeping deliberate stops at exit `0`
  (invariant 9); its program prefers a stable PATH shim *outside* the venv, else
  `python -m ifolder_sync`, so login auto-start survives a venv rebuild / upgrade.
- `NO_COLOR` is honored.

### Tests
- 163 → 255 tests: conflict-policy matrix (all four policies + the `newer` remote-wins
  backup + the 0-byte guard), the delete-threshold pct branch and drift escalation/reset,
  `MTIME_TOL` boundaries, property-based decide-table invariants (hypothesis — never deletes
  without a baseline; unchanged orphans are deleted), the plist asserted **by value**
  (invariant-9 `SuccessfulExit=false`), the daemon clean-stop lifecycle, and runtime
  `SyncClient` Protocol conformance. CI coverage gate raised 65% → 75% (currently ~79%).

## [0.11.0] - 2026-06-11

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

[Unreleased]: https://github.com/zanonicode/ifolder-sync/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.13.0
[0.12.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.12.0
[0.11.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.11.0
[0.10.3]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.3
[0.10.2]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.2
[0.10.1]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.1
[0.10.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.10.0
[0.9.0]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.9.0
[0.8.2]: https://github.com/zanonicode/ifolder-sync/releases/tag/v0.8.2
