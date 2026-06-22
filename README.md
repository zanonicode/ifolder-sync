# ifolder-sync

[![CI](https://github.com/zanonicode/ifolder-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/zanonicode/ifolder-sync/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **macOS** CLI daemon that **bidirectionally** syncs one folder of a **specific
iCloud Drive account** (not necessarily the one signed into the Mac) with a local
folder — **every X seconds** (remote polling) **and on every local change** (real-time
FSEvents watcher). Built for an **Obsidian vault**, with safe handling of the
`.obsidian/` config folder.

> Imagine you're on a Mac signed into one user account, and you'd really like a
> *single specific folder* from a **different iCloud account** to stay in sync right
> there — without signing that whole account in, creating another macOS user, or
> syncing its entire iCloud Drive. That's the itch ifolder-sync was built to scratch.

> [!WARNING]
> **Read before using.**
>
> - This is **not** an official Obsidian plugin. It is not affiliated with, endorsed
>   or reviewed by the Obsidian team (nor by Apple).
> - This daemon is **alpha software**, built for the author's personal use, and has
>   **not been widely validated**.
> - **Do not point it at a vault you don't have a full backup of.** Bidirectional
>   sync over a reverse-engineered API can fail in unforeseen ways; there is no way
>   to guarantee a sync will never misbehave, so **there are no guarantees of any
>   kind** (see the MIT license).
> - **Use at your own risk.**
>
> That said, the engine is built defensively: soft-delete trash on both sides,
> `--dry-run` previews, a mass-deletion threshold, and abort-on-partial-visibility
> guards — see [Safety & resilience](#safety--resilience).

## Requirements

- **macOS** (developed and tested on macOS 26 only; earlier versions untested).
- **Python ≥ 3.10** — the macOS system Python (3.9) is too old; install one with
  [Homebrew](https://brew.sh) (`brew install python`) or pyenv.
- An **Apple ID you control**, with two-factor authentication and its **primary
  password** (app-specific passwords do not work — see [Password](#password)).

## Install

Not yet published on PyPI — install from source:

```bash
git clone https://github.com/zanonicode/ifolder-sync.git
cd ifolder-sync
python3.13 -m venv .venv          # any Python >= 3.10
source .venv/bin/activate
pip install -e .
# for development (tests, lint, format, types):
pip install -e ".[dev]"
```

Or with [uv](https://docs.astral.sh/uv/) (a committed `uv.lock` pins exact versions):

```bash
uv sync --extra dev      # create .venv and install from the lockfile
uv run ifolder-sync --help
# or install the CLI standalone:  uv tool install .
```

## Quick start

Three commands after installing:

```bash
ifolder-sync init --obsidian   # interactive setup: Apple ID, iCloud folder, local folder
                               # (drop --obsidian if the folder is not an Obsidian vault)
ifolder-sync auth              # log into that iCloud account — one-time 2FA, then the
                               # session is trusted (~90 days observed)
ifolder-sync start --background
```

That's it — **set it up once and forget it**. The last command hands the daemon to
**launchd**, macOS's own service manager, so it now **survives logouts, reboots and
crashes** on its own: it starts at every login (`RunAtLoad`), gets restarted if it ever
crashes (`KeepAlive`), and there is no extra "add to startup" step. The only thing that
turns it off is you: `ifolder-sync stop`.

```bash
ifolder-sync status            # is it running? session valid? when was the last sync?
ifolder-sync logs -f           # watch it work in real time
ifolder-sync stop              # stop it (also disables the automatic start at login)
```

> **Where to put the vault:** not under `~/Downloads`, `~/Desktop` or `~/Documents` —
> macOS privacy protection (TCC) blocks background daemons from reading those folders.
> Use something like `~/vaults/<name>`.

## Why this is not trivial

macOS only natively syncs the iCloud Drive of the **Apple ID signed into the system**.
There is no way to locally mount the Drive of a *second* account. So this project
reaches the other account through the **unofficial iCloud web API**, via
[`pyicloud`](https://github.com/picklepete/pyicloud):

- You authenticate with the **Apple ID + password + 2FA** of the account to sync.
- The session (cookies + trust token) is saved, so 2FA is asked **once** (Apple trusts
  the session for roughly **90 days**, as observed).
- **Honest limitations:** this is reverse-engineered Apple API — it can break when
  Apple changes things, has no SLA or official support, and is subject to rate
  limiting. Use it with an account you control and keep a backup.
- **Advanced Data Protection (ADP) is incompatible:** enabling ADP on the Apple ID
  ends web-API access to iCloud Drive entirely (this affects every tool in this
  space, not just this one).

### Change detection

| Side | How it is detected | Latency |
|------|--------------------|---------|
| **Local** | FSEvents watcher (`watchdog`), debounced | near-instant |
| **Remote (iCloud)** | polling every `interval_seconds` (faster while changes flow) | seconds to the interval |

There is no iCloud webhook — remote changes only appear on the next poll. Polling is
adaptive: while changes flowed recently the daemon polls every
`interval_active_seconds` (default 20s), then settles back to `interval_seconds`.

## Usage

```bash
ifolder-sync init                 # configure Apple ID, remote folder, local folder, interval...
ifolder-sync init --obsidian      # same, and mark this vault as Obsidian (excludes .obsidian config)
ifolder-sync auth                 # authenticate with iCloud (one-time 2FA, then a saved session)
ifolder-sync auth --fresh         # same, but discard the saved session and log in clean
ifolder-sync sync                 # run ONE sync pass and exit (good for testing)
ifolder-sync sync --dry-run       # preview a pass without writing anything
ifolder-sync sync --json          # emit the pass outcome as JSON (pairs with --dry-run)
ifolder-sync sync --force-delete  # apply deletions even past the safety threshold
ifolder-sync start                # run the daemon in foreground (poll + watch)
ifolder-sync start --background   # run it detached via launchd (returns your terminal)
ifolder-sync stop                 # stop the background (launchd) daemon
ifolder-sync restart              # restart the background (launchd) daemon (atomic; verified)
ifolder-sync status               # show every profile's state (--profile <name> for just one)
ifolder-sync status --json        # machine-readable state (for menu-bar/Raycast integrations)
ifolder-sync status --watch       # live dashboard: in-flight transfers, queue, recently synced
ifolder-sync doctor               # read-only consistency audit (baseline vs local vs remote)
ifolder-sync doctor --fix-orphans # drop orphan baseline rows (backs up the baseline first)
ifolder-sync logs -f              # tail the daemon log and keep following (Ctrl-C stops)
ifolder-sync rebaseline           # reset the baseline (backup first) after the vault moved/drifted
ifolder-sync purge-trash          # empty the local soft-delete trash (confirms; -y to skip)
ifolder-sync install-agent        # generate the launchd LaunchAgent without loading it
ifolder-sync uninstall            # stop and remove the launchd LaunchAgent (.plist)
```

JSON goes to **stdout**, human/diagnostic text to **stderr** — so `status --json | jq` and
`sync --dry-run --json` are stable to script against. `NO_COLOR` is honored.

- **`status --watch`** is a live dashboard: it redraws the daemon's state, the in-flight
  transfers, the full pending queue, recently-synced files (and any path that is
  re-syncing in a loop) until Ctrl-C. With no `--profile` and more than one profile it
  shows a compact multi-profile overview; it is read-only and network-free (it polls the
  daemon's snapshot, never the iCloud API). Install the optional `rich` extra
  (`pip install "ifolder-sync[dashboard]"`) for a richer frame. Refresh cadence is
  `--interval` or `dashboard_interval_seconds` (default 1s).
- **`doctor`** is a read-only consistency audit — the read-only counterpart of a sync
  pass: it runs the engine's decide phase with **no apply**, so it never writes the
  baseline and never changes a local or iCloud file, and reports inconsistencies (orphan
  baseline rows, would-be conflicts, planned transfers/deletions). `doctor --fix-orphans`
  is the one opt-in write: it drops only the provably-orphan baseline rows, **backing up
  the baseline first** and **holding the single-instance lock** (so it refuses while the
  daemon is running). It still does a network walk and may persist the iCloud session.

### Exit codes

`ifolder-sync` returns a distinct code per outcome so cron/monitoring can react (not just a
blanket `0`):

| Code | Meaning |
| ---- | ------- |
| 0 | success |
| 2 | usage error (bad arguments) |
| 3 | authentication required — run `ifolder-sync auth` |
| 4 | a scan guard aborted the pass (zero deletions; check permissions/network) |
| 5 | vault identity mismatch — run `ifolder-sync rebaseline` |
| 6 | sync ran, but deletions were suppressed by the safety threshold |
| 7 | sync ran, but some file operations failed |
| 130 | interrupted (Ctrl-C) |

### Shell completion (optional)

```bash
pip install "ifolder-sync[completion]"          # adds shtab
ifolder-sync --print-completion zsh  > "${fpath[1]}/_ifolder-sync"   # zsh
ifolder-sync --print-completion bash > ifolder-sync.bash            # bash
```

### Password

The password is **not** stored in a file. Resolution order:

1. **Environment variable** `IFOLDER_SYNC_PASSWORD`, if set (note: visible in the
   process environment — prefer the Keychain).
2. **macOS Keychain**, if a password is already saved for that Apple ID.
3. **Interactive prompt**: if neither exists, `auth` asks — and on success **stores the
   password in the Keychain automatically**, so the non-interactive daemon (`start`)
   can connect later.

> Use the Apple ID's **primary password**. *App-specific passwords* **do not work**
> with iCloud Drive via pyicloud (they are only accepted by legacy IMAP/CalDAV/CardDAV)
> — Apple rejects them in the web/SRP flow used here.

### Where the 2FA code shows up

Apple's 6-digit 2FA code **does not arrive by SMS or email** by default. It appears as
a **system pop-up** ("Sign-In Request") on the Apple devices signed into this account —
tap **"Allow"** to see the digits. (An SMS fallback is available too.)

Run `ifolder-sync auth`. The 2FA flow is interactive — and ifolder-sync requests the
push itself, so the classic "asks for a code but none ever arrives" failure of
API-based logins is already handled:

```
2FA code | [r]esend push | [s]ms | [d]iag | Enter=cancel:
```

- type the **6 digits** from the pop-up to validate;
- **`r`** = resend the push to trusted devices;
- **`s`** = send the code by **SMS** to a trusted phone (fallback when the pop-up never
  appears — e.g. no Apple device nearby);
- **`d`** = diagnostics (`hsaVersion`, 2fa/2sa flags, trusted session, trusted phones).

## Obsidian: how `.obsidian/` is handled

This handling is **opt-in**: enable it with `ifolder-sync init --obsidian` (sets
`obsidian: true`). A folder that is not an Obsidian vault leaves `obsidian: false`
(the default) and syncs `.obsidian/` like any other content.

Obsidian's `.obsidian/` folder mixes two very different things, and syncing them the
same way is what breaks cross-device setups:

- **Shared assets** — plugin code (`plugins/<id>/main.js`, `manifest.json`,
  `styles.css`), `themes/`, `snippets/`, `icons/`. These **sync** so your plugins and
  themes are installed and available on every device.
- **Volatile per-device config** — rewritten by every device. These are **never
  synced**, because syncing them causes the classic problems: a theme set on the PC
  **reverts** (`appearance.json` conflicts), the enabled-plugins list goes incoherent
  (`community-plugins.json` desyncs), and each plugin's `data.json` thrashes — it is
  rewritten on nearly every app launch (especially on mobile) and is the chief victim
  of iCloud's *publish-before-content* lag.

**Never-synced (config-local) set:** `workspace.json`, `workspace-mobile.json`,
`appearance.json`, `app.json`, `core-plugins.json`, `community-plugins.json`,
`hotkeys.json`, `cache`, `graph.json`, and every plugin's `plugins/*/data.json`.
`manifest.json`, the plugin code, and `.obsidian/types.json` **still sync**.

The trade-off: you set your theme and enable plugins **once per device** — usually
desirable (desktop and mobile often want different appearance/layout).

> **Obsidian config is opt-in (`obsidian: true`).** When enabled, the volatile patterns
> are applied automatically *on top of* your `ignore` list (not stored in it) — see
> `Config.effective_ignore`. Enable with `ifolder-sync init --obsidian`, or add
> `"obsidian": true` to an existing config.
>
> Each plugin's per-device state (`plugins/<id>/data.json`) is excluded **automatically**
> when `obsidian: true` — it is rewritten on nearly every launch and several plugins
> (e.g. Iconic) treat an external writer as corruption. This is almost always what you
> want: device-specific plugin settings stay local while the plugin itself still travels.
> If you genuinely need one plugin's settings to sync across devices, leave Obsidian mode
> off and curate `ignore` by hand. See the
> [conflicts & recovery playbook](docs/ADVANCED_USAGE.md#conflicts--recovery-playbook).

## Ignored files (`ignore`)

Patterns apply on **both sides** and match at **any depth** (root *and* subfolders):

- **simple name** (no `/`), e.g. `.DS_Store`, `*.icloud` → matches that name in any
  path segment (a file, or a folder + its contents);
- **path** (with `/`), e.g. `.obsidian/workspace.json`, `.trash/` → matches that span
  at any depth, **including everything below it**. A trailing `/` is just readability.

`*` never crosses a folder boundary (matching is segment by segment).

| Pattern | Matches | Does NOT match |
|---------|---------|----------------|
| `.obsidian/workspace.json` | `.obsidian/workspace.json`, `notes/.obsidian/workspace.json` | `.obsidian/app.json`, `workspace.json` |
| `.trash/` | `.trash/old.md`, `notes/.trash/x/y.md` | `.trashcan/x` |
| `*.icloud` | `a/b/foo.icloud` | `notes/icloud.md` |

**Default patterns:** `.DS_Store`, `.Trash`, `*.icloud`, `*.conflict-*`, `*.part`,
plus the Obsidian config-local set listed above when `obsidian: true`.

`*.conflict-*` (the conflict-backup names) and `*.part` (in-flight downloads) are
**always** ignored by the engine even if absent from a saved `ignore` list, and the
vault marker `.ifolder-sync-vault` never syncs.

**Symlinks inside the vault are not synced.** A symlinked file would be replaced by a
regular file on the next remote download (destroying the link), and a symlinked folder
would sync as empty (the scan does not descend it). Symlinks are skipped with a
one-time warning.

## Conflict policy

When **both sides change** the same file between two syncs:

- `newer` (default): the newer `mtime` wins; the loser is saved as
  `name.conflict-YYYYMMDD-HHMMSS.ext` (locally, never synced) — nothing is lost.
- `local` / `remote`: the chosen side always wins.
- `both`: keep both (the remote version becomes a `.conflict-…` file).

> Conflicts, `.conflict-*` files, theme-revert, plugin `data.json`, the
> publish-before-content lag (`pending` items), vault-identity mismatch, and
> delete-threshold trips each have step-by-step recovery instructions in the
> [conflicts & recovery playbook](docs/ADVANCED_USAGE.md#conflicts--recovery-playbook).

## Safety & resilience

- **Walk guard (both sides):** if the remote listing fails (network/auth) **or the
  local scan hits a permission error / missing vault root**, the pass aborts with
  **zero deletions** instead of mistaking partial visibility for "everything was
  deleted".
- **Vault identity marker:** a local-only `.ifolder-sync-vault` file ties the baseline
  to the folder it was built from. If the vault is moved or recreated, the daemon stops
  with "vault identity mismatch" instead of deriving phantom deletions — recover with
  `ifolder-sync rebaseline` (backs up the baseline, then the next pass is purely
  additive: downloads + uploads, never deletes).
- **Bootstrap pass:** the daemon's first pass after start transfers content normally
  but **defers all deletions to the next pass**, and logs which side has the freshest
  change. Destructive decisions never ride on a possibly-stale startup view.
- **Delete threshold:** if a single pass would delete more than `delete_threshold_pct`
  (default 50%) of tracked files **or** `delete_threshold_count` (default 100), it
  **skips the deletions** and warns. Override with `sync --force-delete`. If it trips
  right after startup the daemon flags **DRIFT SUSPECTED**; after 3 consecutive trips
  it slows polling until a clean pass.
- **Preflight + no crash-loop:** before syncing, the daemon probes that the vault is
  readable and writable, and fails fast with an actionable message otherwise. The
  LaunchAgent restarts only on real crashes (`SuccessfulExit=false`), so a
  misconfigured daemon cannot restart-loop.
- **Download tempfiles:** in-flight `*.part` files are engine-ignored and can never be
  uploaded back to iCloud.
- **Soft-delete (recoverable):** local deletions move to a trash under
  `~/.config/ifolder-sync/state/<profile>/trash/` (outside the vault). Remote deletions
  go to iCloud's "Recently Deleted" (`remote_trash`, default on; recoverable ~30 days).
  `status` shows the local trash count; `purge-trash` empties it.
- **Retries:** transient iCloud / rate-limit errors are retried with exponential
  backoff (`max_retries`, default 3).
- **Publish-before-content lag (unreadable remote):** iCloud sometimes lists a file
  (size N > 0) before its body has propagated, so a fetch returns 0 bytes. The engine
  **defers** that file — it counts as `pending`, never an error, and your good local
  copy is never overwritten — and retries on later passes. Only if it stays unreadable
  for `unreadable_max_passes` (default 20) against an *unchanged* remote signature does
  the engine treat it as a genuine empty husk and let the good side win (one warning).
  A conflict is never resolved against an unreadable remote.
- **Single-instance lock:** a **kernel advisory lock** (`fcntl.flock`) on
  `state/<profile>/daemon.lock` (kept `0600`) stops two daemons from racing the baseline.
  The kernel releases the lock on **any** process exit — clean, crash, or `SIGKILL` — so
  there is no stale-lock heuristic: a dead holder's lock is simply gone. (The pid written
  in the lock file is a human-readable label only, never a liveness decision.) The lock
  file must live on a **local filesystem** — flock is unreliable over NFS/SMB. A manual
  `sync`, `rebaseline`, and `doctor --fix-orphans` each **hold** this lock for the whole
  baseline write and refuse to run while the daemon is up.
- **Credential perms:** the session/cookie files are kept `0600` in a `0700` directory
  (bearer credentials); downloads are path-traversal safe (a remote name cannot escape
  the vault root).

> Full component map, sync-pass sequence diagram, safety model and performance model:
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## How the bidirectional sync works

The engine keeps a **three-way baseline** in SQLite
(`~/.config/ifolder-sync/state/<profile>/baseline.sqlite3`): the signature
(size + mtime) of each file **as it was at the last sync**, per side. Each pass
compares the current state of each side against that baseline:

- changed on one side only → copy to the other;
- changed on both sides → **conflict** (resolved by policy);
- gone from one side without having changed → propagate the deletion.

That is what tells "new file here" apart from "file deleted there" — without the
baseline, the two would look identical. Each pass **decides** every action first, then
**applies** them (enabling `--dry-run` and the delete threshold). Remote scans are
cheap: iCloud folder etags fingerprint whole subtrees, so unchanged folders are served
from cache and a no-change pass costs about one network call.

## Profiles (sync multiple folders)

Each synced folder is an isolated **profile** with its own config, state, lock, and
launchd agent. Pass `--profile <name>` (default `default`) to any subcommand:

```bash
ifolder-sync init  --profile work --obsidian
ifolder-sync auth  --profile work
ifolder-sync start --profile work --background
ifolder-sync status                 # shows every profile's state
```

Layout:

```
~/.config/ifolder-sync/
  profiles/<name>.json        # one config per profile
  state/<name>/               # per-profile baseline.sqlite3, trash/, daemon.lock, logs/
  state/sessions/             # iCloud sessions, shared and keyed by Apple ID
```

- **Isolation:** a failed scan or crash in one profile never touches another's baseline.
- **Sessions are shared per Apple ID:** profiles on the same account reuse one trusted
  session (one 2FA); different accounts get separate sessions automatically.
- **Back-compat:** a pre-profiles setup (`config.json` + `state/`) is migrated **once,
  automatically** to the `default` profile on the next command.

## Run in the background (launchd details)

`start --background` (see [Quick start](#quick-start)) generates
`~/Library/LaunchAgents/com.ifolder-sync.<profile>.plist` and hands the daemon to
**launchd** — one agent per profile. The daemon log is `~/Library/Logs/ifolder-sync/<profile>.log`
(tail it with `ifolder-sync logs -f`); launchd's own stdout/stderr crash capture lives under
`~/.config/ifolder-sync/state/<profile>/logs/`.

The lifecycle commands use the **modern domain-target launchctl control plane**
(`bootstrap` / `bootout` / `enable` / `kickstart`, not the legacy `load` / `unload`),
and they **verify the post-condition** before reporting success: `start --background`,
`restart`, `stop` and `uninstall` each poll `launchctl print` until the daemon really is
up (or down) — so a command never prints a false "started"/"stopped". A fresh spawn is
throttled by launchd (see `throttle_interval_seconds`), so a (re)start may wait a few
seconds for the throttled spawn to appear; the verify deliberately outlasts that window
(a throttled-but-fine start must not read as a failure).

- **Survives logouts and reboots:** the agent is registered with launchd, so after any
  reboot the cycle is simply *boot → log in → it's already running*. Technically it
  starts at **login**, not at raw boot — LaunchAgents run inside your user session,
  which is deliberate: the daemon needs your login Keychain (Apple ID password) and
  your user's file permissions. `stop` disables it persistently until the next
  `start --background`.
- **`restart`** is a first-class verb (not `stop && start`): it converges the job
  atomically (`bootout` → `enable` → `bootstrap` → `kickstart -k`) and verifies the
  daemon came back up, so a restart never ends with the daemon stopped. It accepts
  `--background` (for symmetry with `start`; `restart` always manages the launchd job).
- **`uninstall`** stops the job and removes its `.plist`; it is idempotent (safe to run
  when nothing is installed).
- `install-agent` does the same generation *without* loading, if you prefer to drive
  `launchctl` yourself.
- **Authenticate first** (`ifolder-sync auth`): the background daemon runs
  non-interactively and cannot answer a 2FA prompt. It validates its saved trust token
  first and only reads the password from the macOS Keychain when a real login is needed,
  with a **bounded read** (`keyring_timeout_seconds`) so a non-grantable Keychain access
  can never wedge the daemon — it fails fast with a clean auth error and stops.
- The vault-location (TCC) restriction from [Quick start](#quick-start) applies
  especially here.

## Configuration

Each profile's config lives at `~/.config/ifolder-sync/profiles/<name>.json`:

| Field | Meaning | Default |
|-------|---------|---------|
| `apple_id` | Apple ID of the iCloud account to sync | — |
| `remote_folder` | Subfolder inside iCloud Drive (empty = root) | `""` |
| `local_folder` | Mirrored local folder | — |
| `interval_seconds` | Remote poll interval when idle (warns if `<30`) | `60` |
| `interval_active_seconds` | Poll interval while changes flowed recently | `20` |
| `active_window_seconds` | How long the fast cadence lasts after a change | `300` |
| `watch_local` | Enable the real-time local FS watcher | `true` |
| `debounce_seconds` | Quiet time before syncing after local events | `3.0` |
| `conflict_policy` | `newer` \| `local` \| `remote` \| `both` | `newer` |
| `obsidian` | Treat as an Obsidian vault (exclude `.obsidian/` per-device config) | `false` |
| `max_retries` | Backoff attempts on transient errors | `3` |
| `retry_base_delay` | Backoff base in seconds (1s, 2s, 4s…) | `1.0` |
| `remote_trash` | Remote delete → iCloud Recently Deleted | `true` |
| `delete_threshold_pct` | Pause deletes above this % of tracked files | `50` |
| `delete_threshold_count` | Pause deletes above this many files | `100` |
| `walk_workers` | Concurrent remote folder listings (1 = serial) | `4` |
| `full_walk_interval_seconds` | Max etag-cache age before a full remote walk (0 = no cache) | `3600` |
| `throttle_interval_seconds` | launchd `ThrottleInterval`: min seconds between (re)spawns — bounds start/restart latency and crash-loop spacing (≥1) | `15` |
| `dashboard_interval_seconds` | `status --watch` redraw cadence (floor 0.2s; `--interval` overrides) | `1.0` |
| `ignore` | Patterns ignored on both sides (see above) | see defaults |

The table above lists the everyday options. The remaining tuning/advanced options —
request timeout, the bounded Keychain read (`keyring_timeout_seconds`), session
auto-reconnect bounds, baseline backups, Unicode normalization, etag verification, the
publish-before-content deferral window (`unreadable_max_passes`), the 0-byte settle
window, the upload size cap, strict child-count, the post-condition verify bound
(`lifecycle_verify_timeout_seconds`), and the live-dashboard surface
(`inflight_surface`, `inflight_min_write_interval_ms`) — are documented in full, with
when-to-change guidance and example configs, in
**[docs/ADVANCED_USAGE.md](docs/ADVANCED_USAGE.md)**.

## Troubleshooting

- **Is it actually running?** `ifolder-sync status` (daemon liveness + session
  validity), `ifolder-sync status --watch` (live in-flight/queue dashboard), and
  `ifolder-sync logs -f` (live activity).
- **Suspect drift / inconsistency** (suppressed deletions, stuck files): run the
  read-only `ifolder-sync doctor` audit before any destructive step.
- **2FA stuck / "invalid code too many times" / no code arrives:**
  `ifolder-sync auth --fresh` discards the saved session and logs in from scratch.
- **Moved or recreated the vault folder** (or "vault identity mismatch"):
  `ifolder-sync rebaseline`, then `sync --dry-run` to preview the recovery.
- **Daemon sees nothing / permission errors:** the vault is probably under
  `~/Downloads`, `~/Desktop` or `~/Documents` (TCC) — move it.
- Before trusting any big operation: `ifolder-sync sync --dry-run`.

## Uninstall / upgrade

```bash
# upgrade (from the clone)
git pull && pip install -e .
ifolder-sync restart                               # per active profile (see the note below)

# uninstall
ifolder-sync uninstall                             # per profile: stops + removes the .plist
rm -rf ~/.config/ifolder-sync                      # configs, state, sessions, local trash
pip uninstall ifolder-sync
```

> **One-time after upgrading: run `ifolder-sync restart` for each active profile.** The
> single-instance lock is now a kernel `fcntl.flock` (it used to be a PID file). A daemon
> started by an older version holds the lock file **without** a kernel flock, so a
> new-code process cannot see it; restarting makes the new code take the kernel lock.
> `restart` is atomic (it verifies the daemon came back up), so it is the correct upgrade
> step — `stop && start --background` also works.

`uninstall` removes the launchd agent and its `.plist` per profile. The Keychain entry
(the Apple ID password saved by `auth`) can be removed with the Keychain Access app if
desired. Your vault and the remote iCloud folder are never touched by uninstalling.

## Tests & development

```bash
.venv/bin/pytest                       # full suite (in-memory fake iCloud, no credentials)
.venv/bin/ruff check ifolder_sync tests
.venv/bin/ruff format ifolder_sync tests
.venv/bin/mypy ifolder_sync tests
```

The suite uses an **in-memory fake iCloud** and covers the bidirectional matrix
(create/edit/delete both sides, idempotence, conflict), the Obsidian taxonomy, and the
safety guards (walk guards, delete threshold, path traversal, locking, soft-delete,
dry-run, settle guard, etag cache). Code layout and design rationale live in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Continuous integration & AI-assisted review

Every PR runs a layered check suite. The AI layers are **advisory** — only the
deterministic checks gate a merge:

- **Hard gates** — `ruff`, `mypy`, the full `pytest` matrix (3.10–3.14), plus CodeQL,
  Trivy and gitleaks security scans.
- **[CodeRabbit](https://coderabbit.ai)** — general inline review.
- **Invariant Guardian** ([`scripts/ai_guardian/`](scripts/ai_guardian/)) — a small custom
  reviewer (Gemini on Vertex AI, keyless via Workload Identity Federation) that flags diffs
  weakening the data-loss invariants in
  [`invariants.yaml`](scripts/ai_guardian/invariants.yaml). It only comments; it never blocks.

Because the Guardian is an LLM, **the reviewer itself is tested**: an eval harness
([`evals/`](evals/README.md)) runs it over golden fixtures — diffs that deliberately weaken
an invariant (must be caught) and benign ones (must not be flagged) — gating on
**recall ≥ 0.85** and **false-positive ≤ 0.10**. A weekly drift guard keeps `invariants.yaml`
honest against the code it references.

The AI layers need a Vertex project + repo variables; without them they skip cleanly, so
forks and unconfigured clones just run the deterministic gates. Design rationale:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

[MIT](LICENSE) — © 2026 Vitor Zanoni. Provided as-is, without warranty of any kind.
