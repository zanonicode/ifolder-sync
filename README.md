# ifolder-sync

A **macOS** CLI daemon that **bidirectionally** syncs one folder of a **specific
iCloud Drive account** (not necessarily the one signed into the Mac) with a local
folder — **every X seconds** (remote polling) **and on every local change** (real-time
FSEvents watcher). Built for an **Obsidian vault**, with safe handling of the
`.obsidian/` config folder.

## Why this is not trivial (read first)

macOS only natively syncs the iCloud Drive of the **Apple ID signed into the system**.
There is no way to locally mount the Drive of a *second* account. So this project
reaches the other account through the **unofficial iCloud web API**, via
[`pyicloud`](https://github.com/picklepete/pyicloud):

- You authenticate with the **Apple ID + password + 2FA** of the account to sync.
- The session (cookies + trust token) is saved, so 2FA is asked **once** (Apple trusts
  the session for ~30 days).
- **Honest limitations:** this is reverse-engineered Apple API — it can break when
  Apple changes things, has no SLA or official support, and is subject to rate
  limiting. Use it with an account you control and keep a backup.

### Change detection

| Side | How it is detected | Latency |
|------|--------------------|---------|
| **Local** | FSEvents watcher (`watchdog`), debounced | near-instant |
| **Remote (iCloud)** | polling every `interval_seconds` | up to the interval |

There is no iCloud webhook — remote changes only appear on the next poll. Because the
watcher catches local edits almost instantly, the poll only needs to detect remote
(phone) changes, so an aggressive interval is rarely useful (`>=30s` recommended).

## Install

```bash
cd ifolder-sync
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
# for development (tests, lint, format, types):
pip install -e ".[dev]"
```

> The system Python (3.9, LibreSSL) emits a harmless `NotOpenSSLWarning`. To silence
> it, use a Homebrew/pyenv Python built against OpenSSL.

## Usage

```bash
ifolder-sync init                 # configure Apple ID, remote folder, local folder, interval...
ifolder-sync init --obsidian      # same, and mark this vault as Obsidian (excludes .obsidian config)
ifolder-sync auth                 # authenticate with iCloud (one-time 2FA, then a saved session)
ifolder-sync auth --fresh         # same, but discard the saved session and log in clean
ifolder-sync sync                 # run ONE sync pass and exit (good for testing)
ifolder-sync sync --dry-run       # preview a pass without writing anything
ifolder-sync sync --force-delete  # apply deletions even past the safety threshold
ifolder-sync start                # run the daemon in foreground (poll + watch)
ifolder-sync start --background   # run it detached via launchd (returns your terminal)
ifolder-sync stop                 # stop the background (launchd) daemon
ifolder-sync status               # show ALL profiles' state (one in detail with --profile)
ifolder-sync logs -f              # tail the daemon log and keep following (Ctrl-C stops)
ifolder-sync rebaseline           # reset the baseline (backup first) after the vault moved/drifted
ifolder-sync purge-trash          # empty the local soft-delete trash
ifolder-sync install-agent        # generate a launchd LaunchAgent to run at login
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

### Where the 2FA code shows up (important)

Apple's 6-digit 2FA code **does not arrive by SMS or email** by default. It appears as
a **system pop-up** ("Sign-In Request") on the Apple devices signed into this account —
tap **"Allow"** to see the digits. (An SMS fallback is available too.)

> **⚠️ Apple change (~iOS 26 / early 2026):** on API logins (like this one) Apple
> **stopped auto-sending the code** after login. The client must **request the push
> explicitly** — and pyicloud 2.0.1 does not, which caused the "asks for a code but
> none arrives" symptom. `ifolder-sync` now **triggers the push itself** when starting
> 2FA (`PUT .../verify/trusteddevice/securitycode`).

Run `ifolder-sync auth`. The 2FA flow is interactive:

```
2FA code | [r]esend push | [s]ms | [d]iag | Enter=cancel:
```

- type the **6 digits** from the pop-up to validate;
- **`r`** = resend the push to trusted devices;
- **`s`** = send the code by **SMS** to a trusted phone (fallback when the pop-up never
  appears — e.g. no Apple device nearby);
- **`d`** = diagnostics (`hsaVersion`, 2fa/2sa flags, trusted session, trusted phones).

If it gets stuck ("invalid code too many times", or a stale session interfering):

```bash
ifolder-sync auth --fresh   # discard the saved session and log in from scratch
```

## Obsidian: how `.obsidian/` is handled

This handling is **opt-in**: enable it with `ifolder-sync init --obsidian` (sets
`obsidian: true`). A folder that is not an Obsidian vault leaves `obsidian: false`
(the default) and syncs `.obsidian/` like any other content.

Obsidian's `.obsidian/` folder mixes two very different things, and syncing them the
same way is what breaks cross-device setups:

- **Shared assets** — plugin code (`plugins/<id>/`), `themes/`, `snippets/`, `icons/`.
  These **sync** so your plugins and themes are available on every device.
- **Volatile per-device config** — rewritten by every device. These are **never
  synced**, because syncing them causes the classic problems: a theme set on the PC
  **reverts** (`appearance.json` conflicts), and the enabled-plugins list goes
  incoherent (`community-plugins.json` desyncs).

**Never-synced (config-local) set:** `workspace.json`, `workspace-mobile.json`,
`appearance.json`, `app.json`, `core-plugins.json`, `community-plugins.json`,
`hotkeys.json`, `cache`, `graph.json`.

The trade-off: you set your theme and enable plugins **once per device** — usually
desirable (desktop and mobile often want different appearance/layout).

> **Obsidian config is opt-in (`obsidian: true`).** When enabled, the volatile patterns
> are applied automatically *on top of* your `ignore` list (not stored in it) — see
> `Config.effective_ignore`. Enable with `ifolder-sync init --obsidian`, or add
> `"obsidian": true` to an existing `config.json`.

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

**Default patterns:** `.DS_Store`, `.Trash`, `*.icloud`, `*.conflict-*`, plus the
Obsidian config-local set listed above.

## Conflict policy

When **both sides change** the same file between two syncs:

- `newer` (default): the newer `mtime` wins; the loser is saved as
  `name.conflict-YYYYMMDD-HHMMSS.ext`.
- `local` / `remote`: the chosen side always wins.
- `both`: keep both (the remote version becomes a `.conflict-…` file).

## Safety & resilience

- **Walk guard (both sides):** if the remote listing fails (network/auth) **or the
  local scan hits a permission error / missing vault root**, the pass aborts with
  **zero deletions** instead of mistaking partial visibility for "everything was
  deleted". (macOS TCC blindness used to look exactly like a mass local delete.)
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
  `~/.config/ifolder-sync/state/trash/` (outside the vault). Remote deletions go to
  iCloud's "Recently Deleted" (`remote_trash`, default on). `status` shows the local
  trash count; `purge-trash` empties it.
- **Retries:** transient iCloud / rate-limit errors are retried with exponential
  backoff (`max_retries`, default 3).
- **Single-instance lock:** a PID lockfile (`state/daemon.lock`) stops two daemons from
  racing the baseline; a lock left by a dead process is reclaimed automatically.
- **Credential perms:** the session/cookie files are set to `0600` (bearer credentials);
  downloads are path-traversal safe (a remote name cannot escape the vault root).

> Full component map, sync-pass sequence diagram, safety model and performance model:
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## How the bidirectional sync works

The engine keeps a **three-way baseline** in SQLite
(`~/.config/ifolder-sync/state/baseline.sqlite3`): the signature (size + mtime) of each
file **as it was at the last sync**, per side. Each pass compares the current state of
each side against that baseline:

- changed on one side only → copy to the other;
- changed on both sides → **conflict** (resolved by policy);
- gone from one side without having changed → propagate the deletion.

That is what tells "new file here" apart from "file deleted there" — without the
baseline, the two would look identical.

Each pass **decides** every action first, then **applies** them. This is what makes
`--dry-run` (decide, don't apply), the delete threshold (count deletes before
applying), and soft-delete possible. Uploads stamp the remote mtime = local mtime, so
no extra `stat()` round-trip is needed and there is no upload→download ping-pong.

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
  state/<name>/               # per-profile baseline.sqlite3, trash/, daemon.lock
  state/sessions/             # iCloud sessions, shared and keyed by Apple ID
```

- **Isolation:** a failed scan or crash in one profile never touches another's baseline.
- **Sessions are shared per Apple ID:** profiles on the same account reuse one trusted
  session (one 2FA); different accounts get separate sessions automatically.
- **launchd:** `install-agent --profile work` generates `com.ifolder-sync.work.plist`.
- **Back-compat:** a pre-profiles setup (`config.json` + `state/`) is migrated **once,
  automatically** to the `default` profile on the next command — your session and
  baseline are preserved.

## Run in the background / at boot (launchd)

Foreground `start` is great for debugging. To detach the daemon — it keeps running after
you close the terminal, restarts on crash (launchd `KeepAlive`), and starts again at each
login (`RunAtLoad`) — hand it to launchd:

```bash
ifolder-sync auth                 # IMPORTANT: authenticate FIRST (the daemon runs non-interactively)
ifolder-sync start --background   # generate the LaunchAgent + launchctl load, in one step
ifolder-sync stop                 # unload it (stops now and at future logins)
```

`start --background` generates `~/Library/LaunchAgents/com.ifolder-sync.<profile>.plist`
(label `com.ifolder-sync.default` for the default profile) and loads it. Logs go to
`~/.config/ifolder-sync/state/<profile>/logs/`. `install-agent` does the same generation
*without* loading, if you prefer to drive `launchctl` yourself.

> **Vault location matters:** do NOT keep the vault under `~/Downloads`, `~/Desktop`
> or `~/Documents`. macOS TCC blocks launchd daemons from reading those folders (a
> Terminal-started daemon works, which masks the problem). Use e.g. `~/vaults/<name>`,
> or grant the daemon Full Disk Access. `init` and `start --background` warn about this.

## Configuration

Each profile's config lives at `~/.config/ifolder-sync/profiles/<name>.json` (see Profiles):

| Field | Meaning | Default |
|-------|---------|---------|
| `apple_id` | Apple ID of the iCloud account to sync | — |
| `remote_folder` | Subfolder inside iCloud Drive (empty = root) | `""` |
| `local_folder` | Mirrored local folder | — |
| `interval_seconds` | Remote poll interval (warns if `<30`) | `60` |
| `watch_local` | Enable the real-time local FS watcher | `true` |
| `debounce_seconds` | Quiet time before syncing after local events | `3.0` |
| `conflict_policy` | `newer` \| `local` \| `remote` \| `both` | `newer` |
| `obsidian` | Treat as an Obsidian vault (exclude `.obsidian/` per-device config) | `false` |
| `max_retries` | Backoff attempts on transient errors | `3` |
| `retry_base_delay` | Backoff base in seconds (1s, 2s, 4s…) | `1.0` |
| `remote_trash` | Remote delete → iCloud Recently Deleted | `true` |
| `delete_threshold_pct` | Pause deletes above this % of tracked files | `50` |
| `delete_threshold_count` | Pause deletes above this many files | `100` |
| `ignore` | Patterns ignored on both sides (see above) | see defaults |

## Tests & development

```bash
.venv/bin/pytest                       # full suite (in-memory fake iCloud, no credentials)
.venv/bin/ruff check ifolder_sync tests
.venv/bin/black ifolder_sync tests
.venv/bin/mypy ifolder_sync
```

The suite uses an **in-memory fake iCloud** and covers the bidirectional matrix
(create/edit/delete both sides, idempotence, conflict), the Obsidian taxonomy, and the
safety guards (walk guard, delete threshold, path traversal, single-instance lock,
soft-delete, dry-run, no post-upload stat).

## Structure

```
ifolder_sync/
  obsidian.py       # .obsidian taxonomy: volatile config vs shared assets
  config.py         # JSON config in ~/.config/ifolder-sync/ + ignore defaults
  state.py          # three-way baseline (SQLite) + status meta
  icloud_client.py  # pyicloud wrapper: auth/2FA + Drive ops by path
  syncer.py         # bidirectional engine (decide → apply) + conflict policy
  retry.py          # exponential backoff for transient errors
  trash.py          # local soft-delete (recoverable)
  locking.py        # single-instance PID lock with stale reclaim
  watcher.py        # local FSEvents watcher with debounce
  daemon.py         # main loop: poll + watch, single lock, signals
  cli.py            # init / auth / sync / start / status / purge-trash / install-agent
```
