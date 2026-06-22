# ifolder-sync — Advanced Usage

Everything beyond the three-command quick start: the **complete configuration
reference**, **worked example configs** for common scenarios, and a **conflicts &
recovery playbook** that walks through every failure mode this project has hit in the
field and exactly how to resolve it.

New here? Start with the [README](../README.md). For the internal design, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Contents

- [The config file](#the-config-file)
- [Complete option reference](#complete-option-reference)
  - [Identity & locations](#identity--locations)
  - [Scheduling & change detection](#scheduling--change-detection)
  - [Conflict & deletion safety](#conflict--deletion-safety)
  - [Obsidian](#obsidian)
  - [Reliability & network](#reliability--network)
  - [Data integrity & propagation-lag](#data-integrity--propagation-lag)
  - [Performance](#performance)
  - [Lifecycle & dashboard](#lifecycle--dashboard)
  - [Limits](#limits)
  - [Ignore patterns](#ignore-patterns)
- [Example configurations](#example-configurations)
- [Inspecting & operating a live vault](#inspecting--operating-a-live-vault)
- [Conflicts & recovery playbook](#conflicts--recovery-playbook)
- [Operational tips](#operational-tips)

---

## The config file

Each profile is one JSON file:

```
~/.config/ifolder-sync/profiles/<name>.json      # default profile: default.json
```

`ifolder-sync init` writes it interactively; after that you can edit the JSON directly.
A few rules worth knowing:

- **Edit while stopped.** The daemon reads its config **once at startup**. Edit the
  file, then `ifolder-sync stop && ifolder-sync start --background` (or just `stop`
  before a manual `sync`) for changes to take effect.
- **Unknown keys are warned, not silently dropped.** A typo like `"intervall_seconds"`
  logs a warning at load and is ignored — check `ifolder-sync logs` if a setting seems
  to have no effect.
- **Types are validated.** Integer options reject a JSON `true`/`false` (a common
  mistake), and the numeric options reject non-numbers — `ifolder-sync sync` fails fast
  with the offending key rather than misbehaving later.
- **The password is never in this file.** It comes from the macOS Keychain or the
  `IFOLDER_SYNC_PASSWORD` env var (see the README's [Password](../README.md#password)
  section).
- **One file per profile, fully isolated.** `--profile work` reads `work.json` and keeps
  its own baseline, trash, lock and launchd agent. See the README's
  [Profiles](../README.md#profiles-sync-multiple-folders) section.

A minimal valid config only needs `apple_id` and `local_folder`; every other key falls
back to the default listed below.

---

## Complete option reference

Every field of the config, grouped by what it governs. **Type · default** is shown for
each; "when to change" calls out the cases that actually warrant tuning — most defaults
are correct for an Obsidian vault and should be left alone.

### Identity & locations

| Field | Type · default | What it does |
|-------|----------------|--------------|
| `apple_id` | str · `""` | Apple ID of the iCloud account to sync. **Required.** |
| `remote_folder` | str · `""` | Subfolder inside that account's iCloud Drive. Empty = Drive root. e.g. `Obsidian/MyVault`. |
| `local_folder` | str · `""` | The local folder mirrored against `remote_folder`. **Required.** Keep it out of `~/Downloads`/`~/Desktop`/`~/Documents` (macOS TCC blocks background daemons there). |

### Scheduling & change detection

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `interval_seconds` | int · `60` | Remote poll interval when idle. iCloud has no webhook, so remote edits only appear on the next poll. Lower = fresher but more API calls (warns below 30). |
| `interval_active_seconds` | int · `20` | Faster poll cadence used while changes flowed recently. |
| `active_window_seconds` | int · `300` | How long the fast cadence persists after the last change before settling back to `interval_seconds`. |
| `watch_local` | bool · `true` | Enable the real-time FSEvents watcher for local edits. Turn off only to run as a pure poller (e.g. headless/odd filesystems). |
| `debounce_seconds` | float · `3.0` | Quiet time after a local event before syncing, so a burst of editor saves coalesces into one pass. Raise if your editor writes many times per save. |

### Conflict & deletion safety

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `conflict_policy` | str · `newer` | Who wins when **both sides** changed a file since the last sync. `newer` (mtime wins, loser kept as `.conflict-…`), `local`, `remote`, or `both` (keep both). See the [playbook](#conflicts--recovery-playbook). |
| `delete_threshold_pct` | int · `50` | If a single pass would delete more than this % of tracked files, **all** deletions are skipped and a warning is logged. The primary guard against a misread tree becoming mass deletion. |
| `delete_threshold_count` | int · `100` | Absolute-count companion to the above — deletions are skipped if either limit trips. Raise both for a genuinely large bulk delete, or use `sync --force-delete` once. |
| `remote_trash` | bool · `true` | Remote deletions go to iCloud's *Recently Deleted* (recoverable ~30 days) instead of a hard delete. Leave on. |

### Obsidian

| Field | Type · default | What it does |
|-------|----------------|--------------|
| `obsidian` | bool · `false` | Treat the folder as an Obsidian vault: the per-device `.obsidian/` config set (`workspace.json`, `appearance.json`, `community-plugins.json`, …, and every `plugins/*/data.json`) is excluded automatically on top of `ignore`, while plugin code, themes, snippets and `manifest.json` still sync. Set via `init --obsidian`. See the README's [Obsidian section](../README.md#obsidian-how-obsidian-is-handled). |

### Reliability & network

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `max_retries` | int · `3` | Retry attempts for a transient iCloud/rate-limit error before the operation is counted as failed. |
| `retry_base_delay` | float · `1.0` | Exponential-backoff base in seconds (1s, 2s, 4s, …). Raise on a flaky/metered link to back off harder. |
| `request_timeout_seconds` | int · `60` | `(connect, read)` timeout on every iCloud request. pyicloud defaults to *no* timeout, so a single hung socket could wedge the daemon forever; this turns a hang into a retryable error. `<= 0` disables (not recommended). |
| `max_session_reconnects` | int · `5` | The iCloud *login token* lapses after some hours of uptime (HTTP 421 `LOGIN_TOKEN_EXPIRED`). The daemon reconnects in place — no 2FA, the trust token is still valid — instead of looping every poll. This caps consecutive reconnects with no clean pass between them before it clean-stops with a "run auth" hint. `0` = clean-stop on the first relapse. |
| `min_reconnect_interval_seconds` | int · `120` | Minimum gap between two SRP reconnects, so a relapse storm cannot replay logins every poll (Apple lockout risk). Within the window it retries without reconnecting. |
| `keyring_timeout_seconds` | float · `10.0` | Bound on a **non-interactive** macOS Keychain read. Under launchd a venv Python is ad-hoc signed, so a non-interactive Keychain authorization cannot be auto-granted and the `security` read can block forever (once observed wedging the daemon ~17h). The daemon validates its saved trust token first and reads the password only when a real SRP login is needed; this bound turns a wedged read into a clean auth error and a tidy stop. Interactive reads (a human at a prompt) stay unbounded. `<= 0` disables the bound (legacy, unbounded). |

### Data integrity & propagation-lag

These govern how the engine handles iCloud's eventual-consistency quirks. The defaults
encode hard-won field experience — **read the [playbook](#conflicts--recovery-playbook)
before changing them.**

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `settle_max_passes` | int · `3` | A **0-byte** remote record shadowing a non-empty local file is usually a publish-before-content upload from another device, so the engine waits this many passes before judging the remote genuinely empty (and escalating to a conflict). |
| `unreadable_max_passes` | int · `20` | A remote whose record lists **size N > 0** but whose body fetches as **0 bytes** (publish-before-content lag, e.g. an iPhone-rewritten `data.json`) is **deferred** every pass — counted `pending`, never errored, never clobbering local. Only after this many sustained passes against the **same** remote signature is it judged genuine corruption (one warning, then the good side wins). Intentionally long so a slow real edit is never mistaken for corruption. Lower it **temporarily** only to force-heal a known-broken blob (see playbook). |
| `verify_remote_etag` | bool · `true` | Treat a same-size/same-mtime remote whose iCloud etag differs from the baseline as a remote change and download it. Safe (the new etag is recorded, so it cannot loop); catches silent remote rewrites. |
| `normalize_unicode` | bool · `true` | Normalize filenames to NFC for *identity*. macOS may store accented names decomposed (NFD) while iCloud reports them composed (NFC); without this the same note reads as two paths → a phantom create+delete. Leave on. |
| `strict_child_count` | bool · `false` | If a folder listing returns fewer items than iCloud's reported `directChildrenCount` (possible silent truncation), `false` logs a warning and proceeds (the delete threshold still backstops), `true` aborts the pass with zero deletions like the rest of the walk guard. Set `true` for maximum paranoia. |

### Performance

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `walk_workers` | int · `4` | Concurrent remote folder listings (one network call per changed folder). `1` = serial. Raise for a very wide tree on a fast link; lower to be gentle on rate limits. |
| `full_walk_interval_seconds` | int · `3600` | Max age of the etag cache before a full uncached remote walk runs as ground truth (plus small per-instance jitter). The etag cache makes most passes ~1 call, so this rarely fires. `0` disables caching (a full walk every pass — slow). |
| `baseline_backups` | int · `5` | After each pass that changed something, the baseline DB is snapshotted into a ring of this many rotated copies (a recovery net for corruption; never auto-restored). `0` disables. |

### Lifecycle & dashboard

These govern the launchd control plane (`start --background`/`stop`/`restart`/`uninstall`)
and the live `status --watch` dashboard. They almost never need tuning.

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `throttle_interval_seconds` | int · `15` | The launchd plist `ThrottleInterval`: launchd will not (re)spawn the job more than once per this many seconds. This bounds **both** how fast `start`/`restart` see a fresh spawn appear **and** how tightly genuine crash restarts (`KeepAlive` fires only on a non-zero exit) are spaced. Lower = snappier start/restart and faster crash recovery; higher = more conservative crash-loop spacing. Must be `>= 1` (macOS default is `10`). Written into the plist, so a change takes effect once the agent is regenerated (`start --background`, `restart`, or `install-agent`). |
| `lifecycle_verify_timeout_seconds` | float · `5.0` | How long `start`/`stop`/`restart`/`uninstall` poll `launchctl print` to verify the post-condition (the daemon really came up / went down) before reporting the true outcome — no more false "started". `start`/`restart` floor this at the throttle window (a throttled-but-fine spawn must not read as "failed to start"); `stop`/`uninstall` keep the short value (teardown is not throttled). |
| `inflight_surface` | bool · `true` | The daemon (and a foreground `sync`) writes a live `status.json` snapshot of in-flight transfers so `status --watch` can show real-time progress. `false` disables **all** producer-side dashboard work (zero overhead) — the dashboard then falls back to the persisted "stuck" set only. |
| `inflight_min_write_interval_ms` | int · `200` | Throttle for those in-flight snapshot writes: rapid updates coalesce to at most one flush per this many milliseconds. Raise to write less often on a slow disk; lower for a more granular dashboard. |
| `dashboard_interval_seconds` | float · `1.0` | How often `status --watch` re-polls the snapshot/meta and redraws. Purely view-side (no engine effect). `--interval` overrides it per run; the floor is `0.2s`. |

### Limits

| Field | Type · default | What it does · when to change |
|-------|----------------|-------------------------------|
| `max_file_size_mb` | int · `0` | Skip **uploading** a local file larger than this many MB. pyicloud buffers the whole file in memory to build the multipart body, so a multi-GB file can spike the daemon's RSS (OOM risk under launchd). `0` = no limit. Note: an over-limit file that is *also* in a both-sides conflict can't be pushed, so the conflict stays unresolved until the limit is raised or the file shrinks. |

### Ignore patterns

`ignore` (a list of strings) is applied on **both sides** and at **any depth**:

- a **simple name** (no `/`), e.g. `.DS_Store`, `*.icloud`, matches that name in any path
  segment (a file, or a folder and everything under it);
- a **path** (with `/`), e.g. `.obsidian/workspace.json`, `.trash/`, matches that span at
  any depth, **including everything below it** (a trailing `/` is just readability);
- `*` never crosses a folder boundary — matching is segment by segment.

| Pattern | Matches | Does NOT match |
|---------|---------|----------------|
| `.obsidian/workspace.json` | `.obsidian/workspace.json`, `notes/.obsidian/workspace.json` | `.obsidian/app.json` |
| `.trash/` | `.trash/old.md`, `notes/.trash/x/y.md` | `.trashcan/x` |
| `*.icloud` | `a/b/foo.icloud` | `notes/icloud.md` |
| `plugins/*/data.json` | `.obsidian/plugins/dataview/data.json` | `.obsidian/plugins/dataview/main.js` |

**Defaults:** `.DS_Store`, `.Trash`, `*.icloud`, `*.conflict-*`, `*.part`, plus the
Obsidian config-local set when `obsidian: true`. `*.conflict-*` and `*.part` are *always*
enforced by the engine even if removed from a saved list, and the vault marker
`.ifolder-sync-vault` never syncs. **Symlinks inside the vault are never synced** (skipped
with a one-time warning).

> The saved `ignore` list is frozen at `init`; newer engine-critical defaults are merged
> in at load time (`effective_ignore`) so an old config still gains them without a
> rewrite. Add your own patterns freely — they are additive.

---

## Example configurations

All examples live at `~/.config/ifolder-sync/profiles/<name>.json`. Only the keys that
differ from the defaults are shown; everything else can be omitted.

### Obsidian vault (recommended baseline)

What `init --obsidian` produces, plus sensible polling:

```json
{
  "apple_id": "you@example.com",
  "remote_folder": "Obsidian/MyVault",
  "local_folder": "/Users/you/vaults/MyVault",
  "obsidian": true,
  "conflict_policy": "newer",
  "interval_seconds": 60,
  "remote_trash": true
}
```

### Plain folder (not Obsidian)

Syncs `.obsidian/` and everything else verbatim — use for a non-vault folder:

```json
{
  "apple_id": "you@example.com",
  "remote_folder": "Documents/Shared",
  "local_folder": "/Users/you/Shared",
  "obsidian": false
}
```

### Low-bandwidth / metered connection

Poll less often, back off harder, list folders serially:

```json
{
  "apple_id": "you@example.com",
  "local_folder": "/Users/you/vaults/MyVault",
  "obsidian": true,
  "interval_seconds": 300,
  "interval_active_seconds": 60,
  "walk_workers": 1,
  "retry_base_delay": 2.0,
  "max_retries": 5
}
```

### Large binary files (PDFs, media)

Cap uploads so a giant file can't OOM the daemon, and be patient with slow blobs:

```json
{
  "apple_id": "you@example.com",
  "local_folder": "/Users/you/Library",
  "max_file_size_mb": 200,
  "request_timeout_seconds": 180,
  "unreadable_max_passes": 30
}
```

### Maximum freshness (small vault, fast link)

```json
{
  "apple_id": "you@example.com",
  "local_folder": "/Users/you/vaults/Notes",
  "obsidian": true,
  "interval_seconds": 30,
  "interval_active_seconds": 10,
  "active_window_seconds": 600,
  "walk_workers": 8
}
```

### Conservative / paranoid safety

Abort on any partial listing, keep more baseline backups, tighten the delete guard:

```json
{
  "apple_id": "you@example.com",
  "local_folder": "/Users/you/vaults/Critical",
  "obsidian": true,
  "strict_child_count": true,
  "delete_threshold_pct": 25,
  "delete_threshold_count": 50,
  "baseline_backups": 10
}
```

### Multiple folders (profiles)

Each profile is its own file and its own daemon:

```bash
ifolder-sync init  --profile work --obsidian
ifolder-sync auth  --profile work          # same account → reuses the trusted session
ifolder-sync start --profile work --background
ifolder-sync status                        # shows every profile
```

---

## Inspecting & operating a live vault

Beyond `init` / `auth` / `start`, these commands cover watching, auditing, and managing
a running daemon. All take `--profile` (default `default`).

### Live dashboard — `status --watch`

`ifolder-sync status --watch` opens a live dashboard that redraws until Ctrl-C:

- **in-flight transfers** the daemon is moving *right now* (uploading / downloading /
  deleting), backed by the atomic `status.json` snapshot (`inflight_surface`);
- the **full pending queue** (`queued`) plus the persisted *stuck* set (settle-waits and
  propagation-lag `pending` backoffs);
- a short **recently-synced** rail so a fast transfer is not invisible, and a **flapping**
  flag for any path that completes repeatedly within a moving window (a re-sync loop);
- the suppressed-deletes banner when the safety threshold withheld deletions.

With no `--profile` and multiple profiles configured it shows a compact one-line-per-profile
overview instead. Redraw cadence is `dashboard_interval_seconds` (default `1.0s`); override
per run with `--interval <seconds>` (floor `0.2s`). If the optional `rich` extra is installed
the frame upgrades to truecolor boxes; otherwise a plain ANSI frame is used. A foreground
`ifolder-sync sync` also feeds this surface, so a manual pass is visible too.

> The dashboard only renders the live snapshot when its writer is the **current** lock
> holder — a stale `status.json` left by a dead daemon never shows as live activity.

### Consistency audit — `doctor` (read-only) and `doctor --fix-orphans`

`ifolder-sync doctor` is the **read-only** counterpart of a sync pass: it runs the engine's
decide phase with **no apply** — it changes no local files, never writes the baseline, and
makes no remote change (it does perform a network walk and may refresh the iCloud session,
like every command). It reports inconsistencies grouped by kind:

- **orphan baseline rows** — paths present only in the baseline, absent from a *successful*
  local **and** remote scan (the residue of a moved/renamed folder, e.g. a macOS
  case-only rename);
- would-conflict, unsettled/pending, and the planned upload/download/delete tallies.

`status` points you here automatically (`→ run doctor …`) whenever the last pass logged
errors or suppressed deletions.

`ifolder-sync doctor --fix-orphans` is the one opt-in **write**: it drops only the
provably-orphan baseline rows, **after** backing up the baseline (a collision-safe
`baseline.sqlite3.pre-fix-orphans-<timestamp>` copy) and clearing the stale walk cache. It
touches no local or remote content, and **refuses while the daemon is running** (it holds
the same single-instance lock the daemon uses, so it can never race a live baseline write —
stop the daemon first). `doctor` and `doctor --fix-orphans` both accept `--json` (schema 1)
and `--non-interactive`. A scan failure aborts the audit, so `--fix-orphans` can never act
on a partial tree.

```bash
ifolder-sync doctor                          # read-only: what disagrees, and why
ifolder-sync stop                            # required before a fix (it writes the baseline)
ifolder-sync doctor --fix-orphans            # backup + drop only orphan rows
ifolder-sync start --background
```

### `restart` — first-class atomic restart

`ifolder-sync restart` restarts the background (launchd) daemon as a single verb, **not**
`stop && start`. It runs the modern launchd converge chain — regenerate the plist →
`bootout` the old job → wait for that async unload → `enable` the label → `bootstrap` →
`kickstart -k` a fresh spawn — then **verifies** the daemon actually came back up before
printing success. It is **atomic**: a restart never ends with the daemon stopped. The verify
wait outlasts `throttle_interval_seconds` (a throttled-but-fine respawn must not read as
"failed to start"), so a restart can take up to roughly the throttle window plus a few seconds
(`throttle_interval_seconds` + a ~5s slack) to confirm.
`--background` is accepted for symmetry with `start` but is a no-op (restart always manages
the launchd daemon). This is the command to run after upgrading (see below).

### `uninstall` — remove the launchd agent

`ifolder-sync uninstall` stops the profile's launchd job (idempotent), verifies it went
down, then removes its `LaunchAgent .plist`. Safe to run when nothing is installed
("nothing to uninstall"). It removes only the launchd agent — your config, baseline, trash,
and the synced vault are untouched.

### The single-instance lock (kernel `fcntl.flock`)

Each profile's daemon holds a kernel advisory lock (`fcntl.flock`) on
`state/<profile>/daemon.lock` for its whole lifetime, so two daemons can never race the same
SQLite baseline. The kernel releases the lock on **any** process exit — clean, crash, or
SIGKILL — so there is no stale-lock heuristic: a dead holder's lock is freed instantly. The
PID written into the lock file is a human-readable **label only**, never a liveness decision.
The lock file is `0600`. It must live on a **local** filesystem (here, APFS under `$HOME`):
`flock` semantics are unreliable over network filesystems (NFS, some SMB), so a state
directory on a network share is unsupported.

> **Upgrade note (one-time, required).** After upgrading ifolder-sync, run
> **`ifolder-sync restart`** for each active profile. A daemon started by the previous
> version holds the lock file **without** a kernel `flock`, so a new-code process cannot see
> it; restarting makes the new code take the kernel lock. Until you restart, a manual
> `sync`/`doctor --fix-orphans` may not detect the old daemon's hold.

---

## Conflicts & recovery playbook

This section catalogs every failure mode encountered with this project so far, what
causes it, and the exact steps to resolve it. **When in doubt, preview first:**
`ifolder-sync sync --dry-run` decides every action and writes nothing.

### How a conflict arises (one-paragraph recap)

The engine keeps a **three-way baseline**: the (size, mtime) of each file on each side
*as of the last successful sync*. A file changed on **one** side is simply copied to the
other. A file changed on **both** sides since the baseline is a **conflict**, resolved by
`conflict_policy`. This is why a conflict is a real "both of you edited this" event, not
noise — and why nothing is ever silently overwritten.

### 1. Both sides edited the same file → `.conflict-*` files appear

**Symptom:** a file like `Note.conflict-20260615-191122.md` shows up next to `Note.md`.

**Cause:** both devices changed `Note.md` between two syncs. Under the default `newer`
policy the newer mtime wins and the **loser is preserved** locally as a `.conflict-…`
copy (never synced, never lost).

**Resolve:**
1. Open both files, merge by hand whatever you want to keep into `Note.md`.
2. Delete the `.conflict-…` file (it is engine-ignored, so deleting it never propagates).

**Tune:** set `conflict_policy` to `local`/`remote` if one side is authoritative, or
`both` to always keep the remote copy as a `.conflict-…` file. Reduce conflicts at the
source by letting one device finish syncing before editing on another.

### 2. Theme reverts / enabled-plugin list goes incoherent (Obsidian)

**Symptom:** a theme set on the PC reverts after the phone syncs; plugins toggle on/off
across devices; `appearance.json`/`community-plugins.json` keep "changing".

**Cause:** these `.obsidian/` files are **per-device** and rewritten constantly; syncing
them makes each device fight the others.

**Resolve:** enable Obsidian mode — `ifolder-sync init --obsidian`, or add
`"obsidian": true` to the config and restart. The per-device config set is then excluded
automatically. Set your theme and enable plugins **once per device** (usually what you
want anyway).

### 3. A plugin reports "corruption" or its settings bounce (e.g. Iconic)

**Symptom:** a plugin warns about external edits, or its settings reset after a device
switch.

**Cause:** the plugin keeps live per-device state in `plugins/<id>/data.json`, rewritten
on nearly every launch (especially on mobile).

**Resolve:** under `obsidian: true` this is **already handled** — every
`plugins/*/data.json` is excluded from sync automatically (while `manifest.json` and the
plugin code still sync, so the plugin stays installed everywhere). No action needed. If
you specifically *want* one plugin's settings to travel between devices, run with
Obsidian mode off and curate `ignore` by hand.

### 4. "download size mismatch / 0 bytes" and `pending` items — publish-before-content lag

**Symptom:** logs mention a file that won't download, or `status`/a sync summary shows
`pending=N` (distinct from `errors=N`). Correlates with another device (an iPhone)
having just rewritten the file.

**Cause:** iCloud published the file's **record** (size N > 0) before its **body**
propagated to the web API, so a fetch returns HTTP 200 with 0 bytes. This is **transient
and expected**, not corruption.

**Resolve — usually nothing:** the engine **defers** the file (counts it `pending`, never
an error, never overwriting your good local copy) and retries each pass. It heals on its
own once the body propagates — often within a poll or two of the other device finishing.
A conflict is *never* resolved against an unreadable remote, so your data is safe while
you wait.

**If a blob is genuinely stuck** (a permanently broken remote blob — rare): the engine
auto-escalates after `unreadable_max_passes` (default 20 passes) — one warning, then your
good local copy is uploaded over the bad remote and devices converge. To force the cure
immediately from the device that has the correct content:

```bash
ifolder-sync stop
# make the local copy "newer" so it will be uploaded:
touch "/path/to/vault/.obsidian/types.json"
ifolder-sync sync                 # one foreground pass: local uploads over the bad blob
ifolder-sync start --background
```

If the file is stuck specifically as a **conflict** against the unreadable remote
(`pending` won't clear because both sides changed), force escalation for one pass:
temporarily set `"unreadable_max_passes": 1` in the profile, run `ifolder-sync sync`
(the good local side wins and overwrites the husk), then **restore** it to `20` and
restart. *(This is exactly the cure used for a stuck `.obsidian/types.json` blob.)*

> **`pending` vs `errors`:** `pending` = deferred on purpose, will retry, nothing wrong,
> baseline untouched. `errors` = an operation actually failed. A healthy steady state is
> `pending=0 errors=0`; a transient `pending>0` that clears on the next pass is normal.

### 5. 0-byte remote shadowing a non-empty local file

**Symptom:** a brand-new file shows as a 0-byte remote while your local copy has content.

**Cause:** the *settle* case — iCloud listed the record before its content. The engine
waits `settle_max_passes` (default 3) rather than treating it as an empty file to copy
down. It resolves automatically; raise `settle_max_passes` if your link is very slow.

### 6. "vault identity mismatch" — the daemon stops

**Symptom:** the daemon stops with a vault-identity error (exit code `5`).

**Cause:** the `.ifolder-sync-vault` marker no longer matches the baseline — you moved,
renamed, or recreated the vault folder. The engine refuses to derive phantom deletions
from a folder it doesn't recognize.

**Resolve:**
```bash
ifolder-sync rebaseline           # backs up the baseline, then starts empty
ifolder-sync sync --dry-run       # preview: the next pass is purely additive (no deletes)
ifolder-sync start --background
```

### 7. Deletions were suppressed / "DRIFT SUSPECTED"

**Symptom:** a sync summary says deletions were skipped (exit code `6`), or the daemon
logs `DRIFT SUSPECTED` and slows polling.

**Cause:** a single pass wanted to delete more than `delete_threshold_pct` (50%) or
`delete_threshold_count` (100) of tracked files — the guard against a misread tree
becoming mass deletion.

**Resolve:**
1. Confirm the deletions are real: `ifolder-sync sync --dry-run` and read the list.
2. If they're genuinely intended, apply once with `ifolder-sync sync --force-delete`, or
   raise the thresholds in the config.
3. If they're **not** intended (a half-mounted drive, a TCC-blocked folder), fix the
   underlying access problem instead — the guard just saved your files.

### 8. 2FA stuck / "invalid code too many times" / no code arrives

**Resolve:** `ifolder-sync auth --fresh` discards the saved session and logs in clean. At
the prompt, `r` resends the push, `s` sends an **SMS** fallback (when no Apple device is
nearby to show the pop-up), and `d` prints diagnostics (trusted devices, 2FA flags). The
6-digit code arrives as a **system pop-up**, not SMS/email, by default.

### 9. Session keeps dropping after a few hours

**Symptom:** `status` was healthy, then sync stops; logs show a 421 / `LOGIN_TOKEN_EXPIRED`.

**Cause:** the iCloud login token lapses after some hours of uptime. The daemon
auto-reconnects in place (no 2FA), bounded by `max_session_reconnects` (5) and
`min_reconnect_interval_seconds` (120).

**Resolve:** usually nothing — it self-heals. If it exhausts the reconnect budget it
clean-stops with a "run auth" hint; run `ifolder-sync auth` then `start --background`.

### 10. Daemon sees nothing / permission errors

**Cause:** the vault is under `~/Downloads`, `~/Desktop`, or `~/Documents` — macOS TCC
blocks launchd daemons from those folders (a Terminal-started daemon works, masking it).

**Resolve:** move the vault somewhere like `~/vaults/<name>` and `ifolder-sync rebaseline`
(the folder moved). The scan guard correctly aborts with **zero deletions** when it can't
read the root, so nothing was lost.

### 11. Nothing syncs at all, no clear error

**Cause:** **Advanced Data Protection (ADP)** is enabled on the Apple ID. ADP ends
web-API access to iCloud Drive entirely — this affects every tool in this space
(pyicloud, rclone's iclouddrive backend, all forks), not just this one.

**Resolve:** there is no workaround other than disabling ADP on that Apple ID.

### 12. A large file never uploads

**Cause:** `max_file_size_mb` is set and the file exceeds it (or it's so large pyicloud's
in-memory buffering is failing).

**Resolve:** raise `max_file_size_mb` (or set `0` for no limit) and restart. Remember an
over-limit file that's *also* in a conflict can't be pushed until the limit allows it.

---

## Operational tips

- **Preview before any big change:** `ifolder-sync sync --dry-run` (add `--json` to
  script against it). It decides every action and writes nothing.
- **Watch it work:** `ifolder-sync logs -f`. No-op passes log at DEBUG with an hourly INFO
  heartbeat, so a quiet log is normal.
- **Health at a glance:** `ifolder-sync status` (daemon liveness, session validity, last
  sync, local trash count). `status --json | jq` for menu-bar/Raycast integrations.
- **Watch it live:** `ifolder-sync status --watch` for a redrawing dashboard of in-flight
  transfers, the pending queue, and anything stuck (see
  [Inspecting & operating a live vault](#inspecting--operating-a-live-vault)).
- **Audit without touching anything:** `ifolder-sync doctor` is a read-only consistency
  check (orphan baseline rows, would-be conflicts/deletes); `doctor --fix-orphans` drops
  stale baseline rows after a backup (stop the daemon first).
- **Restart after an upgrade:** `ifolder-sync restart` per active profile — required so the
  new code takes the kernel `flock` lock (the old daemon held the file without one).
- **Exit codes are meaningful** — cron/monitoring can branch on them
  (`3` = auth needed, `4` = scan guard aborted, `5` = vault mismatch, `6` = deletes
  suppressed, `7` = some file ops failed). Full table in the
  [README](../README.md#exit-codes).
- **Recover deletions:** local deletions sit in `state/<profile>/trash/` until
  `purge-trash`; remote deletions sit in iCloud's *Recently Deleted* (~30 days).
- **Baseline got weird?** Snapshots are under `state/<profile>/`; the clean reset is
  `rebaseline` (additive next pass, never deletes).
