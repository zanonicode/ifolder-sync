# Lifecycle invariants — review checklist

A rider for reviewers (human + CodeRabbit) on any change to the daemon **lifecycle** surface:
`ifolder_sync/cli.py` (start/stop/restart/status/install-agent/uninstall, `_lc`, `_converge_*`,
`_observe_daemon`, `_verify`, `_write_agent_plist`), `ifolder_sync/daemon.py` (`run()` ordering,
exit codes), and `ifolder_sync/locking.py` (the single-instance lock).

This is the lifecycle counterpart to the 9 engine invariants (owned by the Invariant Guardian).
The lifecycle is **orthogonal to the sync engine** — a lifecycle change must not need to touch
those 9. Background: `.claude/kb/macos-launchd-daemon-lifecycle/` (private SDD repo).

## The checklist

- [ ] **Invariant 9 preserved.** The daemon exits **0** on operator-actionable stops (auth/2FA,
      corrupt baseline, vault-identity mismatch, repeated session relapse) so launchd
      `KeepAlive {SuccessfulExit: false}` does **not** crash-loop it. Don't flip `SuccessfulExit`
      and don't make a deliberate stop exit non-zero.
- [ ] **Plist keys unchanged.** `KeepAlive SuccessfulExit=false`, `RunAtLoad`, `ThrottleInterval`,
      `ExitTimeOut`, `ProcessType` are a contract. A control-plane change alters the launchctl
      *verbs*, not these keys. (`test_plist_has_no_crash_loop_keys` guards this.) `ThrottleInterval`
      is single-sourced from `Config.throttle_interval_seconds` (default 15) into the plist — never
      hardcode it; the start/restart verify wait must outlast it (see "Verify the post-condition").
- [ ] **Verify the post-condition.** `start`/`stop`/`restart`/`uninstall` must confirm the daemon
      actually started/stopped (bounded poll of observed liveness) before reporting success — never
      print an unconditional "it runs now". A never-up daemon (invariant-9 exit-0) must make
      `_verify` **time out → "failed"**, never hang. The bound is `lifecycle_verify_timeout_seconds`
      (default 5.0s) for teardown (`stop`/`uninstall`), but `start`/`restart` floor it at the
      throttle window (`throttle_interval_seconds + _VERIFY_BUFFER_SECONDS`) because launchd can
      delay a fresh spawn up to `ThrottleInterval` — a throttled-but-fine spawn must not read as a
      false "failed to start". The poll returns the instant the daemon is observed up, so a fast
      start stays fast.
- [ ] **Observe liveness, don't infer it.** Read it from the supervisor (`launchctl print`) or a
      held lock; surface three states — **running / stopped / unknown**. A torn/unreadable lock
      or an unexpected launchctl error is `unknown`, not `stopped`. Don't AND together fallible
      heuristics. Lock liveness is decided by the **kernel** (`fcntl.flock`): `holder_pid()` does a
      non-blocking flock probe — a refused probe means a live holder, a successful probe means free.
      The kernel releases the lock on ANY process exit (clean, crash, SIGKILL), so there is **no
      stale-lock heuristic** — never reintroduce the old `kern.boottime`/`_BOOT_TOL` reclaim or
      treat the pid in the lock file as a liveness input (it is a human-readable label only).
- [ ] **Classify launchctl by exit code, not stderr text.** `bootout` not-loaded = rc 3;
      `print` not-found = rc 113. No English-substring matching of another tool's output.
- [ ] **Domain target from `os.getuid()`** — `gui/<uid>/<label>`, never hardcoded.
- [ ] **Baseline-writing commands HOLD the lock.** `sync`, `doctor --fix-orphans`, `rebaseline`
      acquire `SingleInstanceLock` for the whole write (via `_daemon_lock`), never a bare
      `holder_pid` snapshot (that's a TOCTOU). The lock is a kernel `flock` held on an fd kept
      open for the whole write — closing the fd releases it, so the fd must stay open until the
      write completes. The lock file is `0600` (invariant 7's posture; `acquire()` re-`fchmod`s it
      even when it already exists) and must live on a **local** filesystem (flock is unreliable
      over NFS/SMB).
- [ ] **The live `status.json` is trusted only from the live writer** — `_dashboard_view` shows a
      snapshot only when its `pid` is the current lock holder (a foreground `sync` and the daemon
      both stamp their own pid).
- [ ] **Tests assert command construction**, not launchd itself (the suite can't run launchd):
      verb + `gui/<uid>/<label>` target + ordering, and parse captured `launchctl print` output.
      A live `start`/`stop`/`restart`/`status` smoke test is an operator step.
- [ ] **flock migration is one-time-restart.** A daemon started by a pre-flock build holds the lock
      file WITHOUT a kernel `flock`, so a new-code `holder_pid()` probe sees the file as free. After
      upgrading, each active profile needs one `ifolder-sync restart` so the new code takes the
      kernel lock. Don't add a back-compat shim that re-reads the pid for liveness — that would
      resurrect the stale-reclaim heuristic flock was adopted to retire.
- [ ] **Engine untouched.** No change to `syncer.py`/`state.py`/`icloud_client.py` engine logic
      or any of the 9 engine invariants.

## Operator smoke test (run on a real Mac after a lifecycle change)

```bash
ifolder-sync start --background --profile <p>   # expect: started (pid N), no silent no-op
ifolder-sync status --profile <p>               # expect: running (pid N) immediately
ifolder-sync restart --profile <p>              # expect: a fresh pid, no throttle-long "stopped" window
ifolder-sync stop --profile <p>                 # expect: stopped; running it again is a no-op success
ifolder-sync uninstall --profile <p>            # expect: bootout + plist removed; idempotent
```
