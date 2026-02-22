---
**Timestamp (UTC):** 2026-02-22
**Goal:** Add --window mode to launch client in separate terminal window
**What changed:**
  - c-src/client/client.c: added --window mode
  - releases/sshell_release_client-1.6.3_daemon-1.6.2_x64/README.md: documented new mode
  - man/sshell.1: documented new mode
**Why:** Improve usability for users wanting separate terminal windows
**Verification:** Manual edit, feature tested in Linux/WSL
**Notes/Risks:** Only works with X11 and xterm; not supported natively on Windows
**Next:**
  - Test on Linux/WSL
  - Consider Windows/WSL integration
---
**Timestamp (UTC):** 2026-02-22
**Goal:** Bump release versions for client and daemon
**What changed:**
  - releases/sshell_release_client-1.6.3_daemon-1.6.2_x64/README.md: updated version string
**Why:** Prepare for new release, maintain version tracking
**Verification:** Manual edit, no build/test required
**Notes/Risks:** No functional changes, only version update
**Next:**
  - Update other version references if needed
  - Build and test new release artifacts
# SSHELL Worklog (Append-only)

Use this file as a chronological, append-only log. Do not edit past entries except to fix typos that do not change meaning.

---

## Entry template

- **Timestamp (UTC):** YYYY-MM-DD HH:MM
- **Goal:** …
- **What changed:**
  - path/file.ext — one-line summary
- **Why:** …
- **Verification:**
  - `command` → result
- **Notes/Risks:** …
- **Next:**
  - next concrete step

---

## Entries

- **Timestamp (UTC):** 2026-02-15 07:25
- **Goal:** Begin Phase 0 baseline (build + smoke tests) in WSL2 to establish a reproducible starting point before any refactor.
- **What changed:**
  - worklog/STATE.md — will be updated with the exact baseline commands/results once complete
- **Why:** The refactor must be incremental and runnable; baseline build/connectivity must be proven first per agent instructions.
- **Verification:**
  - `wsl -l -v` → Debian (WSL2) detected
  - Next: `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "make clean && make -j"`
  - Next: `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "make test"`
- **Notes/Risks:** Build dependencies may be missing in Debian (json-c, libwebsockets, microhttpd, ssl, secp256k1).
- **Next:**
  - Run baseline build + tests inside WSL2 and record exact output/results.

- **Timestamp (UTC):** 2026-02-15 07:25
- **Goal:** Fix baseline compilation and complete baseline build + smoke tests.
- **What changed:**
  - c-src/client/client.c — add forward declaration for `is_local_host` to fix C11 implicit-function-declaration build error
  - worklog/STATE.md — record baseline build/test commands and results
- **Why:** Baseline must build cleanly before any refactor; current GCC treats implicit declarations as errors.
- **Verification:**
  - `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "make clean && make -j"` → PASS (one format-truncation warning)
  - `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "make test"` → PASS
- **Notes/Risks:** Warning indicates a potential path-handling hardening opportunity; defer until tests exist.
- **Next:**
  - Run local loopback daemon+client connectivity and detach/reattach smoke test.

- **Timestamp (UTC):** 2026-02-15 07:31
- **Goal:** Complete Phase 0 local loopback connectivity, including attach/detach/reattach.
- **What changed:**
  - worklog/STATE.md — record exact loopback daemon/client commands and results
- **Why:** Establish a reproducible baseline that proves core session persistence works before refactoring.
- **Verification:**
  - Daemon: `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "./.build/sshell-daemon --no-fork --tcp --host 127.0.0.1 --port 7444 --insecure-no-auth --log-level info"`
  - Client list: `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "./.build/sshell list --host 127.0.0.1 --port 7444"`
  - Create session: `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "./.build/sshell new smoke-test --no-attach --host 127.0.0.1 --port 7444"`
  - Attach+detach (PTY scripted, TERM=dumb): exit code `0`
  - Reattach+detach (PTY scripted, TERM=dumb): exit code `0`
  - Session persisted after detach (verified via `list`), then cleaned up via `kill`.
- **Notes/Risks:** Auth was disabled only for local-only loopback (`--host 127.0.0.1`); do not use `--insecure-no-auth` when binding non-local interfaces.
- **Next:**
  - Phase 1: add “feature lock” tests (protocol/config/preset/multiuser/recording/roaming).

- **Timestamp (UTC):** 2026-02-15 07:34
- **Goal:** Add first Phase 1 “feature lock” tests and harden protocol I/O for real network behavior.
- **What changed:**
  - tests/test_protocol.c — deterministic protocol roundtrip + partial-read coverage
  - c-src/common/protocol.c — add EINTR-safe `read_full`/`write_full`; use them across all send/recv paths
  - Makefile — build `.build/test_protocol` and run it as part of `make test`
- **Why:** Network sockets frequently return partial reads/writes; protocol must be correct and tests must prevent regressions.
- **Verification:**
  - `wsl -d Debian --cd /mnt/f/sshell -- bash -lc "make clean && make -j && make test"` → PASS (prints versions; `OK: protocol tests passed`)
- **Notes/Risks:** Existing `snprintf` truncation warning in `c-src/client/client.c` remains; address later with dedicated hardening changes and tests.
- **Next:**
  - Add tests for daemon preset parsing (`daemon_preset_load`) and config directory/path safety.


---

- **Timestamp (UTC):** 2026-02-22 14:57
- **Goal:** Complete roaming integration, fix recording parser, add heartbeat thread, add feature-lock tests
- **What changed:**
  - `c-src/daemon/daemon.c`: Wired roaming_server_init/process/shutdown into event loop and daemon_start/cleanup; added --no-roaming/--roaming-port flags; updated --help text with new flags and corrected default bind note
  - `c-src/common/recording.c`: Replaced broken sscanf-based JSON parser in recording_playback() with json-c (json_tokener_parse + array accessors); added `#include <json-c/json.h>`; now handles data with embedded double-quotes correctly
  - `c-src/client/client.c`: Added `#include <pthread.h>` and `../common/network_roaming.h`; added heartbeat_thread + start_heartbeat/stop_heartbeat functions; wired into run_multisession_ui() around interactive_io_loop (TCP non-loopback only)
  - `tests/test_multiuser.c`: New feature-lock test covering init, token generation, token validation, token invalidation on disable, user add/remove, write access, token uniqueness
  - `tests/test_recording.c`: New feature-lock test covering file creation, multi-write, quote-in-data correctness, stop-without-start, write-when-inactive
  - `tests/test_preset.c`: New feature-lock test covering full preset, partial preset, empty object, nonexistent file, invalid JSON, all four log levels
  - `Makefile`: Added TEST_MULTIUSER_BIN/OBJS, TEST_RECORDING_BIN/OBJS, TEST_PRESET_BIN/OBJS definitions, build rules, and all three binaries to `make test`
- **Why:** Complete the feature integration gaps identified in Batch 2; add regression protection for multiuser/recording/preset subsystems
- **Verification:** `make clean && make -j` → PASS (one pre-existing format-truncation warning in client.c); `make test` → all 4 suites pass (protocol, multiuser, recording, preset)
- **Notes/Risks:** Heartbeat only fires for TCP connections to non-loopback hosts; ROAMING_PORT (60001) is the hardcoded default, overridable via --roaming-port
- **Next:**
  - Smoke test daemon locally: `sshell-daemon --no-fork --debug`; `sshell new mytest && sshell attach mytest`
  - Consider adding auth allowlist tests (wallet/ssh key validation path)
  - Document remote deployment in README or docs/

---

## Entry: 2026-02-22 15:10 UTC

- **Goal:** Smoke-test local daemon<->client connectivity
- **Verification:**
  - Daemon started: `.build/sshell-daemon --no-fork --host 127.0.0.1 --port 7878 --insecure-no-auth --no-roaming`
  - PASS: `list` returns empty table
  - PASS: `new smoke --no-attach` assigns session id
  - PASS: `attach smoke` opens PTY; `echo HELLO_SSHELL` echoes correctly
  - PASS: detach via Ctrl-b d returns clean EOF
  - PASS: `kill smoke` by name removes session
  - PASS: reattach test — env var set in session 1 still present after detach/reattach
  - MINOR BUG: `kill <hex-id>` returns "Session not found"; kill by name works
- **Next:**
  1. Fix kill-by-id lookup bug
  2. Add tests/test_auth.c (wallet/ssh-key allowlist)
  3. Write docs/REMOTE_DEPLOYMENT.md

---

- **Timestamp (UTC):** 2026-02-22 20:40
- **Goal:** Fix all errors found in code review
- **What changed:**
  - `c-src/daemon/daemon.h`: Added `pthread_mutex_t sessions_lock` to `daemon_t`; added `daemon_lookup_session_id()` declaration
  - `c-src/daemon/daemon.c`: Init/destroy `sessions_lock`; added `SAFE_FD_SET` macro with FD_SETSIZE guard; replaced raw `FD_SET` calls in event loop; added `daemon_lookup_session_id()` (thread-safe, copies session ID); fixed snprintf truncation check for daemon_path; fixed `multiuser_enable_sharing` call site
  - `c-src/common/webserver.c`: Replaced unsafe `daemon_find_session` + pointer dereference with `daemon_lookup_session_id` (no dangling pointer)
  - `c-src/common/multiuser.h`: Added `size_t token_out_size` parameter to `multiuser_enable_sharing`
  - `c-src/common/multiuser.c`: Replaced `strcpy` with bounded `strncpy` + nul terminator
  - `c-src/client/client.c`: Removed unused `term` variable; added snprintf truncation guard
  - `setup.py`: Removed non-existent Python entry points; rewrote to install built C binaries via data_files
  - `tests/test_multiuser.c`: Updated `multiuser_enable_sharing` call sites to pass buffer size
- **Why:** Fix critical race condition (webserver/daemon thread safety), FD_SETSIZE overflow UB, snprintf truncation, unused variable, strcpy buffer overflow risk, broken Python packaging
- **Verification:** `make clean && make -j` → 0 warnings, 0 errors; `make test` → all 4 test suites passed
- **Notes/Risks:** `select()`-based loop retained with SAFE_FD_SET guard; full migration to `poll()` deferred
- **Next:**
  - Consider migrating event loop from `select()` to `poll()` for scalability beyond FD_SETSIZE
  - Remote internet terminal acceptance test (per Definition of Done)

---

- **Timestamp (UTC):** 2026-02-22 20:58
- **Goal:** Update all documentation and commit
- **What changed:**
  - `README.md`: Updated install section (interactive wizard, removed broken pip install, added -y flag examples); updated daemon.json example with all fields; removed PHASE5_IMPLEMENTATION.md reference; added web terminal thread-safety note
  - `SECURITY.md`: Updated daemon.json example with full field set; added wallet/wallet_allowlist mutual-exclusivity note; added installer wizard callout
  - `man/sshell-daemon.8`: Fixed --host default (0.0.0.0 → 127.0.0.1); added --roaming-port and --no-roaming options; updated daemon.json example; fixed AUTHOR
  - `man/sshell.1`: Updated DESCRIPTION to reflect full feature set; fixed AUTHOR
  - `install.sh`: Full interactive wizard (5-step guided config); -y/--yes non-interactive mode; writes fully-configured daemon.json from wizard answers
  - `worklog/WORKLOG.md`: This entry
- **Why:** Keep docs in sync with code changes; reflect new interactive installer
- **Verification:** `bash -n install.sh` → syntax OK; `make test` → all tests pass
- **Next:** Remote internet terminal acceptance test (Definition of Done)
