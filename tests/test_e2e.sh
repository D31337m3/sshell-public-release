#!/usr/bin/env bash
# tests/test_e2e.sh - End-to-end test for typical SShell use routine.
#
# Usage: bash tests/test_e2e.sh [DAEMON_BIN] [CLIENT_BIN]
#
# Tests: start daemon, list (empty), create session, list (one entry),
#        rename session, list (renamed), kill session, list (empty), stop daemon.
#
# Exit code: 0 on full pass, 1 on any failure.

set -euo pipefail

DAEMON="${1:-.build/sshell-daemon}"
CLIENT="${2:-.build/sshell}"

HOST="127.0.0.1"
PORT="17444"
PASS=0
FAIL=0
DAEMON_PID=""

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
        DAEMON_PID=""
    fi
}
trap cleanup EXIT

echo "SShell end-to-end test suite"
echo "  daemon : $DAEMON"
echo "  client : $CLIENT"
echo "  address: $HOST:$PORT"
echo ""

# ── 1. Start daemon ────────────────────────────────────────────────────────────
echo "[1] Start daemon"
"$DAEMON" --no-fork --tcp --host "$HOST" --port "$PORT" \
          --insecure-no-auth --no-roaming 2>/dev/null &
DAEMON_PID=$!

# Wait up to 3 seconds for daemon to accept connections.
READY=0
for i in 1 2 3; do
    sleep 1
    if "$CLIENT" --host "$HOST" --port "$PORT" list >/dev/null 2>&1; then
        READY=1; break
    fi
done
if [ "$READY" -eq 1 ]; then
    pass "Daemon started and accepting connections"
else
    fail "Daemon did not start within 3 seconds"
    exit 1
fi

BASE_ARGS="--host $HOST --port $PORT"

# ── 2. List sessions (expect empty) ────────────────────────────────────────────
echo "[2] List sessions (expect empty)"
OUT=$("$CLIENT" $BASE_ARGS list 2>&1)
if echo "$OUT" | grep -qiE "no sessions|^ID\s"; then
    pass "List returns empty table"
else
    fail "Unexpected list output: $OUT"
fi

# ── 3. Create a session with --no-attach ──────────────────────────────────────
echo "[3] Create session 'smoke-test'"
OUT=$("$CLIENT" $BASE_ARGS new smoke-test --no-attach 2>&1)
if echo "$OUT" | grep -qi "smoke-test"; then
    pass "Session 'smoke-test' created"
else
    fail "Session creation failed: $OUT"
fi

# ── 4. List sessions (expect one entry) ───────────────────────────────────────
echo "[4] List sessions (expect smoke-test)"
OUT=$("$CLIENT" $BASE_ARGS list 2>&1)
if echo "$OUT" | grep -q "smoke-test"; then
    pass "Session 'smoke-test' appears in list"
else
    fail "Session not found in list: $OUT"
fi

# ── 5. Rename session ─────────────────────────────────────────────────────────
echo "[5] Rename 'smoke-test' -> 'smoke-renamed'"
OUT=$("$CLIENT" $BASE_ARGS rename smoke-test smoke-renamed 2>&1)
if echo "$OUT" | grep -qi "rename\|smoke-renamed"; then
    pass "Session renamed successfully"
else
    fail "Rename failed: $OUT"
fi

# ── 6. List sessions (expect renamed name) ────────────────────────────────────
echo "[6] List sessions (expect smoke-renamed)"
OUT=$("$CLIENT" $BASE_ARGS list 2>&1)
if echo "$OUT" | grep -q "smoke-renamed"; then
    pass "Renamed session 'smoke-renamed' appears in list"
else
    fail "Renamed session not found in list: $OUT"
fi
if echo "$OUT" | grep -q "smoke-test"; then
    fail "Old name 'smoke-test' still appears after rename"
fi

# ── 7. Kill session ───────────────────────────────────────────────────────────
echo "[7] Kill session 'smoke-renamed'"
OUT=$("$CLIENT" $BASE_ARGS kill smoke-renamed 2>&1)
if echo "$OUT" | grep -qi "kill\|terminat\|remov\|smoke"; then
    pass "Session killed"
else
    fail "Kill failed: $OUT"
fi

# ── 8. List sessions (expect empty again) ─────────────────────────────────────
echo "[8] List sessions (expect empty)"
# Give daemon a moment to reap the session.
sleep 1
OUT=$("$CLIENT" $BASE_ARGS list 2>&1)
if echo "$OUT" | grep -q "smoke-renamed"; then
    fail "Killed session still appears in list: $OUT"
else
    pass "Session list is empty after kill"
fi

# ── 9. Duplicate session name is rejected ─────────────────────────────────────
echo "[9] Duplicate session name rejected"
"$CLIENT" $BASE_ARGS new dup-check --no-attach >/dev/null 2>&1 || true
OUT=$("$CLIENT" $BASE_ARGS new dup-check --no-attach 2>&1) || true
if echo "$OUT" | grep -qi "already\|exist\|error"; then
    pass "Duplicate session name rejected"
else
    fail "Duplicate session name not rejected: $OUT"
fi
"$CLIENT" $BASE_ARGS kill dup-check >/dev/null 2>&1 || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: end-to-end tests had $FAIL failure(s)"
    exit 1
fi
echo "OK: all end-to-end tests passed"
