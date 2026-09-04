#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ ! -x "$ROOT/target/release/veil-forum" ]; then
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
fi
TMP=$(mktemp -d)
PORT=$((19000 + ($$ % 1000)))
LOG="$TMP/server.log"
PIDFILE="$TMP/server.pid"
trap 'if [ -f "$PIDFILE" ]; then kill -TERM "$(cat "$PIDFILE")" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT HUP INT TERM

VEIL_ADMIN_PASSWORD='smoke-test-password' "$ROOT/target/release/veil-forum" \
  --addr "127.0.0.1:$PORT" --data "$TMP/forum.db" >"$LOG" 2>&1 &
echo $! > "$PIDFILE"
pid=$(cat "$PIDFILE")

ready=0
i=1
while [ "$i" -le 40 ]; do
  if curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz" > "$TMP/healthz"; then
    ready=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$LOG" >&2
    exit 1
  fi
  sleep 0.25
  i=$((i + 1))
done
test "$ready" -eq 1
test "$(cat "$TMP/healthz")" = ok

kill -TERM "$pid"
wait "$pid" || true
if kill -0 "$pid" 2>/dev/null; then
  echo 'server did not exit after SIGTERM' >&2
  exit 1
fi

echo 'startup, healthz, and SIGTERM smoke test passed'
