#!/bin/sh
# Startup, health, and SIGTERM smoke test against a real PostgreSQL server.
#
# Requires psql/createdb and a reachable server. The scratch database is created
# and dropped by this script, so it never touches a real installation.
#
#   DATABASE_URL=postgres://user@%2Fvar%2Frun%2Fpostgresql/veil_forum_test tests/startup-smoke.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ ! -x "$ROOT/target/release/veil-forum" ]; then
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
fi

DATABASE_URL="${DATABASE_URL:-postgres://user@%2Fvar%2Frun%2Fpostgresql/veil_forum_test}"
# Split the URL into the part before the query string and the query string
# itself, then swap only the database name for a scratch one. Splitting this way
# leaves the socket host (url-encoded in the authority) untouched.
case "$DATABASE_URL" in
  *\?*) URL_BASE=${DATABASE_URL%%\?*}; URL_QUERY="?${DATABASE_URL#*\?}" ;;
  *) URL_BASE=$DATABASE_URL; URL_QUERY="" ;;
esac
BASE_DB=${URL_BASE##*/}
case "$BASE_DB" in
  ''|*[!A-Za-z0-9_]*) echo "error: cannot derive a database name from DATABASE_URL" >&2; exit 1 ;;
esac
SMOKE_DB="veil_smoke_$$"
SMOKE_URL="${URL_BASE%/*}/${SMOKE_DB}${URL_QUERY}"
# Administrative connection: same server, the base database from DATABASE_URL.
ADMIN_URL="$DATABASE_URL"

command -v psql >/dev/null 2>&1 || { echo 'error: psql is required' >&2; exit 1; }
# psql is used for CREATE/DROP DATABASE: the standalone createdb tool treats a
# connection URI as a literal database name rather than a connection string.

TMP=$(mktemp -d)
PORT=$((19000 + ($$ % 1000)))
LOG="$TMP/server.log"
PIDFILE="$TMP/server.pid"
cleanup() {
  if [ -f "$PIDFILE" ]; then kill -TERM "$(cat "$PIDFILE")" 2>/dev/null || true; fi
  psql "$ADMIN_URL" -c "DROP DATABASE IF EXISTS $SMOKE_DB" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c "CREATE DATABASE $SMOKE_DB"

VEIL_ADMIN_PASSWORD='smoke-test-password' "$ROOT/target/release/veil-forum" \
  --addr "127.0.0.1:$PORT" --database-url "$SMOKE_URL" >"$LOG" 2>&1 &
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

# The startup banner must show the redacted database target, never a password.
grep -q 'veil-forum database: postgres' "$LOG"

kill -TERM "$pid"
wait "$pid" || true
if kill -0 "$pid" 2>/dev/null; then
  echo 'server did not exit after SIGTERM' >&2
  exit 1
fi

# A failing connection must not print the password either, in any of the forms
# sqlx accepts. Each attempt exits non-zero; the secret has to stay out of both
# the banner and the error.
SECRET='smoke-test-secret-9c1f'
for dsn in \
  "postgres://u:${SECRET}@127.0.0.1:5599/db" \
  "postgres://u:p@ss${SECRET}@127.0.0.1:5599/db" \
  "host=127.0.0.1 port=5599 password=${SECRET} user=u dbname=x" \
  "postgres:///db?host=127.0.0.1&port=5599&password=${SECRET}"; do
  if "$ROOT/target/release/veil-forum" --addr 127.0.0.1:0 --database-url "$dsn" \
      > "$TMP/redact.log" 2>&1; then
    echo "unexpected success for the unreachable database" >&2
    exit 1
  fi
  if grep -q "$SECRET" "$TMP/redact.log"; then
    echo "the password leaked into the log for: $dsn" >&2
    cat "$TMP/redact.log" >&2
    exit 1
  fi
  grep -q '\*\*\*' "$TMP/redact.log" ||
    { echo "no redaction marker in the log for: $dsn" >&2; exit 1; }
done

# The baseline migration and first-run seeding must have run.
tables=$(psql "$SMOKE_URL" -At -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
test "$tables" -gt 0
admins=$(psql "$SMOKE_URL" -At -c "SELECT count(*) FROM users WHERE is_admin")
test "$admins" -eq 1

echo 'startup, healthz, REDACTED banner, and SIGTERM smoke test passed'
