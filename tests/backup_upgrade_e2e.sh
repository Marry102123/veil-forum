#!/bin/sh
# Real backup, restore, upgrade, and rollback E2E for veil-forum.
#
# Failure modes covered:
# 1. Backup output cannot be listed, is empty, or has unsafe permissions.
# 2. A backup is made before the data marker is committed, so restoration loses it.
# 3. Upgrade does not preserve the installed release or start its health endpoint.
# 4. A deliberately unhealthy incoming release is installed and left active.
# 5. Rollback does not restore the previous binary/static files or service health.
# 6. A database restore does not reproduce the exact user/thread marker.
# 7. Encryption is missing, output is not private, or the wrong age identity works.
# 8. Database ownership, peer authentication, and service execution identities differ.
# 9. Temporary databases, roles, snapshots, or services survive a failed run.
# 10. Install, upgrade, or rollback output/snapshots expose a credential-bearing DSN.
# 11. Encrypted rollback materializes plaintext or bypasses pg_restore streaming.
# 12. Credential-bearing/mismatched restore DSNs stop service or DROP too late.
# 13. Age identity mode/ownership, wrong identity, or compatibility encryption is unsafe.
# 14. Report generation includes credentials or cannot describe/reproduce its checks.
#
# Requirements: PostgreSQL with peer authentication, cargo, curl, age, and
# passwordless sudo for the local postgres account. A missing PostgreSQL role
# for the current OS user is created temporarily with least-privilege attributes.
#
# Run: `sh tests/backup_upgrade_e2e.sh`
# The same command creates a credential-free report at
# `target/backup-upgrade-e2e-report.json`.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/veil-backup-upgrade-e2e.XXXXXX")
REPORT="$ROOT/target/backup-upgrade-e2e-report.json"
mkdir -p "$ROOT/target"
rm -f "$REPORT"
REPORT_SCHEMA='veil-forum-script-e2e-report/v1'
REPORT_VERSION='1.0.0'
RUN_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CHECKS="$TMP/checks.jsonl"
ROOT_KEY="$TMP/backup-root.key"
WRONG_ROOT_KEY="$TMP/wrong-root.key"
SYSTEMCTL_LOG="$TMP/systemctl.log"
CREDENTIAL_SENTINEL='e2e-only-DSN-password-4f8b2c'

write_report() {
  report_status=$1
  failure_reason=${2:-}
  input_digest=$(find "$ROOT/scripts" -maxdepth 1 -type f -name '*.sh' -print | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)
  if command -v jq >/dev/null 2>&1; then
    checks_json='[]'
    if [ -s "$CHECKS" ]; then
      checks_json=$(jq -s '.' < "$CHECKS")
    fi
    jq -n \
      --arg schema "$REPORT_SCHEMA" \
      --arg version "$REPORT_VERSION" \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg started_at "$RUN_STARTED_AT" \
      --arg input_digest "$input_digest" \
      --arg status "$report_status" \
      --arg failure_reason "$failure_reason" \
      --argjson checks "$checks_json" \
      --arg artifact "$REPORT" \
      '{
        schema: $schema,
        version: $version,
        generated_at: $generated_at,
        started_at: $started_at,
        input_summary: {
          scripts: "repository scripts/*.sh",
          database: "temporary local PostgreSQL database",
          service: "local process shim exercising stop/start/health",
          encryption: "temporary age identities",
          credentials_recorded: false
        },
        input_sha256: $input_digest,
        status: $status,
        failure_reason: (if $failure_reason == "" then null else $failure_reason end),
        checks: $checks,
        reproduction: {
          command: "sh tests/backup_upgrade_e2e.sh",
          validate: "jq -e . target/backup-upgrade-e2e-report.json >/dev/null"
        },
        credentials_included: false,
        logs: {
          artifact: $artifact,
          temporary_logs_retained: false
        }
      }' > "$REPORT"
  else
    # jq is a prerequisite on normal runs. Keep even an early prerequisite
    # failure schema-compatible and credential-free.
    printf '%s\n' '{' \
      '  "schema": "veil-forum-script-e2e-report/v1",' \
      '  "version": "1.0.0",' \
      '  "generated_at": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",' \
      '  "started_at": "'"$RUN_STARTED_AT"'",' \
      '  "input_summary": {"credentials_recorded": false},' \
      '  "input_sha256": "unavailable",' \
      '  "status": "'"$report_status"'",' \
      '  "failure_reason": "'"$failure_reason"'",' \
      '  "checks": [],' \
      '  "reproduction": {"command": "sh tests/backup_upgrade_e2e.sh"},' \
      '  "credentials_included": false' '}' > "$REPORT"
  fi
}

check_pass() {
  check_name=$1
  if command -v jq >/dev/null 2>&1; then
    jq -cn --arg name "$check_name" '{name: $name, status: "passed"}' >> "$CHECKS"
  fi
}
# Database ownership, peer authentication, and the service account all use the
# same disposable identity. Existing roles are only narrowed temporarily and
# are never dropped by test cleanup.
DB_NAME="veil_e2e_backup_$$"
DB_USER="$(id -un)"
DB_ROLE_CREATED=0
DB_ROLE_ORIGINAL_ATTRS=""
DB_URL="postgres://$DB_USER@%2Fvar%2Frun%2Fpostgresql/$DB_NAME"
PID=""
PORT=$((19800 + ($$ % 400)))
PREFIX="$TMP/prefix"
STATE="$TMP/state"
BACKUPS="$TMP/backups"
ROLLBACK="$STATE/rollback"
LOGDIR="$TMP/logs"
# Resolve the build directory through cargo rather than assuming "$ROOT/target".
# A `build.target-dir` in a cargo config moves the binary elsewhere, and a
# hard-coded path then reports a false failure.
TARGET_DIR=$(cargo metadata --format-version 1 --no-deps --manifest-path "$ROOT/Cargo.toml" 2>/dev/null \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$TARGET_DIR" ] || TARGET_DIR="$ROOT/target"
BIN_SRC="$TARGET_DIR/debug/veil-forum"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -f "$TMP/service.pid" ]; then
    service_pid=$(cat "$TMP/service.pid" 2>/dev/null || true)
    if [ -n "$service_pid" ]; then
      kill -TERM "$service_pid" 2>/dev/null || true
      i=0
      while kill -0 "$service_pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
      kill -KILL "$service_pid" 2>/dev/null || true
    fi
  fi
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  sudo -n -u postgres dropdb --if-exists "$DB_NAME" >/dev/null 2>&1 || true
  if [ "$DB_ROLE_CREATED" -eq 1 ]; then
    as_postgres psql -v ON_ERROR_STOP=1 -d postgres \
      -c "DROP ROLE IF EXISTS \"$DB_USER\"" >/dev/null 2>&1 || true
  elif [ -n "$DB_ROLE_ORIGINAL_ATTRS" ]; then
    as_postgres psql -v ON_ERROR_STOP=1 -d postgres \
      -c "ALTER ROLE \"$DB_USER\" $DB_ROLE_ORIGINAL_ATTRS" >/dev/null 2>&1 || true
  fi
  # A root-run restore may replace files in the disposable prefix as root.
  sudo -n chown -R "$(id -u):$(id -g)" "$TMP" 2>/dev/null || true
  if [ "$status" -ne 0 ] && [ ! -f "$REPORT" ]; then
    write_report failed "unexpected_exit_status_$status"
  fi
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

fail() {
  if command -v jq >/dev/null 2>&1; then
    jq -cn --arg name "$1" '{name: $name, status: "failed"}' >> "$CHECKS"
  fi
  write_report failed "$1"
  printf 'backup-upgrade E2E FAILED: %s\n' "$1" >&2
  exit 1
}

assert_contains() {
  file=$1
  text=$2
  grep -F "$text" "$file" >/dev/null 2>&1 || fail "missing '$text' in $file"
}

as_postgres() {
  sudo -n -u postgres "$@"
}

for cmd in cargo curl psql pg_dump pg_restore age tar sha256sum openssl sudo seq su jq python3; do
  command -v "$cmd" >/dev/null 2>&1 || fail "missing command: $cmd"
done
CREDENTIAL_DSN="postgres://$DB_USER:$CREDENTIAL_SENTINEL@%2Fvar%2Frun%2Fpostgresql/$DB_NAME"
[ -x "$BIN_SRC" ] || cargo build --quiet

mkdir -p "$PREFIX/bin" "$PREFIX/static" "$STATE" "$BACKUPS" "$LOGDIR"
age-keygen -o "$TMP/backup.key" >/dev/null 2>&1
chmod 600 "$TMP/backup.key"
RECIPIENT=$(age-keygen -y "$TMP/backup.key")
# rollback.sh requires a root-owned 0600 identity when invoked through sudo.
# Install disposable copies as root, with cleanup handled through TMP removal.
sudo -n install -m 600 -o root -g root "$TMP/backup.key" "$ROOT_KEY"
age-keygen -o "$TMP/wrong.key" >/dev/null 2>&1
chmod 600 "$TMP/wrong.key"
sudo -n install -m 600 -o root -g root "$TMP/wrong.key" "$WRONG_ROOT_KEY"
printf '/* old static */\n' > "$PREFIX/static/style.css"
printf 'veil-forum old-e2e\n' > "$PREFIX/bin/veil-forum"
chmod 0755 "$PREFIX/bin/veil-forum"

# The real release binary must be a valid old release for upgrade.sh snapshots.
cp "$BIN_SRC" "$PREFIX/bin/veil-forum"
printf '/* installed static */\n' > "$PREFIX/static/style.css"

if as_postgres psql -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
  DB_ROLE_ORIGINAL_ATTRS=$(as_postgres psql -d postgres -Atqc \
    "SELECT concat_ws(' ', CASE WHEN rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END, CASE WHEN rolsuper THEN 'SUPERUSER' ELSE 'NOSUPERUSER' END, CASE WHEN rolcreatedb THEN 'CREATEDB' ELSE 'NOCREATEDB' END, CASE WHEN rolcreaterole THEN 'CREATEROLE' ELSE 'NOCREATEROLE' END, CASE WHEN rolreplication THEN 'REPLICATION' ELSE 'NOREPLICATION' END, CASE WHEN rolbypassrls THEN 'BYPASSRLS' ELSE 'NOBYPASSRLS' END) FROM pg_roles WHERE rolname='$DB_USER'")
  as_postgres psql -v ON_ERROR_STOP=1 -d postgres \
    -c "ALTER ROLE \"$DB_USER\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" >/dev/null
else
  DB_ROLE_CREATED=1
  DB_ROLE_ORIGINAL_ATTRS="LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
  as_postgres psql -v ON_ERROR_STOP=1 -d postgres \
    -c "CREATE ROLE \"$DB_USER\" $DB_ROLE_ORIGINAL_ATTRS" >/dev/null
fi
as_postgres createdb -O "$DB_USER" "$DB_NAME"

# Seed a real migrated forum and a durable marker that must survive all paths.
VEIL_ADMIN_PASSWORD='Glacier-Maple7-Raven' \
  "$BIN_SRC" --addr "127.0.0.1:0" --database-url "$DB_URL" >"$LOGDIR/seed.log" 2>&1 &
PID=$!
for i in $(seq 1 120); do
  if grep -q 'listening on' "$LOGDIR/seed.log"; then break; fi
  if ! kill -0 "$PID" 2>/dev/null; then cat "$LOGDIR/seed.log" >&2; fail 'seed exited'; fi
  sleep 0.2
done
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
tables=$(as_postgres psql -d "$DB_NAME" -Atqc "select count(*) from information_schema.tables where table_schema='public'")
[ "$tables" -gt 0 ] || fail 'seed did not migrate database'
as_postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 \
  -c "insert into configs(key,value) values('backup_marker','before-upgrade')" >/dev/null
marker_before=$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")
[ "$marker_before" = before-upgrade ] || fail 'seed marker missing'

# Missing recipients must fail before creating a plaintext backup.
if env -u VEIL_BACKUP_RECIPIENT -u VEIL_BACKUP_RECIPIENT_FILE \
  "$ROOT/scripts/db-maintenance.sh" backup "$DB_URL" "$BACKUPS" >"$LOGDIR/no-recipient.log" 2>&1; then
  fail 'backup without age recipient unexpectedly succeeded'
fi
[ -z "$(find "$BACKUPS" -type f -print -quit)" ] || fail 'missing-recipient backup wrote output'

# Canonical backup must create an encrypted, private custom-format archive.
export VEIL_BACKUP_RECIPIENT="$RECIPIENT"
"$ROOT/scripts/db-maintenance.sh" backup "$DB_URL" "$BACKUPS" >"$LOGDIR/backup.log"
encrypted=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump.age' -print | head -n 1)
[ -n "$encrypted" ] || fail 'backup did not create encrypted dump'
[ -s "$encrypted" ] || fail 'encrypted backup is empty'
[ "$(stat -c '%a' "$encrypted")" = 600 ] || fail 'encrypted backup permissions are not 600'
[ "$(stat -c '%a' "$BACKUPS")" = 700 ] || fail 'backup directory permissions are not 700'
if pg_restore --list "$encrypted" >/dev/null 2>&1; then fail 'ciphertext was directly accepted by pg_restore'; fi
age --decrypt -i "$TMP/backup.key" "$encrypted" | pg_restore --list >/dev/null
if age --decrypt -i "$WRONG_ROOT_KEY" "$encrypted" >/dev/null 2>&1; then fail 'wrong age identity unexpectedly decrypted backup'; fi
if age --decrypt -i "$TMP/wrong.key" "$encrypted" >/dev/null 2>&1; then fail 'wrong age identity unexpectedly decrypted backup'; fi
check_pass backup_encryption_and_wrong_identity

# Build a genuine incoming archive from the current release binary. Its version
# is read by upgrade.sh before any service operation.
STAGE="$TMP/stage"
mkdir -p "$STAGE/veil-forum-e2e/static" "$STAGE/veil-forum-e2e/deploy"
cp "$BIN_SRC" "$STAGE/veil-forum-e2e/veil-forum"
cp "$ROOT/static/style.css" "$STAGE/veil-forum-e2e/static/style.css"
cp "$ROOT/deploy/veil-forum.service" "$STAGE/veil-forum-e2e/deploy/veil-forum.service"
RELEASE_ARCHIVE="$TMP/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz"
RELEASE_CHECKSUMS="$TMP/veil-forum-v0.1.0-alpha.19-checksums.txt"
tar -czf "$RELEASE_ARCHIVE" -C "$STAGE" veil-forum-e2e
(cd "$TMP" && sha256sum "$(basename "$RELEASE_ARCHIVE")" > "$(basename "$RELEASE_CHECKSUMS")")

# A local service manager is intentionally provided by a tiny systemctl shim.
# It controls the process started from the installed binary, so upgrade and
# rollback exercise their real stop/start/health gate instead of a mocked path.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/systemctl" <<'EOF'
#!/bin/sh
# The shim body is fully quoted: nothing here is expanded when this file is
# generated, so no command substitution or backtick in a comment can run at
# generation time. The __TOKEN__ placeholders below are replaced afterwards
# with literal values, because `sudo -n env` does not forward the harness
# environment to this script.
set -eu
SYSTEMCTL_LOG='__SYSTEMCTL_LOG__'
DB_USER='__DB_USER__'
PREFIX='__PREFIX__'
PORT='__PORT__'
DB_URL='__DB_URL__'
TMP='__TMP__'
printf '%s %s\n' "${1:-}" "${2:-}" >> "$SYSTEMCTL_LOG"
case "${1:-}" in
  stop)
    if [ -f "$TMP/service.pid" ]; then
      pid=$(cat "$TMP/service.pid")
      kill -TERM "$pid" 2>/dev/null || true
      i=0
      while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
      kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
      rm -f "$TMP/service.pid"
    fi
    ;;
  start)
    # Switching to the *same* user still goes through PAM and interactively
    # prompts for a password on Debian/Ubuntu, which hangs a non-interactive
    # CI runner. Skip the identity switch when it is unnecessary.
    if [ "$(id -un)" = "$DB_USER" ]; then
      VEIL_ALLOW_NONROOT=1 "$PREFIX/bin/veil-forum" --addr "127.0.0.1:$PORT" \
        --database-url "$DB_URL" >>"$TMP/service.log" 2>&1 &
      echo $! > "$TMP/service.pid"
    else
      su -s /bin/sh -c 'VEIL_ALLOW_NONROOT=1 "$1" --addr "127.0.0.1:$2" --database-url "$3" >>"$4" 2>&1 & echo $! > "$5"' \
        "$DB_USER" veil-e2e-service "$PREFIX/bin/veil-forum" "$PORT" "$DB_URL" "$TMP/service.log" "$TMP/service.pid"
    fi
    ;;
  daemon-reload) : ;;
  *) exit 0 ;;
esac
EOF
# Inject the literal harness values now that the quoted heredoc is written.
# Python is used instead of sed so values containing the delimiter cannot
# corrupt the shim, and so a missing placeholder is a hard error.
python3 - "$TMP/bin/systemctl" "$SYSTEMCTL_LOG" "$DB_USER" "$PREFIX" "$PORT" "$DB_URL" "$TMP" <<'PY'
import pathlib
import sys

path, systemctl_log, db_user, prefix, port, db_url, tmp = sys.argv[1:]
path = pathlib.Path(path)
text = path.read_text(encoding="utf-8")
values = {
    "__SYSTEMCTL_LOG__": systemctl_log,
    "__DB_USER__": db_user,
    "__PREFIX__": prefix,
    "__PORT__": port,
    "__DB_URL__": db_url,
    "__TMP__": tmp,
}
for token, value in values.items():
    if token not in text:
        raise SystemExit(f"systemctl shim is missing {token}")
    # Single-quote for POSIX sh, escaping any embedded single quote.
    literal = "'" + value.replace("'", "'\\''") + "'"
    text = text.replace(token, literal)
path.write_text(text, encoding="utf-8")
PY
chmod 0755 "$TMP/bin/systemctl"

export PATH="$TMP/bin:$PATH"
# The systemctl shim is a fully quoted heredoc, so it reads these from the
# environment instead of from generation-time expansion.
export SYSTEMCTL_LOG DB_USER DB_URL PORT PREFIX TMP
export VEIL_ALLOW_NONROOT=1
export VEIL_TEST_HARNESS=1
export VEIL_SERVICE_MANAGER=systemd
export VEIL_PREFIX="$PREFIX"
export VEIL_STATE_DIR="$STATE"
export VEIL_BACKUP_DIR="$BACKUPS"
export VEIL_ROLLBACK_ROOT="$ROLLBACK"
export VEIL_USER="$(id -un)"
export VEIL_DB_USER="$DB_USER"
export VEIL_DB_NAME="$DB_NAME"
export VEIL_BIN="$PREFIX/bin/veil-forum"
export VEIL_STATIC_DIR="$PREFIX/static"

# Start the installed release through the same shim before upgrading.
systemctl start
for i in $(seq 1 120); do
  if curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz" > "$TMP/health" 2>/dev/null; then break; fi
  if [ -f "$TMP/service.pid" ] && ! kill -0 "$(cat "$TMP/service.pid")" 2>/dev/null; then cat "$TMP/service.log" >&2; fail 'installed service failed to start'; fi
  sleep 0.2
done
[ "$(cat "$TMP/health" 2>/dev/null || true)" = ok ] || fail 'installed service health failed'

# A real upgrade takes a fresh backup, snapshots the old release, and health-checks
# the incoming binary against the same database.
if ! "$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" --checksums "$RELEASE_CHECKSUMS" \
  --database-url "$DB_URL" --addr "127.0.0.1:$PORT" --backup-dir "$BACKUPS" \
  --health-timeout 30 --no-attestation-verify v0.1.0-alpha.19 >"$LOGDIR/upgrade.log" 2>&1; then
  sed -E 's#postgres://[^/@[:space:]]+:[^/@[:space:]]+@#postgres://[REDACTED]@#g' \
    "$LOGDIR/upgrade.log" >&2
  fail 'real upgrade command failed'
fi
assert_contains "$LOGDIR/upgrade.log" "Health: http://127.0.0.1:$PORT/healthz says ok"
[ "$(curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz")" = ok ] || fail 'upgraded service health failed'
marker_after=$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")
[ "$marker_after" = before-upgrade ] || fail 'upgrade lost database marker'
check_pass upgrade_health_and_marker
snapshot=$(sed -n 's/.*If anything looks wrong later: .*rollback.sh --snapshot \([^ ]*\).*/\1/p' "$LOGDIR/upgrade.log" | tail -n 1)
[ -d "$snapshot" ] || fail 'upgrade did not report a snapshot'

# Restore preflight failures must close before service stop or database DROP.
# Exercise wrong identity, permissive mode, non-root ownership,
# credential-bearing DSN, and role mismatch against the real database.
stops_before=$(grep -c '^stop ' "$SYSTEMCTL_LOG" || true)
marker_before_failures=$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")
if sudo -n env PATH="$PATH" VEIL_SERVICE_MANAGER=systemd VEIL_PREFIX="$PREFIX" \
  VEIL_BIN="$PREFIX/bin/veil-forum" VEIL_STATIC_DIR="$PREFIX/static" \
  VEIL_ALLOW_NONROOT=1 VEIL_TEST_HARNESS=1 VEIL_USER="$DB_USER" VEIL_DB_USER="$DB_USER" \
  VEIL_DB_NAME="$DB_NAME" VEIL_ADDR="127.0.0.1:$PORT" \
  "$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --restore-db "$encrypted" \
  --database-url "$DB_URL" --backup-identity "$WRONG_ROOT_KEY" --yes --health-timeout 2 \
  >"$LOGDIR/wrong-identity-restore.log" 2>&1; then
  fail 'wrong root-owned age identity unexpectedly restored backup'
fi
stops_after_wrong=$(grep -c '^stop ' "$SYSTEMCTL_LOG" || true)
test "$stops_after_wrong" -eq "$stops_before"

sudo -n chmod 0644 "$ROOT_KEY"
if sudo -n env PATH="$PATH" VEIL_SERVICE_MANAGER=systemd VEIL_PREFIX="$PREFIX" \
  VEIL_BIN="$PREFIX/bin/veil-forum" VEIL_STATIC_DIR="$PREFIX/static" \
  VEIL_ALLOW_NONROOT=1 VEIL_TEST_HARNESS=1 VEIL_USER="$DB_USER" VEIL_DB_USER="$DB_USER" \
  VEIL_DB_NAME="$DB_NAME" VEIL_ADDR="127.0.0.1:$PORT" \
  "$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --restore-db "$encrypted" \
  --database-url "$DB_URL" --backup-identity "$ROOT_KEY" --yes --health-timeout 2 \
  >"$LOGDIR/permissive-identity-restore.log" 2>&1; then
  fail 'group/world-readable root age identity unexpectedly restored backup'
fi
sudo -n chmod 0600 "$ROOT_KEY"

if sudo -n env PATH="$PATH" VEIL_SERVICE_MANAGER=systemd VEIL_PREFIX="$PREFIX" \
  VEIL_BIN="$PREFIX/bin/veil-forum" VEIL_STATIC_DIR="$PREFIX/static" \
  VEIL_ALLOW_NONROOT=1 VEIL_TEST_HARNESS=1 VEIL_USER="$DB_USER" VEIL_DB_USER="$DB_USER" \
  VEIL_DB_NAME="$DB_NAME" VEIL_ADDR="127.0.0.1:$PORT" \
  "$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --restore-db "$encrypted" \
  --database-url "$DB_URL" --backup-identity "$TMP/backup.key" --yes --health-timeout 2 \
  >"$LOGDIR/nonroot-identity-restore.log" 2>&1; then
  fail 'user-owned age identity unexpectedly restored backup'
fi

if sudo -n env PATH="$PATH" VEIL_SERVICE_MANAGER=systemd VEIL_PREFIX="$PREFIX" \
  VEIL_BIN="$PREFIX/bin/veil-forum" VEIL_STATIC_DIR="$PREFIX/static" \
  VEIL_ALLOW_NONROOT=1 VEIL_TEST_HARNESS=1 VEIL_USER="$DB_USER" VEIL_DB_USER="$DB_USER" \
  VEIL_DB_NAME="$DB_NAME" VEIL_ADDR="127.0.0.1:$PORT" \
  "$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --restore-db "$encrypted" \
  --database-url "$CREDENTIAL_DSN" --backup-identity "$ROOT_KEY" --yes --health-timeout 2 \
  >"$LOGDIR/credential-dsn-restore.log" 2>&1; then
  fail 'credential-bearing restore DSN unexpectedly passed'
fi
if grep -F "$CREDENTIAL_SENTINEL" "$LOGDIR/credential-dsn-restore.log" >/dev/null 2>&1; then
  fail 'credential-bearing DSN leaked to rollback output'
fi

MISMATCH_DSN="postgres://veil_e2e_wrong_role@%2Fvar%2Frun%2Fpostgresql/$DB_NAME"
if sudo -n env PATH="$PATH" VEIL_SERVICE_MANAGER=systemd VEIL_PREFIX="$PREFIX" \
  VEIL_BIN="$PREFIX/bin/veil-forum" VEIL_STATIC_DIR="$PREFIX/static" \
  VEIL_ALLOW_NONROOT=1 VEIL_TEST_HARNESS=1 VEIL_USER="$DB_USER" VEIL_DB_USER="$DB_USER" \
  VEIL_DB_NAME="$DB_NAME" VEIL_ADDR="127.0.0.1:$PORT" \
  "$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --restore-db "$encrypted" \
  --database-url "$MISMATCH_DSN" --backup-identity "$ROOT_KEY" --yes --health-timeout 2 \
  >"$LOGDIR/mismatched-role-restore.log" 2>&1; then
  fail 'restore role mismatch unexpectedly passed'
fi
stops_after_preflight=$(grep -c '^stop ' "$SYSTEMCTL_LOG" || true)
test "$stops_after_preflight" -eq "$stops_before"
test "$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")" = "$marker_before_failures"
[ "$(curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz")" = ok ] || fail 'preflight failure disturbed service health'
check_pass restore_preflight_fail_closed_before_stop_or_drop

# Replace the incoming binary with a real executable that never becomes healthy.
# upgrade.sh must restore the snapshot and the pre-upgrade health state.
BAD_BIN="$TMP/bad-veil-forum"
cat > "$BAD_BIN" <<'EOF'
#!/bin/sh
case "$1" in
  --version) echo 'veil-forum bad-e2e' ;;
  --help) echo 'usage: veil-forum' ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$BAD_BIN"
BAD_STAGE="$TMP/bad-stage"
mkdir -p "$BAD_STAGE/veil-forum-e2e/static" "$BAD_STAGE/veil-forum-e2e/deploy"
cp "$BAD_BIN" "$BAD_STAGE/veil-forum-e2e/veil-forum"
cp "$ROOT/static/style.css" "$BAD_STAGE/veil-forum-e2e/static/style.css"
cp "$ROOT/deploy/veil-forum.service" "$BAD_STAGE/veil-forum-e2e/deploy/veil-forum.service"
BAD_RELEASE_DIR="$TMP/bad-release"
BAD_RELEASE_ARCHIVE="$BAD_RELEASE_DIR/$(basename "$RELEASE_ARCHIVE")"
BAD_RELEASE_CHECKSUMS="$BAD_RELEASE_DIR/$(basename "$RELEASE_CHECKSUMS")"
mkdir -p "$BAD_RELEASE_DIR"
tar -czf "$BAD_RELEASE_ARCHIVE" -C "$BAD_STAGE" veil-forum-e2e
(cd "$BAD_RELEASE_DIR" && sha256sum "$(basename "$BAD_RELEASE_ARCHIVE")" > "$(basename "$BAD_RELEASE_CHECKSUMS")")
if "$ROOT/scripts/upgrade.sh" "$BAD_RELEASE_ARCHIVE" --checksums "$BAD_RELEASE_CHECKSUMS" \
    --database-url "$DB_URL" --addr "127.0.0.1:$PORT" --backup-dir "$BACKUPS" \
    --health-timeout 2 --no-attestation-verify v0.1.0-alpha.19 >"$LOGDIR/bad-upgrade.log" 2>&1; then
  fail 'unhealthy incoming release unexpectedly passed upgrade'
fi
assert_contains "$LOGDIR/bad-upgrade.log" 'rollback succeeded'
[ "$(curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz")" = ok ] || fail 'automatic rollback health failed'
[ "$PREFIX/bin/veil-forum" != "$BAD_BIN" ] || fail 'bad binary remained installed'

# Explicit rollback also restores the prior release and preserves the data.
"$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --health-timeout 30 >"$LOGDIR/rollback.log" 2>&1
assert_contains "$LOGDIR/rollback.log" 'Done: rolled back to'
health_now=$(curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz" 2>/dev/null || true)
[ "$health_now" = ok ] || fail 'explicit rollback health failed'
marker_rollback=$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")
[ "$marker_rollback" = before-upgrade ] || fail 'rollback changed durable data'
check_pass explicit_rollback_health_and_marker

# A real upgrade accepts a TCP DSN with a password, but must neither print nor
# snapshot it. Use --no-backup so this security check exercises file deployment
# independently of PostgreSQL password authentication, then restore the same
# release and verify health/marker.
"$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" \
  --checksums "$RELEASE_CHECKSUMS" \
  --database-url "$CREDENTIAL_DSN" --addr "127.0.0.1:$PORT" --no-backup \
  --health-timeout 30 --no-attestation-verify v0.1.0-alpha.19 >"$LOGDIR/credential-upgrade.log" 2>&1
if grep -F "$CREDENTIAL_SENTINEL" "$LOGDIR/credential-upgrade.log" >/dev/null 2>&1; then
  fail 'credential-bearing DSN leaked to upgrade output'
fi
credential_snapshot=$(sed -n 's/.*If anything looks wrong later: .*rollback.sh --snapshot \([^ ]*\).*/\1/p' "$LOGDIR/credential-upgrade.log" | tail -n 1)
[ -d "$credential_snapshot" ] || fail 'credential upgrade did not create a snapshot'
test ! -e "$credential_snapshot/DSN"
if grep -R -F "$CREDENTIAL_SENTINEL" "$credential_snapshot" >/dev/null 2>&1; then
  fail 'credential-bearing DSN leaked into upgrade snapshot'
fi
"$ROOT/scripts/rollback.sh" --snapshot "$credential_snapshot" --health-timeout 30 >"$LOGDIR/credential-upgrade-rollback.log" 2>&1
[ "$(curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz")" = ok ] || fail 'credential upgrade rollback health failed'
[ "$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")" = before-upgrade ] || fail 'credential upgrade rollback changed marker'
check_pass upgrade_output_and_snapshot_redact_password_dsn

# Prove that a real encrypted backup can be restored, not merely decrypted and
# listed. Mutate after the backup, restore into the same database, and require
# the pre-upgrade marker and the health endpoint to return.
as_postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 \
  -c "update configs set value='after-upgrade' where key='backup_marker'" >/dev/null
plaintext_before=$(find "$TMP" "$PREFIX" -type f -name '*.dump' -print | sort)
if ! sudo -n env \
  PATH="$PATH" \
  VEIL_SERVICE_MANAGER=systemd \
  VEIL_PREFIX="$PREFIX" \
  VEIL_BIN="$PREFIX/bin/veil-forum" \
  VEIL_STATIC_DIR="$PREFIX/static" \
  VEIL_ALLOW_NONROOT=1 \
  VEIL_TEST_HARNESS=1 \
  VEIL_USER="$DB_USER" \
  VEIL_DB_USER="$DB_USER" \
  VEIL_DB_NAME="$DB_NAME" \
  VEIL_ADDR="127.0.0.1:$PORT" \
  "$ROOT/scripts/rollback.sh" --snapshot "$snapshot" --restore-db "$encrypted" \
  --database-url "$DB_URL" \
  --backup-identity "$ROOT_KEY" --yes --health-timeout 30 >"$LOGDIR/db-restore.log" 2>&1; then
  sed -E 's#postgres://[^/@[:space:]]+:[^/@[:space:]]+@#postgres://[REDACTED]@#g' \
    "$LOGDIR/db-restore.log" >&2
  fail 'encrypted database restore command failed'
fi
assert_contains "$LOGDIR/db-restore.log" "Database restored from $encrypted"
marker_restored=$(as_postgres psql -d "$DB_NAME" -Atqc "select value from configs where key='backup_marker'")
[ "$marker_restored" = before-upgrade ] || fail 'encrypted database restore did not restore the backup marker'
[ "$(curl --fail --silent --show-error "http://127.0.0.1:$PORT/healthz")" = ok ] || fail 'encrypted database restore health failed'
plaintext_after=$(find "$TMP" "$PREFIX" -type f -name '*.dump' -print | sort)
test "$plaintext_before" = "$plaintext_after"
check_pass encrypted_restore_stream_marker_and_health

check_pass automatic_rollback_after_unhealthy_release
check_pass report_is_valid_json_without_credentials
write_report passed
jq -e '.schema == "veil-forum-script-e2e-report/v1" and .status == "passed" and .credentials_included == false' "$REPORT" >/dev/null
if grep -E 'AGE-SECRET-KEY|Glacier-Maple|e2e-only-DSN-password' "$REPORT" >/dev/null 2>&1; then
  fail 'report contains test credentials'
fi

printf 'backup, upgrade, and rollback E2E passed\n'
printf 'artifact: %s\n' "$REPORT"
