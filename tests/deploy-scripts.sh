#!/bin/sh
# Deployment script tests: lib.sh helpers plus install/upgrade/rollback
# against stubbed system tools. No root and no live server required.
#
# Everything privileged is redirected through environment overrides
# (VEIL_PREFIX, VEIL_STATE_DIR, VEIL_BACKUP_DIR, VEIL_ROLLBACK_ROOT,
# VEIL_SERVICE_MANAGER, VEIL_ALLOW_NONROOT) and PATH stubs.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

# Captured before the stub directory shadows PATH.
REAL_INSTALL=$(command -v install)
export REAL_INSTALL
FAIL_ON=""
export FAIL_ON

BIN_DIR="$TMP/bin"
PREFIX="$TMP/prefix"
STATE="$TMP/state"
BACKUPS="$TMP/backups"
ROLLBACK="$STATE/rollback"
mkdir -p "$BIN_DIR" "$PREFIX" "$STATE" "$BACKUPS"
STUB_LOG="$TMP/stub.log"
export STUB_LOG

# --- stubs ---------------------------------------------------------------
cat > "$BIN_DIR/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >> "$STUB_LOG"
exit 0
EOF
cat > "$BIN_DIR/curl" <<'EOF'
#!/bin/sh
# Answers like /healthz ("ok") until STUB_CURL_BUDGET failures are spent;
# each failure appends one line to STUB_CURL_COUNT. A huge budget simulates
# a dead server; the default budget of 0 is always healthy.
for _arg in "$@"; do _url=$_arg; done
_budget=${STUB_CURL_BUDGET:-0}
_countfile=${STUB_CURL_COUNT:-/dev/null}
_n=0
if [ -f "$_countfile" ]; then _n=$(wc -l < "$_countfile"); fi
if [ "$_n" -lt "$_budget" ]; then
    echo x >> "$_countfile"
    exit 1
fi
printf 'ok'
EOF
cat > "$BIN_DIR/pg_dump" <<'EOF'
#!/bin/sh
set -eu
target=
for arg in "$@"; do
  case "$arg" in
    --file=*) target=${arg#--file=} ;;
  esac
done
[ -n "$target" ] || { echo "pg_dump stub: --file required" >&2; exit 1; }
printf 'PGDMP\000custom archive\n' > "$target"
EOF
cat > "$BIN_DIR/pg_restore" <<'EOF'
#!/bin/sh
set -eu
for arg in "$@"; do
  case "$arg" in
    --list) printf 'archive listing\n'; exit 0 ;;
  esac
done
exit 0
EOF
cat > "$BIN_DIR/psql" <<'EOF'
#!/bin/sh
set -eu
printf '12\n'
EOF
cat > "$BIN_DIR/install" <<'EOF'
#!/bin/sh
# Refuses to write to $FAIL_ON (the last argument is the destination), else
# runs the real install. Lets the suite simulate a failed file swap.
for _a in "$@"; do _dest=$_a; done
if [ -n "${FAIL_ON:-}" ] && [ "$_dest" = "$FAIL_ON" ]; then
  echo "install stub: refusing to write $FAIL_ON" >&2
  exit 1
fi
exec "$REAL_INSTALL" "$@"
EOF
chmod +x "$BIN_DIR"/systemctl "$BIN_DIR"/curl "$BIN_DIR"/pg_dump "$BIN_DIR"/pg_restore "$BIN_DIR"/psql "$BIN_DIR"/install

# Fake installed release and fake new release.
make_fake_binary() {
    printf '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "veil-forum %s"; exit 0; fi\necho "fake binary must not run" >&2; exit 1\n' "$2" > "$1"
    chmod +x "$1"
}
make_fake_binary "$TMP/old-binary" "0.1.0-alpha.18"
mkdir -p "$PREFIX/bin" "$PREFIX/static"
cp "$TMP/old-binary" "$PREFIX/bin/veil-forum"
printf '/* old */\n' > "$PREFIX/static/style.css"

mkdir -p "$TMP/stage-top/static"
make_fake_binary "$TMP/stage-top/veil-forum" "0.1.0-alpha.19"
printf '/* new */\n' > "$TMP/stage-top/static/style.css"
tar -czf "$TMP/archive.tar.gz" -C "$TMP" stage-top
mv "$TMP/stage-top" "$TMP/new-top"
(cd "$TMP" && sha256sum archive.tar.gz > checksums.txt)

export PATH="$BIN_DIR:$PATH"
export VEIL_ALLOW_NONROOT=1 VEIL_SERVICE_MANAGER=systemd
export VEIL_PREFIX="$PREFIX" VEIL_STATE_DIR="$STATE" VEIL_BACKUP_DIR="$BACKUPS"

# --- 1. lib.sh helpers ------------------------------------------------------
# shellcheck source=../scripts/lib.sh
. "$ROOT/scripts/lib.sh"

test "$(veil_socket_dsn)" = "postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum"
test "$(veil_socket_dsn app /tmp/pg/ forum)" = "postgres://app@%2Ftmp%2Fpg/forum"
# An empty argument falls back to the default, like an unset flag.
test "$(veil_socket_dsn '' /tmp db)" = "postgres://veil-forum@%2Ftmp/db"
test "$(veil_encode_socket_host '/var/run/postgresql')" = "%2Fvar%2Frun%2Fpostgresql"
test "$(veil_service_manager)" = "systemd"
test "$(veil_installed_version "$TMP/old-binary")" = "0.1.0-alpha.18"
test "$(veil_installed_version "$TMP/missing")" = "unknown"

# Name/path validators: the suite's guarantee against shell interpolation.
# veil_valid_* use `return`, so negative cases run in a subshell.
for _good in veil-forum "a.b-c_d" "abc123"; do
    veil_valid_name "$_good" || { echo "valid name rejected: $_good" >&2; exit 1; }
done
for _bad in "" "-x" ".x" "a;b" "a b" "a'b" 'a"b' 'a`b' 'a$b' "a&b" "a|b" "a/b" 'a(b)' 'a)b'; do
    if (veil_valid_name "$_bad"); then echo "invalid name accepted: $_bad" >&2; exit 1; fi
done
for _good in "/var/run/postgresql" "/tmp/archive.tar.gz" "127.0.0.1:8001" "[::1]:8001"; do
    veil_valid_path "$_good" || { echo "valid path rejected: $_good" >&2; exit 1; }
done
for _bad in "" "a'b" 'a"b' 'a`b' 'a$b' "a;b" "a&b" "a|b" "a b" 'a(b)' "a>b"; do
    if (veil_valid_path "$_bad"); then echo "invalid path accepted: $_bad" >&2; exit 1; fi
done
unset _good _bad
test "$(veil_sed_escape 'a&b|c')" = 'a\&b\|c'
test "$(veil_sed_escape 'a\b')" = 'a\\b'
test "$(veil_sed_escape 'plain')" = 'plain'
# veil_die exits the shell, so negative lib tests run in a subshell.
veil_wait_healthz "127.0.0.1:1" 3 || {
    echo "healthy check must pass" >&2
    exit 1
}
if (VEIL_DB_USER= veil_socket_dsn) >/dev/null 2>&1; then
    echo "empty user with no default must fail" >&2
    exit 1
fi
if (STUB_CURL_BUDGET=999999 STUB_CURL_COUNT="$TMP/c1" veil_wait_healthz "127.0.0.1:1" 2); then
    echo "failing health check must fail" >&2
    exit 1
fi

# --- 2. install.sh --dry-run --------------------------------------------------
printf '%s' 'dry-run-admin-password' > "$TMP/adminpw"
"$ROOT/scripts/install.sh" --dry-run --no-service \
    --binary "$TMP/old-binary" --static "$PREFIX/static" \
    --admin-password-file "$TMP/adminpw" >"$TMP/install.out" 2>&1 || {
    echo "install --dry-run failed" >&2
    cat "$TMP/install.out" >&2
    exit 1
}
grep -q 'Install plan:' "$TMP/install.out"
grep -q '(dry-run) nothing was changed' "$TMP/install.out"
# Dry runs change nothing: the fake install is untouched.
test "$(cat "$PREFIX/static/style.css")" = "/* old */"
if "$ROOT/scripts/install.sh" --dry-run --addr 203.0.113.1:8001 >/dev/null 2>&1; then
    echo "non-loopback addr without the flag must fail" >&2
    exit 1
fi
if "$ROOT/scripts/install.sh" --dry-run --bogus >/dev/null 2>&1; then
    echo "unknown option must fail" >&2
    exit 1
fi

# Metacharacter inputs are rejected before they can reach su/psql/sed, and
# nothing is executed: the marker file must stay absent.
rm -f "$TMP/inj"
if "$ROOT/scripts/install.sh" --dry-run --no-service \
    --binary "$TMP/old-binary" --static "$PREFIX/static" \
    --db-name 'x`id>$TMP/inj`' >/dev/null 2>&1; then
    echo "backtick db-name must fail" >&2
    exit 1
fi
if "$ROOT/scripts/install.sh" --dry-run --no-service \
    --binary "$TMP/old-binary" --static "$PREFIX/static" \
    --db-user 'u$(touch$TMP/inj)' >/dev/null 2>&1; then
    echo "dollar db-user must fail" >&2
    exit 1
fi
if "$ROOT/scripts/install.sh" --dry-run --no-service \
    --binary "$TMP/old-binary" --static "$PREFIX/static" \
    --db-socket '/tmp/a;b' >/dev/null 2>&1; then
    echo "semicolon db-socket must fail" >&2
    exit 1
fi
test ! -e "$TMP/inj" || { echo "injection executed" >&2; exit 1; }

# --- 3. upgrade.sh argument handling -------------------------------------------
if "$ROOT/scripts/upgrade.sh" >/dev/null 2>&1; then
    echo "missing archive must fail" >&2
    exit 1
fi
if "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" --no-backup --dry-run >/dev/null 2>&1; then
    echo "missing checksums must fail" >&2
    exit 1
fi
if "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" --checksums "$TMP/checksums.txt" \
    --database-url 'postgres://u@h/db' --db-name x --dry-run >/dev/null 2>&1; then
    echo "mixed database selectors must fail" >&2
    exit 1
fi
# Without a service manager the scripts refuse to touch a running release
# (dry runs still work: nothing is executed).
if ! VEIL_SERVICE_MANAGER=none "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" \
    --checksums "$TMP/checksums.txt" --no-backup --dry-run >/dev/null 2>&1; then
    echo "dry-run without a manager must still work" >&2
    exit 1
fi
if VEIL_SERVICE_MANAGER=none "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" \
    --checksums "$TMP/checksums.txt" --no-backup >/dev/null 2>&1; then
    echo "missing service manager must fail" >&2
    exit 1
fi

# --- 4. upgrade.sh --dry-run ----------------------------------------------------
DSN='postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum'
"$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" --checksums "$TMP/checksums.txt" \
    --database-url "$DSN" --addr 127.0.0.1:8001 --no-backup --dry-run >"$TMP/upgrade-dry.out" 2>&1
grep -q 'Upgrade plan: 0.1.0-alpha.18 -> 0.1.0-alpha.19' "$TMP/upgrade-dry.out"
grep -q "(dry-run) nothing was changed" "$TMP/upgrade-dry.out"
test "$(cat "$PREFIX/static/style.css")" = "/* old */"

# The installed unit supplies the DSN and listener when no flags are given.
printf 'ExecStart=/usr/local/bin/veil-forum --addr 127.0.0.1:8100 --database-url %s\n' \
    'postgres://custom@%2Ftmp%2Fpg/customdb' > "$TMP/fake.service"
VEIL_UNIT_FILE="$TMP/fake.service" "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" \
    --checksums "$TMP/checksums.txt" --no-backup --dry-run >"$TMP/upgrade-unit.out" 2>&1
grep -q 'database: postgres://custom@%2Ftmp%2Fpg/customdb' "$TMP/upgrade-unit.out"
grep -q 'listen:   127.0.0.1:8100' "$TMP/upgrade-unit.out"

# --- 5. upgrade.sh for real (stubs) ---------------------------------------------
"$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" --checksums "$TMP/checksums.txt" \
    --database-url "$DSN" --addr 127.0.0.1:8001 >"$TMP/upgrade.out" 2>&1
grep -q 'Pre-upgrade backup:' "$TMP/upgrade.out"
grep -q 'Done: 0.1.0-alpha.18 -> 0.1.0-alpha.19' "$TMP/upgrade.out"
test "$("$PREFIX/bin/veil-forum" --version)" = "veil-forum 0.1.0-alpha.19"
test "$(cat "$PREFIX/static/style.css")" = "/* new */"
grep -q 'systemctl stop veil-forum' "$STUB_LOG"
grep -q 'systemctl start veil-forum' "$STUB_LOG"
SNAP=$(sed -n 's|.*scripts/rollback.sh --snapshot \(.*\)|\1|p' "$TMP/upgrade.out" | head -n 1)
[ -n "$SNAP" ] || { echo "upgrade printed no snapshot" >&2; exit 1; }
[ -x "$SNAP/veil-forum" ]
[ -f "$SNAP/static/style.css" ]
test "$(cat "$SNAP/VERSION")" = "0.1.0-alpha.18"
test "$(cat "$SNAP/DSN")" = "$DSN"
test "$(cat "$SNAP/ADDR")" = "127.0.0.1:8001"
test -f "$(cat "$SNAP/DB_DUMP")"
test "$("$SNAP/veil-forum" --version)" = "veil-forum 0.1.0-alpha.18"

# --- 6. rollback.sh for real ------------------------------------------------------
"$ROOT/scripts/rollback.sh" --snapshot "$SNAP" >"$TMP/rollback.out" 2>&1
grep -q 'Done: rolled back to 0.1.0-alpha.18' "$TMP/rollback.out"
test "$("$PREFIX/bin/veil-forum" --version)" = "veil-forum 0.1.0-alpha.18"
test "$(cat "$PREFIX/static/style.css")" = "/* old */"

# --- 7. failing release triggers the automatic rollback ---------------------------
# The stub fails exactly --health-timeout curl calls, so the upgrade's gate
# times out while the rollback's own gate (sharing the counter) succeeds.
rm -f "$TMP/c7"
if STUB_CURL_BUDGET=5 STUB_CURL_COUNT="$TMP/c7" "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" \
    --checksums "$TMP/checksums.txt" --database-url "$DSN" --addr 127.0.0.1:8001 \
    --health-timeout 5 >"$TMP/upgrade-fail.out" 2>&1; then
    echo "unhealthy release must fail the upgrade" >&2
    exit 1
fi
grep -q 'restoring .*/rollback/0.1.0-alpha.18-' "$TMP/upgrade-fail.out"
grep -q 'rollback succeeded' "$TMP/upgrade-fail.out"
test "$("$PREFIX/bin/veil-forum" --version)" = "veil-forum 0.1.0-alpha.18"

# --- 8. rollback.sh argument handling ----------------------------------------------
if "$ROOT/scripts/rollback.sh" --snapshot "$TMP/missing" >/dev/null 2>&1; then
    echo "missing snapshot must fail" >&2
    exit 1
fi
if VEIL_ROLLBACK_ROOT="$TMP/empty-rollback" "$ROOT/scripts/rollback.sh" >/dev/null 2>&1; then
    echo "empty snapshot directory must fail" >&2
    exit 1
fi
if ! VEIL_SERVICE_MANAGER=none "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" --dry-run >/dev/null 2>&1; then
    echo "dry-run without a manager must still work" >&2
    exit 1
fi
# Invert the dry-run above: a real run without a manager must refuse.
if VEIL_SERVICE_MANAGER=none "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" >/dev/null 2>&1; then
    echo "missing service manager must fail" >&2
    exit 1
fi
if "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" --restore-db "$TMP/missing.dump" >/dev/null 2>&1; then
    echo "missing database backup must fail" >&2
    exit 1
fi

# --- 9. failed install triggers the automatic rollback ---------------------------
# Refusing the new binary's destination aborts the swap after the service
# stopped; the snapshot (already taken) must be restored and the old release
# left running.
if FAIL_ON="$PREFIX/bin/veil-forum" "$ROOT/scripts/upgrade.sh" "$TMP/archive.tar.gz" \
    --checksums "$TMP/checksums.txt" --database-url "$DSN" --addr 127.0.0.1:8001 \
    >"$TMP/upgrade-install-fail.out" 2>&1; then
    echo "failed install must fail the upgrade" >&2
    exit 1
fi
grep -q 'could not install the new binary' "$TMP/upgrade-install-fail.out"
grep -q 'rollback succeeded' "$TMP/upgrade-install-fail.out"
test "$("$PREFIX/bin/veil-forum" --version)" = "veil-forum 0.1.0-alpha.18"
test "$(cat "$PREFIX/static/style.css")" = "/* old */"

# --- 10. failed restore still restarts the service ---------------------------------
# Simulate a half-swapped release (installed binary differs from the
# snapshot) with writes blocked: the binary cannot be restored, so rollback
# must start the service best-effort instead of stranding it stopped.
cp "$TMP/new-top/veil-forum" "$PREFIX/bin/veil-forum"
if FAIL_ON="$PREFIX/bin/veil-forum" "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" \
    >"$TMP/rollback-fail.out" 2>&1; then
    echo "failed restore must fail the rollback" >&2
    exit 1
fi
grep -q 'file restore failed' "$TMP/rollback-fail.out"
grep -q 'rollback failed' "$TMP/rollback-fail.out"
grep -q 'systemctl start veil-forum' "$STUB_LOG"

echo 'deploy script tests passed'
