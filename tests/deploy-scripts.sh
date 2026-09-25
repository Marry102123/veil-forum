#!/bin/sh
# Deployment script tests: lib.sh helpers plus install/upgrade/rollback
# against stubbed system tools. No root and no live server required.
#
# Everything privileged is redirected through environment overrides
# (VEIL_PREFIX, VEIL_STATE_DIR, VEIL_BACKUP_DIR, VEIL_ROLLBACK_ROOT,
# VEIL_SERVICE_MANAGER, VEIL_ALLOW_NONROOT, VEIL_TEST_HARNESS) and PATH stubs.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

# Captured before the stub directory shadows PATH.
REAL_INSTALL=$(command -v install)
REAL_STAT=$(command -v stat)
export REAL_INSTALL REAL_STAT
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
has_list=0
has_file=0
for arg in "$@"; do
  case "$arg" in
    --list) has_list=1 ;;
    -*) ;;
    *) has_file=1 ;;
  esac
done
if [ "$has_list" -eq 1 ]; then
  if [ "$has_file" -eq 0 ]; then
    input=$(cat)
    printf '%s\n' "--list stdin=$input" >> "${PG_RESTORE_LOG:-/dev/null}"
  fi
  printf 'archive listing\n'
  exit 0
fi
input=$(cat)
printf '%s\n' "restore stdin=$input args=$*" >> "${PG_RESTORE_LOG:-/dev/null}"
exit 0
EOF
cat > "$BIN_DIR/psql" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "psql $*" >> "${PSQL_LOG:-/dev/null}"
printf '12\n'
EOF
cat > "$BIN_DIR/age" <<'EOF'
#!/bin/sh
set -eu
out=
mode=encrypt
input=
while [ $# -gt 0 ]; do
  case "$1" in
    --decrypt) mode=decrypt; shift ;;
    -o) out=${2:?}; shift 2 ;;
    -o=*) out=${1#-o=}; shift ;;
    -i | -r | -R) shift 2 ;;
    -*) shift ;;
    *) input=$1; shift ;;
  esac
done
if [ "$mode" = decrypt ]; then
  printf 'PLAINTEXT-PGRESTORE-STREAM\n'
else
  [ -n "$out" ] && [ -f "$input" ]
  printf 'AGE-CIPHERTEXT\n' > "$out"
fi
EOF
cat > "$BIN_DIR/su" <<'EOF'
#!/bin/sh
set -eu
printf 'su %s\n' "$*" >> "${SU_LOG:?}"
last=
for arg in "$@"; do last=$arg; done
case "$last" in
  # pg_restore consumes the decrypted archive on stdin, so pass it through.
  pg_restore\ *) exec sh -c "$last" ;;
esac
# psql -c and the remaining stubbed invocations never read stdin. Detach from
# an inherited terminal or never-closed pipe instead of blocking on a read.
exec </dev/null
exit 0
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
cat > "$BIN_DIR/stat" <<'EOF'
#!/bin/sh
if [ -n "${FAKE_STAT_UID:-}" ]; then
  for arg in "$@"; do last=$arg; done
  if [ -f "$last" ]; then
    for arg in "$@"; do
      case "$arg" in
        %u) printf '%s\n' "$FAKE_STAT_UID"; exit 0 ;;
      esac
    done
  fi
fi
exec "$REAL_STAT" "$@"
EOF
cat > "$BIN_DIR/date" <<EOF
#!/bin/sh
n=0
[ ! -f "$TMP/date-count" ] || n=\$(cat "$TMP/date-count")
n=\$((n + 1))
printf '%s\n' "\$n" > "$TMP/date-count"
printf '20260925T0102%02dZ\n' "\$n"
EOF
chmod +x "$BIN_DIR"/systemctl "$BIN_DIR"/curl "$BIN_DIR"/pg_dump "$BIN_DIR"/pg_restore "$BIN_DIR"/psql "$BIN_DIR"/age "$BIN_DIR"/su "$BIN_DIR"/install "$BIN_DIR"/stat "$BIN_DIR"/date

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
RELEASE_ARCHIVE="$TMP/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz"
tar -czf "$RELEASE_ARCHIVE" -C "$TMP" stage-top
mv "$TMP/stage-top" "$TMP/new-top"
(cd "$TMP" && sha256sum "$(basename "$RELEASE_ARCHIVE")" > checksums.txt)

export PATH="$BIN_DIR:$PATH"
export VEIL_ALLOW_NONROOT=1 VEIL_TEST_HARNESS=1 VEIL_SERVICE_MANAGER=systemd
export VEIL_BACKUP_RECIPIENT=age1testrecipient
export VEIL_PREFIX="$PREFIX" VEIL_STATE_DIR="$STATE" VEIL_BACKUP_DIR="$BACKUPS"
export VEIL_ROLLBACK_ROOT="$ROLLBACK"

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
if grep -E 'postgres://[^/@[:space:]]+:[^/@[:space:]]+@' "$TMP/install.out" >/dev/null 2>&1; then
    echo 'install leaked a credential-bearing DSN' >&2
    exit 1
fi
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

# --- 4. upgrade.sh --dry-run ----------------------------------------------------
DSN='postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum'
"$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" --checksums "$TMP/checksums.txt" \
    --database-url "$DSN" --addr 127.0.0.1:8001 --no-backup --dry-run \
    --no-attestation-verify v0.1.0-alpha.19 >"$TMP/upgrade-dry.out" 2>&1
grep -q 'Upgrade plan: 0.1.0-alpha.18 -> 0.1.0-alpha.19' "$TMP/upgrade-dry.out"
grep -q "(dry-run) nothing was changed" "$TMP/upgrade-dry.out"
test "$(cat "$PREFIX/static/style.css")" = "/* old */"

# The installed unit supplies the DSN and listener when no flags are given.
printf 'ExecStart=/usr/local/bin/veil-forum --addr 127.0.0.1:8100 --database-url %s\n' \
    'postgres://custom@%2Ftmp%2Fpg/customdb' > "$TMP/fake.service"
VEIL_UNIT_FILE="$TMP/fake.service" "$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" \
    --checksums "$TMP/checksums.txt" --no-backup --dry-run \
    --no-attestation-verify v0.1.0-alpha.19 >"$TMP/upgrade-unit.out" 2>&1
grep -q 'database: \[redacted PostgreSQL connection string\]' "$TMP/upgrade-unit.out"
if grep -F 'postgres://custom@%2Ftmp%2Fpg/customdb' "$TMP/upgrade-unit.out" >/dev/null; then
    echo 'upgrade leaked the DSN read from the installed unit' >&2
    exit 1
fi
grep -q 'listen:   127.0.0.1:8100' "$TMP/upgrade-unit.out"

# --- 5. upgrade.sh for real (stubs) ---------------------------------------------
# A real upgrade using a credential-bearing DSN must redact it from all output
# and must not persist it in the snapshot. Use a unique sentinel so a partial
# redaction cannot satisfy the assertion.
DSN_SECRET='e2e-DSN-password-9f31c0'
CRED_DSN="postgres://custom:${DSN_SECRET}@%2Ftmp%2Fpg/customdb"
"$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" --checksums "$TMP/checksums.txt" \
    --database-url "$CRED_DSN" --addr 127.0.0.1:8001 \
    --no-attestation-verify v0.1.0-alpha.19 >"$TMP/upgrade-credential.out" 2>&1
grep -F '[redacted PostgreSQL connection string]' "$TMP/upgrade-credential.out" >/dev/null
if grep -F "$CRED_DSN" "$TMP/upgrade-credential.out" >/dev/null || grep -F "$DSN_SECRET" "$TMP/upgrade-credential.out" >/dev/null; then
    echo 'upgrade leaked a credential-bearing DSN' >&2
    exit 1
fi
credential_snapshot=$(sed -n 's|.*scripts/rollback.sh --snapshot \(.*\)|\1|p' "$TMP/upgrade-credential.out" | head -n 1)
[ -d "$credential_snapshot" ]
test ! -e "$credential_snapshot/DSN"
if grep -R -F "$DSN_SECRET" "$credential_snapshot" >/dev/null 2>&1; then
    echo 'upgrade snapshot leaked a credential-bearing DSN' >&2
    exit 1
fi
"$ROOT/scripts/rollback.sh" --snapshot "$credential_snapshot" --health-timeout 5 >"$TMP/credential-upgrade-rollback.out" 2>&1
test "$("$PREFIX/bin/veil-forum" --version)" = "veil-forum 0.1.0-alpha.18"

"$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" --checksums "$TMP/checksums.txt" \
    --database-url "$DSN" --addr 127.0.0.1:8001 \
    --no-attestation-verify v0.1.0-alpha.19 >"$TMP/upgrade.out" 2>&1
grep -q 'Pre-upgrade backup:' "$TMP/upgrade.out" || { cat "$TMP/upgrade.out" >&2; exit 1; }
grep -q 'Done: 0.1.0-alpha.18 -> 0.1.0-alpha.19' "$TMP/upgrade.out" || { cat "$TMP/upgrade.out" >&2; exit 1; }
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

# Encrypted restore validation and loading must both receive the age plaintext
# stream. No decrypted dump may be materialized under TMPDIR or the install
# prefix. The fake root-owned key keeps this non-root smoke test faithful to
# the production ownership gate.
printf 'AGE-CIPHERTEXT\n' > "$TMP/restore.dump.age"
printf 'AGE-SECRET-KEY-TEST\n' > "$TMP/restore.key"
chmod 600 "$TMP/restore.key"
export PG_RESTORE_LOG="$TMP/pg-restore.log" SU_LOG="$TMP/su.log"
: > "$PG_RESTORE_LOG"
: > "$SU_LOG"
: > "$TMP/encrypted-restore.out"
before_tmp_files=$(find "$TMP" -type f | sort)
if ! FAKE_STAT_UID=0 "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" \
    --restore-db "$TMP/restore.dump.age" --backup-identity "$TMP/restore.key" \
    --database-url "$DSN" --yes --health-timeout 5 >"$TMP/encrypted-restore.out" 2>&1; then
  cat "$TMP/encrypted-restore.out" >&2
  exit 1
fi
test "$(grep -c 'stdin=PLAINTEXT-PGRESTORE-STREAM' "$PG_RESTORE_LOG")" -eq 2
grep -F "restore stdin=PLAINTEXT-PGRESTORE-STREAM" "$PG_RESTORE_LOG" >/dev/null
grep -F 'DROP DATABASE' "$SU_LOG" >/dev/null
after_tmp_files=$(find "$TMP" -type f | sort)
test "$before_tmp_files" = "$after_tmp_files"
test "$(find "$PREFIX" -type f -name '*.dump' | wc -l)" -eq 0

# Missing, permissive, and wrongly owned age identities all fail closed before
# the service is stopped or DROP is attempted.
chmod 644 "$TMP/restore.key"
if FAKE_STAT_UID=0 "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" \
    --restore-db "$TMP/restore.dump.age" --backup-identity "$TMP/restore.key" \
    --database-url "$DSN" --yes >"$TMP/bad-key-mode.out" 2>&1; then
    echo 'group/world-readable age identity was accepted' >&2
    exit 1
fi
chmod 600 "$TMP/restore.key"
if FAKE_STAT_UID=12345 "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" \
    --restore-db "$TMP/restore.dump.age" --backup-identity "$TMP/restore.key" \
    --database-url "$DSN" --yes >"$TMP/bad-key-owner.out" 2>&1; then
    echo 'non-root-owned age identity was accepted' >&2
    exit 1
fi

# Credential-bearing DSNs and role mismatches are rejected before service stop
# and before the DROP command boundary. The sentinel must not reach the log.
: > "$STUB_LOG"
: > "$SU_LOG"
if "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" \
    --restore-db "$TMP/restore.dump.age" --backup-identity "$TMP/restore.key" \
    --database-url "$CRED_DSN" --yes >"$TMP/credential-restore.out" 2>&1; then
    echo 'credential-bearing restore DSN was accepted' >&2
    exit 1
fi
if grep -F 'systemctl stop' "$STUB_LOG" >/dev/null || grep -F 'DROP DATABASE' "$SU_LOG" >/dev/null; then
    echo 'credential-bearing DSN reached stop/DROP boundary' >&2
    exit 1
fi
if grep -F "$DSN_SECRET" "$TMP/credential-restore.out" >/dev/null; then
    echo 'rollback leaked a credential-bearing DSN' >&2
    exit 1
fi
: > "$STUB_LOG"
: > "$SU_LOG"
MISMATCH_DSN='postgres://other-role@%2Fvar%2Frun%2Fpostgresql/veil_forum'
if "$ROOT/scripts/rollback.sh" --snapshot "$SNAP" \
    --restore-db "$TMP/restore.dump.age" --backup-identity "$TMP/restore.key" \
    --database-url "$MISMATCH_DSN" --yes >"$TMP/mismatched-role.out" 2>&1; then
    echo 'restore role/VEIL_USER mismatch was accepted' >&2
    exit 1
fi
if grep -F 'systemctl stop' "$STUB_LOG" >/dev/null || grep -F 'DROP DATABASE' "$SU_LOG" >/dev/null; then
    echo 'role mismatch reached stop/DROP boundary' >&2
    exit 1
fi

# --- 6. rollback.sh for real ------------------------------------------------------
"$ROOT/scripts/rollback.sh" --snapshot "$SNAP" >"$TMP/rollback.out" 2>&1
grep -q 'Done: rolled back to 0.1.0-alpha.18' "$TMP/rollback.out"
test "$("$PREFIX/bin/veil-forum" --version)" = "veil-forum 0.1.0-alpha.18"
test "$(cat "$PREFIX/static/style.css")" = "/* old */"

# --- 7. failing release triggers the automatic rollback ---------------------------
# The stub fails exactly --health-timeout curl calls, so the upgrade's gate
# times out while the rollback's own gate (sharing the counter) succeeds.
rm -f "$TMP/c7"
if STUB_CURL_BUDGET=5 STUB_CURL_COUNT="$TMP/c7" "$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" \
    --checksums "$TMP/checksums.txt" --database-url "$DSN" --addr 127.0.0.1:8001 \
    --health-timeout 5 --no-attestation-verify v0.1.0-alpha.19 >"$TMP/upgrade-fail.out" 2>&1; then
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
if FAIL_ON="$PREFIX/bin/veil-forum" "$ROOT/scripts/upgrade.sh" "$RELEASE_ARCHIVE" \
    --checksums "$TMP/checksums.txt" --database-url "$DSN" --addr 127.0.0.1:8001 \
    --no-attestation-verify v0.1.0-alpha.19 \
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
