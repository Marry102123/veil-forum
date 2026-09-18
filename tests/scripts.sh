#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
BACKUPS="$TMP/backups"
URL='postgres:///veil_forum?host=/var/run/postgresql'

# Minimal pg_dump/pg_restore/psql stand-ins: exercise the scripts without a live
# server. They model the exact statements db-maintenance.sh issues.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/pg_dump" <<'EOF'
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
cat > "$TMP/bin/pg_restore" <<'EOF'
#!/bin/sh
set -eu
for arg in "$@"; do
  case "$arg" in
    --list) printf 'archive listing\n'; exit 0 ;;
  esac
done
exit 0
EOF
cat > "$TMP/bin/psql" <<'EOF'
#!/bin/sh
set -eu
printf '12\n'
EOF
chmod +x "$TMP/bin/pg_dump" "$TMP/bin/pg_restore" "$TMP/bin/psql"

PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$BACKUPS" > "$TMP/canonical.out"
sleep 1
PATH="$TMP/bin:$PATH" "$ROOT/scripts/backup.sh" "$URL" "$BACKUPS" > "$TMP/compat.out"
count=$(find "$BACKUPS" -type f -name 'forum-*.dump' | wc -l)
test "$count" -eq 2
for file in "$BACKUPS"/forum-*.dump; do
  test "$(stat -c '%a' "$file")" = 600
  test "$(wc -c < "$file")" -gt 0
done
grep -q 'Backup saved and verified:' "$TMP/canonical.out"
grep -q 'Backup saved and verified:' "$TMP/compat.out"

# The check mode must report the table count from psql.
PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" check "$URL" > "$TMP/check.out"
grep -q 'Connection ok:' "$TMP/check.out"

# Retention applies only to this script's own archives, leaving unrelated files
# untouched. The default retention is 30 archives.
touch "$BACKUPS/unrelated.dump"
i=1
while [ "$i" -le 31 ]; do
  touch -d "${i} minutes ago" "$BACKUPS/forum-old-$i.dump"
  i=$((i + 1))
done
PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$BACKUPS" >/dev/null
test -e "$BACKUPS/unrelated.dump"
kept=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump' | wc -l)
test "$kept" -eq 30

# The directory holds dumps of sessions and password hashes: it must be private,
# and it must be created private even when the caller's umask is permissive.
test "$(stat -c '%a' "$BACKUPS")" = 700
PERMISSIVE="$TMP/permissive-backups"
(umask 022; PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$PERMISSIVE" >/dev/null)
test "$(stat -c '%a' "$PERMISSIVE")" = 700

# A retention value that would delete every archive, or that is not a number, is
# refused instead of applied.
for retain in 0 abc ''; do
  before=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump' | wc -l)
  VEIL_BACKUP_RETAIN="$retain" PATH="$TMP/bin:$PATH" \
    "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$BACKUPS" > "$TMP/retain.out" 2>&1
  after=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump' | wc -l)
  test "$after" -ge "$before" ||
    { echo "retention $retain deleted archives: $before -> $after" >&2; exit 1; }
  test "$after" -gt 0 || { echo "retention $retain left no archives" >&2; exit 1; }
done

echo 'script smoke tests passed'
