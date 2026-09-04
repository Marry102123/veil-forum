#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
DATA="$TMP/data"
BACKUPS="$TMP/backups"
mkdir -p "$DATA"
printf 'SQLite format 3\000' > "$DATA/forum.db"

# Minimal sqlite3 stand-in: exercise the scripts without requiring sqlite3 on the
# developer machine. It models the two statements used by db-maintenance.sh.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/sqlite3" <<'EOF'
#!/bin/sh
set -eu
db=$1
statement=${2:-}
case "$statement" in
  .backup\ \'*) target=${statement#*.backup \'}; target=${target%\'}; cp "$db" "$target" ;;
  "PRAGMA integrity_check;") printf 'ok\n' ;;
  *) echo "unexpected sqlite3 statement: $statement" >&2; exit 1 ;;
esac
EOF
chmod +x "$TMP/bin/sqlite3"

PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$DATA" "$BACKUPS" > "$TMP/canonical.out"
sleep 1
PATH="$TMP/bin:$PATH" "$ROOT/scripts/backup.sh" "$DATA" "$BACKUPS" > "$TMP/compat.out"
count=$(find "$BACKUPS" -type f -name 'forum-*.db' | wc -l)
test "$count" -eq 2
for file in "$BACKUPS"/forum-*.db; do
  test "$(stat -c '%a' "$file")" = 600
  test "$(wc -c < "$file")" -gt 0
done
grep -q 'Backup saved and verified:' "$TMP/canonical.out"
grep -q 'Backup saved and verified:' "$TMP/compat.out"

# Retention applies only to forum backups, leaving unrelated files untouched.
touch "$BACKUPS/unrelated.db"
i=1
while [ "$i" -le 31 ]; do
  touch -d "${i} minutes ago" "$BACKUPS/forum-old-$i.db"
  i=$((i + 1))
done
PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$DATA" "$BACKUPS" >/dev/null
test -e "$BACKUPS/unrelated.db"
test "$(find "$BACKUPS" -type f -name 'forum-*.db' | wc -l)" -eq 30

echo 'script smoke tests passed'
