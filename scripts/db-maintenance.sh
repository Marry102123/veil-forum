#!/bin/sh
# PostgreSQL backup and health check for veil-forum.
#
# Usage:
#   db-maintenance.sh check  [DATABASE_URL]
#   db-maintenance.sh backup [DATABASE_URL] [BACKUP_DIR]
#
# Defaults:
#   DATABASE_URL=$DATABASE_URL or postgres:///veil_forum?host=/var/run/postgresql
#   BACKUP_DIR=/srv/veil-forum-backups
#
# Requires pg_dump and pg_restore. `pg_amcheck` is used for the check when it is
# installed. Backups are custom-format archives verified with `pg_restore
# --list`, written atomically, kept 30 deep (`VEIL_BACKUP_RETAIN`, a positive
# integer), in a 0700 directory, as mode 600 files. They contain sessions,
# deleted content, and password hashes: encrypt them before moving them
# off-host and never store Onion/I2P keys in the same directory.
#
# A DSN with an inline password is visible to other local users through the
# process table while pg_dump runs. Prefer a Unix-socket DSN with peer
# authentication, or set PGPASSWORD / ~/.pgpass for a TCP connection.
set -eu

command -v pg_dump >/dev/null 2>&1 || {
    echo "error: pg_dump is required" >&2
    exit 1
}
command -v pg_restore >/dev/null 2>&1 || {
    echo "error: pg_restore is required" >&2
    exit 1
}

MODE="${1:-}"
DATABASE_URL="${2:-${DATABASE_URL:-postgres:///veil_forum?host=/var/run/postgresql}}"
BACKUP_DIR="${3:-/srv/veil-forum-backups}"
RETAIN="${VEIL_BACKUP_RETAIN:-30}"
case "$RETAIN" in
    '' | *[!0-9]*)
        echo "warning: VEIL_BACKUP_RETAIN=$RETAIN is not a number; keeping 30" >&2
        RETAIN=30
        ;;
    0)
        echo "warning: VEIL_BACKUP_RETAIN=0 would delete every archive; keeping 30" >&2
        RETAIN=30
        ;;
esac

check_database() {
    tables=$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
    [ "$tables" -gt 0 ] || {
        echo "error: no tables found; run veil-forum once to apply migrations" >&2
        return 1
    }
    echo "Connection ok: $tables tables in the public schema"
    if command -v pg_amcheck >/dev/null 2>&1; then
        echo "Running pg_amcheck..."
        pg_amcheck --quiet --database "$DATABASE_URL" && echo "pg_amcheck passed" || {
            echo "error: pg_amcheck reported problems" >&2
            return 1
        }
    fi
}

backup_database() {
    # The directory holds dumps of sessions, deleted content and password
    # hashes: create it private, and before any umask-sensitive work.
    umask 077
    install -d -m 700 "$BACKUP_DIR"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    final="${BACKUP_DIR}/forum-${timestamp}.dump"
    tmp="${BACKUP_DIR}/.forum-${timestamp}.$$.dump"
    trap 'rm -f "$tmp"' EXIT HUP INT TERM

    pg_dump --format=custom --no-owner --no-privileges --file="$tmp" "$DATABASE_URL"
    # An archive that cannot be listed cannot be restored.
    pg_restore --list "$tmp" >/dev/null
    chmod 600 "$tmp"
    mv "$tmp" "$final"
    trap - EXIT HUP INT TERM
    echo "Backup saved and verified: $final"

    # Retention applies only to this script's own archives.
    count=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'forum-*.dump' | wc -l)
    if [ "$count" -gt "$RETAIN" ]; then
        find "$BACKUP_DIR" -maxdepth 1 -type f -name 'forum-*.dump' -printf '%T@ %p\n' |
            sort -n | head -n "$((count - RETAIN))" | cut -d' ' -f2- |
            while IFS= read -r old; do
                rm -f "$old"
                echo "Removed old backup: $old"
            done
    fi
}

case "$MODE" in
    check)
        check_database
        ;;
    backup)
        backup_database
        ;;
    *)
        echo "usage: $0 check|backup [DATABASE_URL] [BACKUP_DIR]" >&2
        exit 2
        ;;
esac
