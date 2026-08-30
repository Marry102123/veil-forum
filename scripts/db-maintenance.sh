#!/bin/sh
# SQLite integrity check and online backup for veil-forum.
#
# Usage:
#   db-maintenance.sh check  [DATA_DIR]
#   db-maintenance.sh backup [DATA_DIR] [BACKUP_DIR]
#
# Requires the sqlite3 command. It deliberately never copies a live database
# file: SQLite creates the backup while holding the appropriate read state.
set -eu

command -v sqlite3 >/dev/null 2>&1 || {
    echo "error: sqlite3 is required" >&2
    exit 1
}

MODE="${1:-}"
DATA_DIR="${2:-/var/lib/veil-forum}"
DB="${DATA_DIR}/forum.db"

[ -f "$DB" ] || { echo "error: database not found: $DB" >&2; exit 1; }

check_database() {
    result="$(sqlite3 "$1" 'PRAGMA integrity_check;')"
    [ "$result" = "ok" ] || {
        echo "error: integrity_check failed for $1: $result" >&2
        return 1
    }
    echo "Integrity check passed: $1"
}

case "$MODE" in
    check)
        check_database "$DB"
        ;;
    backup)
        BACKUP_DIR="${3:-/srv/veil-forum-backups}"
        timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
        final="${BACKUP_DIR}/forum-${timestamp}.db"
        tmp="${BACKUP_DIR}/.forum-${timestamp}.$$.db"
        # Keep the directory private and never expose a partially written file.
        install -d -m 700 "$BACKUP_DIR"
        trap 'rm -f "$tmp"' EXIT HUP INT TERM
        # The path is deployment-controlled (normally under BACKUP_DIR).
        sqlite3 "$DB" ".backup '$tmp'"
        chmod 600 "$tmp"
        check_database "$tmp"
        mv -f "$tmp" "$final"
        trap - EXIT HUP INT TERM
        # Retain 30 backups without touching unrelated files.
        find "$BACKUP_DIR" -type f -name 'forum-*.db' -printf '%T@ %p\n' \
            | sort -rn | awk 'NR > 30 { sub(/^[^ ]* /, ""); print }' \
            | while IFS= read -r old; do rm -f "$old"; done
        size="$(wc -c < "$final")"
        echo "Backup saved and verified: $final (${size} bytes)"
        ;;
    *)
        echo "usage: $0 {check|backup} [DATA_DIR] [BACKUP_DIR]" >&2
        exit 2
        ;;
esac
