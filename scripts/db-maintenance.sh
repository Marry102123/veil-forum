#!/bin/sh
# PostgreSQL backup and health check for veil-forum.
#
# Usage:
#   db-maintenance.sh check  [DATABASE_URL]
#   db-maintenance.sh backup [DATABASE_URL] [BACKUP_DIR]
#
# Backups are always encrypted with age. Set VEIL_BACKUP_RECIPIENT to an age
# public recipient, or VEIL_BACKUP_RECIPIENT_FILE to a 0600-or-stricter file
# containing one public recipient per line. A backup without a recipient fails
# before creating any dump. Requires pg_dump, pg_restore, and age.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

MODE="${1:-}"
DATABASE_URL="${2:-${DATABASE_URL:-postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum}}"
BACKUP_DIR="${3:-/srv/veil-forum-backups}"
RETAIN="${VEIL_BACKUP_RETAIN:-30}"

case "$RETAIN" in ''|*[!0-9]*) echo "warning: invalid VEIL_BACKUP_RETAIN; keeping 30" >&2; RETAIN=30;; 0) echo "warning: VEIL_BACKUP_RETAIN=0 invalid; keeping 30" >&2; RETAIN=30;; esac

case "$MODE" in
    check)
        command -v psql >/dev/null 2>&1 || { echo "error: psql is required" >&2; exit 1; }
        ;;
    backup)
        for required in pg_dump pg_restore age mktemp ln; do
            command -v "$required" >/dev/null 2>&1 || { echo "error: $required is required" >&2; exit 1; }
        done
        ;;
    *)
        echo "usage: $0 check|backup [DATABASE_URL] [BACKUP_DIR]" >&2
        exit 2
        ;;
esac

check_database() {
    tables=$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
    [ "$tables" -gt 0 ] || { echo "error: no tables found" >&2; return 1; }
    echo "Connection ok: $tables tables in the public schema"
    if command -v pg_amcheck >/dev/null 2>&1; then
        pg_amcheck --quiet --database "$DATABASE_URL" && echo "pg_amcheck passed" || { echo "error: pg_amcheck reported problems" >&2; return 1; }
    fi
}

backup_database() {
    recipient="${VEIL_BACKUP_RECIPIENT:-}"
    recipient_file="${VEIL_BACKUP_RECIPIENT_FILE:-}"
    [ -n "$recipient$recipient_file" ] || { echo "error: age recipient required via VEIL_BACKUP_RECIPIENT_FILE or VEIL_BACKUP_RECIPIENT; plaintext backups are forbidden" >&2; return 1; }
    [ -z "$recipient$recipient_file" ] || [ -n "$recipient" -a -z "$recipient_file" ] || { echo "error: set only one of VEIL_BACKUP_RECIPIENT_FILE or VEIL_BACKUP_RECIPIENT" >&2; return 1; }
    if [ -n "$recipient_file" ]; then
        [ -f "$recipient_file" ] || { echo "error: recipient file not found" >&2; return 1; }
        veil_private_file "$recipient_file" || { echo "error: age recipient file must not be group/world accessible" >&2; return 1; }
        set -- -R "$recipient_file"
    else
        set -- -r "$recipient"
    fi
    umask 077
    install -d -m 700 "$BACKUP_DIR"
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    final="$BACKUP_DIR/forum-${timestamp}.dump.age"
    [ ! -e "$final" ] || { echo "error: refusing to overwrite an existing backup: $final" >&2; return 1; }
    # mktemp -d creates an unpredictable private directory inside the already
    # private backup directory. Predictable dot-file names are vulnerable to a
    # symlink race when a caller supplies an incorrectly-owned backup path.
    work=$(mktemp -d "$BACKUP_DIR/.forum-${timestamp}.XXXXXX")
    dump="$work/dump"
    enc="$work/encrypted"
    trap 'rm -rf "$work"' EXIT HUP INT TERM
    pg_dump --format=custom --no-owner --no-privileges --file="$dump" "$DATABASE_URL"
    chmod 600 "$dump"
    pg_restore --list "$dump" >/dev/null
    # shellcheck disable=SC2086
    age "$@" -o "$enc" "$dump"
    chmod 600 "$enc"
    # Production has no private identity. The restored plaintext was validated
    # before encryption; rollback validates it again after decryption.
    # work and final share a filesystem, so a hard link atomically publishes the
    # completed archive and fails closed if another process claimed the same
    # timestamped name first.
    ln "$enc" "$final"
    rm -rf "$work"
    trap - EXIT HUP INT TERM
    echo "Backup encrypted and verified: $final"
    count=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'forum-*.dump.age' | wc -l)
    if [ "$count" -gt "$RETAIN" ]; then
        find "$BACKUP_DIR" -maxdepth 1 -type f -name 'forum-*.dump.age' -printf '%T@ %p\n' | sort -n | head -n "$((count - RETAIN))" | cut -d' ' -f2- | while IFS= read -r old; do rm -f "$old"; echo "Removed old backup: $old"; done
    fi
}

case "$MODE" in
    check) check_database ;;
    backup) backup_database ;;
esac
