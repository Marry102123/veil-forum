#!/bin/sh
# veil-forum online backup script.
#
# Usage:
#   scripts/backup.sh [DATA_DIR] [BACKUP_DIR]
#
# Defaults:
#   DATA_DIR=/var/lib/veil-forum
#   BACKUP_DIR=/srv/veil-forum-backups
#
# Uses SQLite VACUUM INTO for a consistent online backup without stopping the
# service. If no SQLite backup tool is available, exits instead of copying a
# live WAL database. Keeps the 30 most recent backups and sets mode 600 on all
# backup files.
#
# Backups contain sessions and deleted content. Encrypt them before moving
# off-host and never store Onion/I2P keys or credentials in the same backup.
set -eu

DATA_DIR="${1:-/var/lib/veil-forum}"
BACKUP_DIR="${2:-/srv/veil-forum-backups}"
DB="${DATA_DIR}/forum.db"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="${BACKUP_DIR}/forum-${TIMESTAMP}.db"

install -d -m 700 "${BACKUP_DIR}"

if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${DB}" "VACUUM INTO '${BACKUP_FILE}'"
elif command -v sqlite3-rsync >/dev/null 2>&1; then
    sqlite3-rsync --backup "${DB}" "${BACKUP_FILE}"
else
    echo "error: sqlite3 or sqlite3-rsync is required for an online backup" >&2
    exit 1
fi

chmod 600 "${BACKUP_FILE}"

ls -t "${BACKUP_DIR}"/forum-*.db 2>/dev/null | tail -n +31 | xargs -r rm -f

SIZE="$(wc -c < "${BACKUP_FILE}")"
echo "Backup saved: ${BACKUP_FILE} (${SIZE} bytes)"
