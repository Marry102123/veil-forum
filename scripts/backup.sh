#!/bin/sh
# veil-forum PostgreSQL backup script.
#
# Usage:
#   scripts/backup.sh [DATABASE_URL] [BACKUP_DIR]
#
# Defaults:
#   DATABASE_URL=$DATABASE_URL or postgres:///veil_forum?host=/var/run/postgresql
#   BACKUP_DIR=/srv/veil-forum-backups
#
# Compatibility entry point for the canonical maintenance backup. Keeping one
# implementation prevents the two historically supported commands from
# drifting in consistency checks, atomicity, and retention behavior.
#
# Backups contain sessions, password hashes, and deleted content. Encrypt them
# before moving them off-host and never store Onion/I2P keys or credentials in
# the same backup directory.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/db-maintenance.sh" backup \
    "${1:-${DATABASE_URL:-postgres:///veil_forum?host=/var/run/postgresql}}" \
    "${2:-/srv/veil-forum-backups}"
