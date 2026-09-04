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
# Compatibility entry point for the canonical maintenance backup. Keeping one
# implementation prevents the two historically supported commands from
# drifting in consistency checks, atomicity, and retention behavior.
#
# Backups contain sessions and deleted content. Encrypt them before moving
# off-host and never store Onion/I2P keys or credentials in the same backup.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/db-maintenance.sh" backup "${1:-/var/lib/veil-forum}" "${2:-/srv/veil-forum-backups}"
