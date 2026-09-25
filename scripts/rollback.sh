#!/bin/sh
# veil-forum rollback: restore a snapshot taken by upgrade.sh.
#
# Usage:
#   sudo scripts/rollback.sh [options]
#
# Options:
#   --snapshot DIR     snapshot to restore (default: the newest in
#                      /var/lib/veil-forum/rollback)
#   --restore-db DUMP  restore a custom-format database backup. `.age` inputs
#                      require --backup-identity (file path only).
#   --backup-identity FILE age identity file for --restore-db
#                      Needed only when the failed release already applied a
#                      migration; an older binary cannot read a newer schema.
#                      Asks for confirmation unless --yes is given.
#   --yes              answer the --restore-db confirmation with yes
#   --database-url URL connection string for --restore-db (default: the
#                      snapshot's DSN)
#   --addr HOST:PORT   listener address for the health check (default: the
#                      snapshot's address)
#   --prefix DIR --user NAME
#                      install prefix and service user (defaults /usr/local,
#                      veil-forum, shared with install.sh via VEIL_*)
#   --service-manager M systemd|openrc|none (default: auto-detect)
#   --health-timeout SECS seconds to wait for /healthz (default 60)
#   --dry-run          print every step without changing anything
#
# Restoring the binary and static/ never touches the database. --restore-db
# drops the configured database and recreates it from the dump, so it must
# point at a backup taken before the upgrade.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

SNAP=""
RESTORE_DB=""
BACKUP_IDENTITY=""
YES=0
EXPLICIT_URL=""
EXPLICIT_ADDR=""
HEALTH_TIMEOUT=60
PREFIX_GIVEN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --snapshot) SNAP=${2:?--snapshot needs a directory}; shift 2 ;;
        --restore-db) RESTORE_DB=${2:?--restore-db needs a dump file}; shift 2 ;;
        --backup-identity) BACKUP_IDENTITY=${2:?--backup-identity needs a file path}; shift 2 ;;
        --yes) YES=1; shift ;;
        --database-url) EXPLICIT_URL=${2:?--database-url needs a URL}; shift 2 ;;
        --addr) EXPLICIT_ADDR=${2:?--addr needs HOST:PORT}; shift 2 ;;
        --prefix) VEIL_PREFIX=${2:?--prefix needs a directory}; PREFIX_GIVEN=1; shift 2 ;;
        --user) VEIL_USER=${2:?--user needs a name}; shift 2 ;;
        --service-manager) VEIL_SERVICE_MANAGER=${2:?--service-manager needs systemd|openrc|none}; shift 2 ;;
        --health-timeout) HEALTH_TIMEOUT=${2:?--health-timeout needs seconds}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h | --help) sed -n '2,/^set -eu$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) veil_die "unknown option $1 (try --help)" ;;
    esac
done

# Install locations follow the prefix (lib.sh defaulted them at source time).
# An explicitly exported VEIL_BIN is respected unless --prefix overrides it,
# so upgrade.sh can hand its exact layout down.
if [ "$PREFIX_GIVEN" -eq 1 ]; then
    VEIL_BIN="$VEIL_PREFIX/bin/veil-forum"
    VEIL_STATIC_DIR="$VEIL_PREFIX/static"
fi

if [ "$DRY_RUN" -eq 0 ]; then
    veil_need_root
fi
veil_need install curl
# Same rule as upgrade.sh: the scripts must be able to stop and start the
# service, or they refuse to touch a running release.
case "$(veil_service_manager)" in
    systemd) veil_need systemctl ;;
    openrc) veil_need rc-service ;;
    none)
        if [ "$DRY_RUN" -eq 0 ]; then
            veil_die "no service manager found (need systemctl or rc-service); stop the forum and manage the files by hand instead"
        fi
        ;;
    *) veil_die "unknown service manager: $(veil_service_manager)" ;;
esac

if [ -n "$SNAP" ]; then
    veil_valid_path "$SNAP" || veil_die "--snapshot must be a plain path without quoting or shell metacharacters"
fi
if [ -n "$RESTORE_DB" ]; then
    veil_valid_path "$RESTORE_DB" || veil_die "--restore-db must be a plain path without quoting or shell metacharacters"
fi
veil_valid_name "$VEIL_USER" || veil_die "--user must be a plain name ([A-Za-z0-9_.-], not starting with - or .)"
if [ -n "$EXPLICIT_ADDR" ]; then
    veil_valid_path "$EXPLICIT_ADDR" || veil_die "--addr must be HOST:PORT without quoting or shell metacharacters"
fi

if [ -z "$SNAP" ]; then
    [ -d "$VEIL_ROLLBACK_ROOT" ] || veil_die "no snapshots in $VEIL_ROLLBACK_ROOT"
    # shellcheck disable=SC2012
    SNAP=$(ls -td "$VEIL_ROLLBACK_ROOT"/*/ 2>/dev/null | head -n 1) || SNAP=""
    [ -n "$SNAP" ] || veil_die "no snapshots in $VEIL_ROLLBACK_ROOT"
    SNAP=${SNAP%/}
fi
[ -d "$SNAP" ] || veil_die "snapshot not found: $SNAP"
[ -x "$SNAP/veil-forum" ] || veil_die "snapshot has no binary: $SNAP/veil-forum"
[ -f "$SNAP/static/style.css" ] || veil_die "snapshot has no static assets: $SNAP/static"
[ -f "$SNAP/VERSION" ] || veil_die "snapshot has no VERSION file: $SNAP"

VERSION=$(cat "$SNAP/VERSION")
if [ -n "$EXPLICIT_URL" ]; then
    DSN="$EXPLICIT_URL"
elif [ -f "$SNAP/DSN" ]; then
    DSN=$(cat "$SNAP/DSN")
else
    DSN=$(veil_socket_dsn)
fi
if [ -n "$EXPLICIT_ADDR" ]; then
    ADDR="$EXPLICIT_ADDR"
elif [ -f "$SNAP/ADDR" ]; then
    ADDR=$(cat "$SNAP/ADDR")
else
    ADDR="$VEIL_ADDR"
fi

veil_log "Rollback plan: restore $VERSION from $SNAP"
veil_log "  binary: $SNAP/veil-forum -> $VEIL_BIN"
veil_log "  static: $SNAP/static -> $VEIL_STATIC_DIR"
veil_log "  listen: $ADDR"
if [ -n "$RESTORE_DB" ]; then
    [ -f "$RESTORE_DB" ] || veil_die "database backup not found: $RESTORE_DB"
    case "$RESTORE_DB" in
        *.dump.age)
            [ -n "$BACKUP_IDENTITY" ] || veil_die ".age backups require --backup-identity"
            veil_valid_path "$BACKUP_IDENTITY" || veil_die "--backup-identity must be a plain file path"
            [ -f "$BACKUP_IDENTITY" ] || veil_die "age identity file not found"
            veil_root_private_file "$BACKUP_IDENTITY" || veil_die "age identity file must be root-owned and not group/world accessible"
            veil_need age ;;
        *.dump) ;;
        *) veil_die "--restore-db requires a custom-format .dump or .dump.age" ;;
    esac
    veil_log "  database: DROP and recreate from $RESTORE_DB"
    veil_log "  dsn: [redacted PostgreSQL connection string]"
else
    veil_log "  database: untouched"
fi

if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) nothing was changed"
    exit 0
fi

# --- 1. Optional database restore ---------------------------------------------
# Derive the role and database name back from the socket DSN
# (postgres://user@%2F.../dbname). A TCP DSN with a password cannot be split
# this simply, so --restore-db requires the socket form. The split parts and
# the dump path are interpolated into su command lines, so they must pass
# the same strict validation as install.sh inputs.
if [ -n "$RESTORE_DB" ]; then
    case "$DSN" in
        postgres://*:*@%2F*/*)
            veil_die "--restore-db refuses credential-bearing DSNs; use a passwordless peer-authentication socket DSN"
            ;;
        postgres://*@%2F*/*)
            RESTORE_USER=${DSN#postgres://}
            RESTORE_USER=${RESTORE_USER%%@*}
            RESTORE_DBNAME=${DSN##*/}
            veil_valid_name "$RESTORE_USER" || veil_die "cannot parse the database role from the supplied DSN; use a plain socket DSN without credentials"
            veil_valid_name "$RESTORE_DBNAME" || veil_die "cannot parse the database name from the supplied DSN; use a plain socket DSN without credentials"
            veil_valid_path "$DSN" || veil_die "the supplied database DSN contains unsupported characters; use a plain socket DSN without credentials"
            ;;
        *) veil_die "--restore-db needs a passwordless socket DSN (postgres://role@%2F.../dbname); pass --database-url explicitly" ;;
    esac
    [ "$RESTORE_USER" = "$VEIL_USER" ] || veil_die "--restore-db requires the database role to match --user/VEIL_USER for peer authentication"
    if [ "$YES" -ne 1 ]; then
        printf 'This DROPS the database %s and recreates it from %s. Continue? [y/N] ' "$RESTORE_DBNAME" "$RESTORE_DB"
        if ! read -r _answer; then
            veil_die "aborted (no answer)"
        fi
        case "$_answer" in
            y | Y | yes | YES) ;;
            *) veil_die "aborted" ;;
        esac
        unset _answer
    fi
    veil_need su pg_restore psql
    # Stream the validated plaintext straight into pg_restore. In particular,
    # never materialize a decrypted database dump in /tmp, where a crash could
    # leave it behind for another process in the same security domain.
    restore_dump() {
        case "$RESTORE_DB" in
            *.dump.age) age --decrypt -i "$BACKUP_IDENTITY" "$RESTORE_DB" ;;
            *) cat "$RESTORE_DB" ;;
        esac
    }
    if ! restore_dump | pg_restore --list >/dev/null 2>&1; then
        veil_die "decrypted database backup is invalid or the supplied age identity is wrong"
    fi
    # A failed restore must still leave the service running if at all
    # possible: start it best-effort before reporting the failure.
    veil_service_stop || veil_die "could not stop $VEIL_SERVICE"
    if ! su -s /bin/sh postgres -c "psql -v ON_ERROR_STOP=1 -c \"DROP DATABASE \\\"$RESTORE_DBNAME\\\";\" -c \"CREATE DATABASE \\\"$RESTORE_DBNAME\\\" OWNER \\\"$RESTORE_USER\\\";\""; then
        if veil_service_start; then
            veil_die "database restore failed while recreating $RESTORE_DBNAME; the previous service was restarted"
        fi
        veil_die "database restore failed while recreating $RESTORE_DBNAME, and the service could not be restarted"
    fi
    if ! restore_dump | su -s /bin/sh "$VEIL_USER" -c "pg_restore --dbname '$DSN' --no-owner --exit-on-error"; then
        if veil_service_start; then
            veil_die "database restore failed while loading $RESTORE_DB; the previous service was restarted against the partial database"
        fi
        veil_die "database restore failed while loading $RESTORE_DB, and the service could not be restarted"
    fi
    veil_log "Database restored from $RESTORE_DB"
    unset RESTORE_USER RESTORE_DBNAME
fi

# --- 2. Restore the files and restart ------------------------------------------
# Like upgrade.sh, every step must either succeed or leave the service
# running: a bare set -e abort here would strand it stopped.
#
# A failed binary copy is retried by comparison: when the upgrade never
# managed to replace the binary, the identical file is already in place and
# there is nothing to restore. (A partial write differs and still fails.)
_restore_binary() {
    if veil_run install -m 0755 "$SNAP/veil-forum" "$VEIL_BIN"; then
        return 0
    fi
    if command -v cmp >/dev/null 2>&1 && [ -f "$VEIL_BIN" ] && cmp -s "$SNAP/veil-forum" "$VEIL_BIN"; then
        veil_warn "could not reinstall $VEIL_BIN, but the identical binary is already in place; continuing"
        return 0
    fi
    return 1
}
veil_service_stop || veil_die "could not stop $VEIL_SERVICE"
_restore_ok=1
_restore_binary || _restore_ok=0
if [ "$_restore_ok" -eq 1 ]; then
    veil_run rm -rf "$VEIL_STATIC_DIR" || _restore_ok=0
fi
if [ "$_restore_ok" -eq 1 ]; then
    veil_run mkdir -p "$VEIL_STATIC_DIR" || _restore_ok=0
fi
if [ "$_restore_ok" -eq 1 ]; then
    veil_run cp -r "$SNAP/static/." "$VEIL_STATIC_DIR/" || _restore_ok=0
fi
if [ "$_restore_ok" -eq 1 ]; then
    veil_run chmod -R a+rX "$VEIL_STATIC_DIR" || _restore_ok=0
fi
if [ "$_restore_ok" -eq 0 ]; then
    veil_warn "file restore failed; starting the service best-effort"
    if veil_service_start; then
        veil_die "rollback failed, but the previous service was restarted; snapshot at $SNAP"
    fi
    veil_die "rollback failed and the service could not be restarted; snapshot at $SNAP"
fi
veil_service_start

if veil_wait_healthz "$ADDR" "$HEALTH_TIMEOUT"; then
    veil_log ""
    veil_log "Done: rolled back to $VERSION; http://$ADDR/healthz says ok"
else
    veil_die "restored $VERSION but /healthz never answered; snapshot at $SNAP"
fi
