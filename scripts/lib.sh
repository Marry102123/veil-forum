#!/bin/sh
# Shared helpers for the veil-forum deployment scripts.
#
# Sourced, never executed directly:
#   SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
#   . "$SCRIPT_DIR/lib.sh"
#
# Every install location and database setting has a VEIL_* override so the
# scripts work on stock layouts and stay testable against stubs:
#
#   VEIL_SERVICE        service name              (default veil-forum)
#   VEIL_PREFIX         install prefix            (default /usr/local)
#   VEIL_BIN            binary path               (default $VEIL_PREFIX/bin/veil-forum)
#   VEIL_STATIC_DIR     static assets directory   (default $VEIL_PREFIX/static)
#   VEIL_STATE_DIR      service home and rollback snapshots (default /var/lib/veil-forum)
#   VEIL_ROLLBACK_ROOT  snapshot directory        (default $VEIL_STATE_DIR/rollback)
#   VEIL_USER           service user and default DB role (default veil-forum)
#   VEIL_DB_USER        database role             (default $VEIL_USER)
#   VEIL_DB_NAME        database name             (default veil_forum)
#   VEIL_DB_SOCKET      Unix socket directory     (default /var/run/postgresql)
#   VEIL_PORT           listener port             (default 8001)
#   VEIL_ADDR           listener address          (default 127.0.0.1:$VEIL_PORT)
#   VEIL_BACKUP_DIR     database backup directory (default /srv/veil-forum-backups)
#   VEIL_SERVICE_MANAGER systemd|openrc|none      (default: auto-detect)
#   VEIL_ALLOW_NONROOT=1 skips the root check (used by the test suite)
#
# Callers own `set -eu`; this file must stay compatible with POSIX sh.

# Defaults. ${VAR+x} probes avoid tripping `set -u` when a caller exports an
# empty value on purpose.
if [ -z "${VEIL_SERVICE+x}" ] || [ -z "$VEIL_SERVICE" ]; then VEIL_SERVICE="veil-forum"; fi
if [ -z "${VEIL_PREFIX+x}" ] || [ -z "$VEIL_PREFIX" ]; then VEIL_PREFIX="/usr/local"; fi
if [ -z "${VEIL_BIN+x}" ] || [ -z "$VEIL_BIN" ]; then VEIL_BIN="$VEIL_PREFIX/bin/veil-forum"; fi
if [ -z "${VEIL_STATIC_DIR+x}" ] || [ -z "$VEIL_STATIC_DIR" ]; then VEIL_STATIC_DIR="$VEIL_PREFIX/static"; fi
if [ -z "${VEIL_STATE_DIR+x}" ] || [ -z "$VEIL_STATE_DIR" ]; then VEIL_STATE_DIR="/var/lib/veil-forum"; fi
if [ -z "${VEIL_ROLLBACK_ROOT+x}" ] || [ -z "$VEIL_ROLLBACK_ROOT" ]; then VEIL_ROLLBACK_ROOT="$VEIL_STATE_DIR/rollback"; fi
if [ -z "${VEIL_USER+x}" ] || [ -z "$VEIL_USER" ]; then VEIL_USER="veil-forum"; fi
if [ -z "${VEIL_DB_USER+x}" ] || [ -z "$VEIL_DB_USER" ]; then VEIL_DB_USER="$VEIL_USER"; fi
if [ -z "${VEIL_DB_NAME+x}" ] || [ -z "$VEIL_DB_NAME" ]; then VEIL_DB_NAME="veil_forum"; fi
if [ -z "${VEIL_DB_SOCKET+x}" ] || [ -z "$VEIL_DB_SOCKET" ]; then VEIL_DB_SOCKET="/var/run/postgresql"; fi
if [ -z "${VEIL_PORT+x}" ] || [ -z "$VEIL_PORT" ]; then VEIL_PORT="8001"; fi
if [ -z "${VEIL_ADDR+x}" ] || [ -z "$VEIL_ADDR" ]; then VEIL_ADDR="127.0.0.1:$VEIL_PORT"; fi
if [ -z "${VEIL_BACKUP_DIR+x}" ] || [ -z "$VEIL_BACKUP_DIR" ]; then VEIL_BACKUP_DIR="/srv/veil-forum-backups"; fi
if [ -z "${DRY_RUN+x}" ]; then DRY_RUN=0; fi

veil_log() {
    printf '%s\n' "$*"
}

veil_warn() {
    printf 'warning: %s\n' "$*" >&2
}

veil_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

veil_need() {
    for _cmd in "$@"; do
        command -v "$_cmd" >/dev/null 2>&1 || veil_die "'$_cmd' is required but not installed"
    done
    unset _cmd
}

# Refuse to run privileged work as a normal user, unless the test suite says
# it is driving stubs.
veil_need_root() {
    if [ "${VEIL_ALLOW_NONROOT:-0}" = "1" ]; then
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        veil_die "run as root (for example: sudo $0 ...)"
    fi
}

# Strict names for users, roles and databases: letters, digits, underscore,
# dash and dot; never empty, never starting with a dash or a dot. Anything
# else could escape the su/psql command lines the scripts build.
veil_valid_name() {
    case "${1:-}" in
        "" | *[!A-Za-z0-9_.-]* | [-.]*) return 1 ;;
    esac
    return 0
}

# Paths, addresses and DSNs interpolated into shell or sed contexts: refuse
# quoting, expansion, chaining and redirection metacharacters plus
# whitespace. Names go through veil_valid_name instead.
veil_valid_path() {
    case "${1:-}" in
        "" | *"'"* | *'"'* | *'`'* | *'$'* | *';'* | *'&'* | *'|'* | *'('* | *')'* | *'<'* | *'>'* | *[[:space:]]*)
            return 1 ;;
    esac
    return 0
}

# Escape a value for the replacement side of a sed s||| expression.
veil_sed_escape() {
    printf '%s' "$1" | sed 's/[&|\]/\\&/g'
}

# Print `+ <command>` and run it, or only print it under --dry-run.
veil_run() {
    printf '+ %s\n' "$*"
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    "$@"
}

# Percent-encode a socket directory for the authority part of a
# postgres:// URL. Mirrors store::encode_socket_host in src/store.rs for every
# input that occurs in practice; socket directories are [A-Za-z0-9/_ .:-].
veil_encode_socket_host() {
    _dir=${1%/}
    printf '%s' "$_dir" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's|/|%2F|g' -e 's/:/%3A/g' -e 's/@/%40/g'
    unset _dir
}

# Build the peer-authentication socket DSN from its parts, so nobody
# hand-encodes the %2F URL. Mirrors store::socket_database_url.
veil_socket_dsn() {
    _user=${1:-$VEIL_DB_USER}
    _socket=${2:-$VEIL_DB_SOCKET}
    _name=${3:-$VEIL_DB_NAME}
    _socket=${_socket%/}
    [ -n "$_user" ] || veil_die "database user must not be empty"
    [ -n "$_socket" ] || veil_die "socket directory must not be empty"
    [ -n "$_name" ] || veil_die "database name must not be empty"
    printf 'postgres://%s@%s/%s' "$_user" "$(veil_encode_socket_host "$_socket")" "$_name"
    unset _user _socket _name
}

# systemd, openrc, or none. VEIL_SERVICE_MANAGER forces the answer, which is
# also how the test suite selects its stub.
veil_service_manager() {
    if [ -n "${VEIL_SERVICE_MANAGER:-}" ]; then
        printf '%s' "$VEIL_SERVICE_MANAGER"
        return 0
    fi
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf 'systemd'
    elif command -v rc-service >/dev/null 2>&1; then
        printf 'openrc'
    else
        printf 'none'
    fi
}

veil_service_stop() {
    case "$(veil_service_manager)" in
        systemd) veil_run systemctl stop "$VEIL_SERVICE" ;;
        openrc) veil_run rc-service "$VEIL_SERVICE" stop ;;
        none) veil_warn "no service manager found; stop $VEIL_BIN yourself" ;;
        *) veil_die "unknown service manager: $(veil_service_manager)" ;;
    esac
}

veil_service_start() {
    case "$(veil_service_manager)" in
        systemd) veil_run systemctl start "$VEIL_SERVICE" ;;
        openrc) veil_run rc-service "$VEIL_SERVICE" start ;;
        none) veil_warn "no service manager found; start $VEIL_BIN yourself" ;;
        *) veil_die "unknown service manager: $(veil_service_manager)" ;;
    esac
}

veil_service_enable_start() {
    case "$(veil_service_manager)" in
        systemd) veil_run systemctl enable --now "$VEIL_SERVICE" ;;
        openrc) veil_run rc-update add "$VEIL_SERVICE" default && veil_run rc-service "$VEIL_SERVICE" start ;;
        none) veil_warn "no service manager found; start $VEIL_BIN yourself" ;;
        *) veil_die "unknown service manager: $(veil_service_manager)" ;;
    esac
}

# Wait until GET http://ADDR/healthz answers "ok", or fail after $2 seconds.
veil_wait_healthz() {
    _addr=$1
    _timeout=${2:-30}
    _i=0
    while [ "$_i" -lt "$_timeout" ]; do
        if curl --fail --silent --max-time 2 "http://$_addr/healthz" 2>/dev/null | grep -q '^ok$'; then
            unset _addr _timeout _i
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    unset _addr _timeout _i
    return 1
}

# The version string of an installed binary ("0.1.0-alpha.18"), or "unknown".
veil_installed_version() {
    if [ -x "${1:-$VEIL_BIN}" ]; then
        "${1:-$VEIL_BIN}" --version 2>/dev/null | sed -n 's/^veil-forum //p' | head -n 1
    else
        printf 'unknown'
    fi
}
