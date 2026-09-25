#!/bin/sh
# veil-forum upgrade: verify, back up, snapshot, install, health-check,
# and automatically roll back on failure.
#
# Usage:
#   sudo scripts/upgrade.sh ARCHIVE.tar.gz [options]
#
# Options:
#   --checksums FILE        sha256 checksum file listing the archive (required
#                           unless --no-checksum-verify is given)
#   --signatures DIR        directory containing <asset>.sig and <asset>.pem
#                           bundles (required unless --no-attestation-verify)
#   --no-attestation-verify LEGACY_TAG
#                           EMERGENCY ONLY: skip Sigstore identity verification
#                           for this exact historical unsigned tag
#   --no-checksum-verify    skip checksum verification (not recommended)
#   --backup-dir DIR        database backup directory (default /srv/veil-forum-backups)
#   --no-backup             skip the pre-upgrade database backup (not recommended)
#   --database-url URL      connection string (default: the installed unit's
#                           value, else the local socket DSN)
#   --db-user NAME --db-name NAME --db-socket DIR
#                           socket DSN parts, as in install.sh (rejected when
#                           combined with --database-url)
#   --addr HOST:PORT        listener address for the health check (default: the
#                           installed unit's value, else 127.0.0.1:8001)
#   --prefix DIR --user NAME
#                           install prefix and service user (defaults /usr/local,
#                           veil-forum, shared with install.sh via VEIL_*)
#   --service-manager M     systemd|openrc|none (default: auto-detect)
#   --health-timeout SECS   seconds to wait for /healthz (default 60)
#   --dry-run               print every step without changing anything
#
# Only the binary and static/ are replaced; the unit file is left untouched.
# On failure the previous binary and static/ are restored automatically and the
# pre-upgrade database backup path is reported.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

ARCHIVE=""
CHECKSUMS=""
SIGNATURES=""
NO_ATTESTATION_VERIFY=""
NO_CHECKSUM_VERIFY=0
BACKUP_DIR="$VEIL_BACKUP_DIR"
NO_BACKUP=0
EXPLICIT_URL=""
DB_USER="$VEIL_DB_USER"
DB_SOCKET="$VEIL_DB_SOCKET"
DB_NAME="$VEIL_DB_NAME"
SOCKET_FLAGS=0
EXPLICIT_ADDR=""
HEALTH_TIMEOUT=60
PREFIX_GIVEN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --checksums) CHECKSUMS=${2:?--checksums needs a file}; shift 2 ;;
        --signatures) SIGNATURES=${2:?--signatures needs a directory}; shift 2 ;;
        --no-attestation-verify) NO_ATTESTATION_VERIFY=${2:?--no-attestation-verify needs a legacy tag}; shift 2 ;;
        --no-checksum-verify) NO_CHECKSUM_VERIFY=1; shift ;;
        --backup-dir) BACKUP_DIR=${2:?--backup-dir needs a directory}; shift 2 ;;
        --no-backup) NO_BACKUP=1; shift ;;
        --database-url) EXPLICIT_URL=${2:?--database-url needs a URL}; shift 2 ;;
        --db-user) DB_USER=${2:?--db-user needs a name}; SOCKET_FLAGS=1; shift 2 ;;
        --db-name) DB_NAME=${2:?--db-name needs a name}; SOCKET_FLAGS=1; shift 2 ;;
        --db-socket) DB_SOCKET=${2:?--db-socket needs a directory}; SOCKET_FLAGS=1; shift 2 ;;
        --addr) EXPLICIT_ADDR=${2:?--addr needs HOST:PORT}; shift 2 ;;
        --prefix) VEIL_PREFIX=${2:?--prefix needs a directory}; PREFIX_GIVEN=1; shift 2 ;;
        --user) VEIL_USER=${2:?--user needs a name}; shift 2 ;;
        --service-manager) VEIL_SERVICE_MANAGER=${2:?--service-manager needs systemd|openrc|none}; shift 2 ;;
        --health-timeout) HEALTH_TIMEOUT=${2:?--health-timeout needs seconds}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h | --help) sed -n '2,/^set -eu$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) veil_die "unknown option $1 (try --help)" ;;
        *) [ -z "$ARCHIVE" ] || veil_die "only one archive: already have $ARCHIVE"; ARCHIVE=$1; shift ;;
    esac
done

# Install locations follow the prefix, like install.sh does. An explicitly
# exported VEIL_BIN is respected unless --prefix overrides it.
if [ "$PREFIX_GIVEN" -eq 1 ]; then
    VEIL_BIN="$VEIL_PREFIX/bin/veil-forum"
    VEIL_STATIC_DIR="$VEIL_PREFIX/static"
fi

[ -n "$ARCHIVE" ] || veil_die "usage: $0 ARCHIVE.tar.gz [options]"
veil_valid_path "$ARCHIVE" || veil_die "archive path must be plain, without quoting or shell metacharacters"
[ -f "$ARCHIVE" ] || veil_die "archive not found: $ARCHIVE"
if [ -n "$CHECKSUMS" ]; then
    veil_valid_path "$CHECKSUMS" || veil_die "checksum path must be plain, without quoting or shell metacharacters"
fi
if [ -n "$SIGNATURES" ]; then
    [ -d "$SIGNATURES" ] || veil_die "signature directory not found: $SIGNATURES"
    veil_valid_path "$SIGNATURES" || veil_die "signature directory must be a plain path without shell metacharacters"
fi
veil_valid_path "$BACKUP_DIR" || veil_die "backup directory must be plain, without quoting or shell metacharacters"
veil_valid_name "$VEIL_USER" || veil_die "--user must be a plain name ([A-Za-z0-9_.-], not starting with - or .)"
if [ -n "$EXPLICIT_ADDR" ]; then
    veil_valid_path "$EXPLICIT_ADDR" || veil_die "--addr must be HOST:PORT without quoting or shell metacharacters"
fi
if [ "$SOCKET_FLAGS" -eq 1 ]; then
    veil_valid_name "$DB_USER" || veil_die "--db-user must be a plain name"
    veil_valid_name "$DB_NAME" || veil_die "--db-name must be a plain name"
    veil_valid_path "$DB_SOCKET" || veil_die "--db-socket must be a plain path"
fi
if [ "$DRY_RUN" -eq 0 ]; then
    veil_need_root
fi
veil_need tar sha256sum curl install
# Swapping files under a running server the scripts cannot stop would mix
# releases, so a supported manager is required outside --dry-run.
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

if [ -n "$EXPLICIT_URL" ] && [ "$SOCKET_FLAGS" -eq 1 ]; then
    veil_die "cannot combine --database-url with --db-socket/--db-name/--db-user; use one or the other"
fi
if [ -z "$CHECKSUMS" ] && [ "$NO_CHECKSUM_VERIFY" -eq 0 ]; then
    veil_die "refusing to install an unverified archive; pass --checksums FILE or --no-checksum-verify"
fi
if [ -z "$SIGNATURES" ] && [ -z "$NO_ATTESTATION_VERIFY" ]; then
    veil_die "refusing to install an unsigned archive; pass --signatures DIR or the explicit legacy escape --no-attestation-verify TAG"
fi

# --- 1. Verify the archive ---------------------------------------------------
ARCHIVE_BASE=$(basename "$ARCHIVE")
ARCHIVE_DIR=$(CDPATH= cd -- "$(dirname -- "$ARCHIVE")" && pwd)
RELEASE_TAG=$(printf '%s\n' "$ARCHIVE_BASE" | sed -n 's/^veil-forum-\(v.*\)-\(x86_64\|aarch64\|armv7\|riscv64gc\|i686\|powerpc64le\|s390x\)-.*\.tar\.gz$/\1/p')
[ -n "$RELEASE_TAG" ] || veil_die "cannot determine release tag from archive name: $ARCHIVE_BASE"
if [ -n "$NO_ATTESTATION_VERIFY" ] && [ "$NO_ATTESTATION_VERIFY" != "$RELEASE_TAG" ]; then
    veil_die "legacy attestation bypass tag $NO_ATTESTATION_VERIFY does not match archive tag $RELEASE_TAG"
fi
if [ -n "$NO_ATTESTATION_VERIFY" ] && [ "$RELEASE_TAG" != "v0.1.0-alpha.19" ]; then
    veil_die "unsigned legacy verification is allowed only for v0.1.0-alpha.19"
fi
verify_signature() {
    _asset=$1
    _name=${_asset##*/}
    _bundle="$SIGNATURES/$_name.sig"
    _certificate="$SIGNATURES/$_name.pem"
    [ -s "$_bundle" ] || veil_die "missing signature bundle for $_name: $_bundle"
    [ -s "$_certificate" ] || veil_die "missing signing certificate for $_name: $_certificate"
    cosign verify-blob --bundle "$_bundle" --certificate "$_certificate" \
        --certificate-identity-regexp "^https://github.com/Marry102123/veil-forum/\\.github/workflows/ci\\.yml@refs/tags/$RELEASE_TAG$" \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$_asset" || veil_die "Sigstore verification failed for $_name"
}

if [ -n "$SIGNATURES" ]; then
    veil_need cosign
    veil_log "Verifying Sigstore bundle and pinned repository identity for $ARCHIVE_BASE"
    verify_signature "$ARCHIVE"
    if [ -n "$CHECKSUMS" ]; then
        veil_log "Verifying Sigstore bundle and pinned repository identity for $(basename "$CHECKSUMS")"
        verify_signature "$CHECKSUMS"
    fi
else
    printf '\n*** EMERGENCY SECURITY BYPASS: Sigstore verification is DISABLED for explicit legacy tag %s. Do not use this for new releases. ***\n\n' "$NO_ATTESTATION_VERIFY" >&2
fi
if [ -n "$CHECKSUMS" ]; then
    [ -f "$CHECKSUMS" ] || veil_die "checksum file not found: $CHECKSUMS"
    veil_log "Verifying $ARCHIVE_BASE against $CHECKSUMS"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '+ (cd %s && grep -F "  %s" %s | sha256sum -c -)\n' "$ARCHIVE_DIR" "$ARCHIVE_BASE" "$CHECKSUMS"
    else
        (cd "$ARCHIVE_DIR" && grep -F "  $ARCHIVE_BASE" "$CHECKSUMS" | sha256sum -c -) ||
            veil_die "checksum verification failed for $ARCHIVE_BASE"
    fi
elif [ "$DRY_RUN" -eq 0 ]; then
    veil_warn "skipping checksum verification (--no-checksum-verify)"
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
# Extraction is inspection-only (a trapped temporary directory), so even
# --dry-run does it: the plan then shows the real incoming version.
tar -xzf "$ARCHIVE" -C "$STAGE"
set -- "$STAGE"/*/
[ $# -eq 1 ] && [ -d "${1%/}" ] || veil_die "archive must contain a single top directory"
TOP=${1%/}
[ -x "$TOP/veil-forum" ] || veil_die "archive has no executable <top>/veil-forum"
[ -f "$TOP/static/style.css" ] || veil_die "archive has no <top>/static/style.css"
NEW_VERSION=$("$TOP/veil-forum" --version 2>/dev/null | sed -n 's/^veil-forum //p' | head -n 1 || true)
[ -n "$NEW_VERSION" ] || NEW_VERSION="unknown"

# --- 2. Connection string and listener ---------------------------------------
read_unit_setting() {
    # VEIL_UNIT_FILE overrides the installed unit path (used by the tests).
    _unit="${VEIL_UNIT_FILE:-/etc/systemd/system/$VEIL_SERVICE.service}"
    [ -f "$_unit" ] || return 1
    sed -n "s/.*$1 \([^ ][^ ]*\).*/\\1/p" "$_unit" | head -n 1
    unset _unit
}

if [ -n "$EXPLICIT_URL" ]; then
    DSN="$EXPLICIT_URL"
elif _from_unit=$(read_unit_setting "--database-url") && [ -n "$_from_unit" ]; then
    DSN="$_from_unit"
else
    DSN=$(veil_socket_dsn "$DB_USER" "$DB_SOCKET" "$DB_NAME")
fi
if [ -n "$EXPLICIT_ADDR" ]; then
    ADDR="$EXPLICIT_ADDR"
elif _from_unit=$(read_unit_setting "--addr") && [ -n "$_from_unit" ]; then
    ADDR="$_from_unit"
else
    ADDR="$VEIL_ADDR"
fi
unset _from_unit

[ -x "$VEIL_BIN" ] || veil_die "nothing installed at $VEIL_BIN; run install.sh first"
OLD_VERSION=$(veil_installed_version)

veil_log "Upgrade plan: $OLD_VERSION -> ${NEW_VERSION:-unknown}"
veil_log "  database: [redacted PostgreSQL connection string]"
veil_log "  listen:   $ADDR"

# --- 3. Back up the database first -------------------------------------------
if [ "$NO_BACKUP" -eq 1 ]; then
    veil_warn "skipping the pre-upgrade database backup (--no-backup)"
    DB_DUMP="none (--no-backup)"
elif [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) would run: scripts/db-maintenance.sh backup [DSN] $BACKUP_DIR"
    DB_DUMP="(dry-run)"
else
    # Do not use veil_run here: it prints command arguments and a full DSN may
    # carry a password. The child process still receives the real value.
    printf '+ %s backup [redacted PostgreSQL connection string] %s\n' "$SCRIPT_DIR/db-maintenance.sh" "$BACKUP_DIR"
    "$SCRIPT_DIR/db-maintenance.sh" backup "$DSN" "$BACKUP_DIR" || veil_die "pre-upgrade backup failed; refusing to continue"
    # Only encrypted archives are canonical. A legacy plaintext dump may be
    # used only when no encrypted archive exists, and is never created here.
    DB_DUMP=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'forum-*.dump.age' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-) || DB_DUMP=""
    if [ -z "$DB_DUMP" ]; then
        DB_DUMP=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'forum-*.dump' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-) || DB_DUMP=""
    fi
    [ -n "$DB_DUMP" ] || veil_die "backup produced no encrypted archive in $BACKUP_DIR"
    veil_log "Pre-upgrade backup: $DB_DUMP"
fi

# --- 4. Snapshot the running release ------------------------------------------
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SNAP="$VEIL_ROLLBACK_ROOT/${OLD_VERSION}-${STAMP}"
if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) would snapshot $VEIL_BIN and $VEIL_STATIC_DIR to $SNAP"
else
    # The snapshot must be complete before the service stops: a failure here
    # aborts with the old release still running, so no rollback is needed.
    veil_run install -d -m 700 "$SNAP" || veil_die "could not create snapshot directory $SNAP"
    veil_run install -m 0755 "$VEIL_BIN" "$SNAP/veil-forum" || veil_die "could not snapshot the running binary"
    veil_run rm -rf "$SNAP/static" || veil_die "could not clear $SNAP/static"
    veil_run mkdir -p "$SNAP/static" || veil_die "could not create $SNAP/static"
    veil_run cp -r "$VEIL_STATIC_DIR/." "$SNAP/static/" || veil_die "could not snapshot the static assets"
    printf '%s\n' "$OLD_VERSION" >"$SNAP/VERSION"
    # A rollback that does not restore the database does not need the original
    # connection string. Persist it only for the passwordless peer-auth socket
    # form, never a TCP/password URL supplied on the command line.
    SNAPSHOT_DSN=""
    case "$DSN" in
        postgres://*@%2F*/*)
            _dsn_authority=${DSN#postgres://}
            _dsn_authority=${_dsn_authority%%@*}
            _dsn_name=${DSN##*/}
            _dsn_path=${DSN#postgres://}
            _dsn_path=${_dsn_path#*@}
            _dsn_path=${_dsn_path#*/}
            if veil_valid_name "$_dsn_authority" && veil_valid_name "$_dsn_name" && veil_valid_path "$_dsn_path"; then
                SNAPSHOT_DSN="$DSN"
            fi
            unset _dsn_authority _dsn_name _dsn_path
            ;;
    esac
    if [ -n "$SNAPSHOT_DSN" ]; then
        printf '%s\n' "$SNAPSHOT_DSN" >"$SNAP/DSN"
    else
        veil_warn "not persisting a non-peer or credential-bearing DSN in $SNAP/DSN"
    fi
    printf '%s\n' "$ADDR" >"$SNAP/ADDR"
    printf '%s\n' "$DB_DUMP" >"$SNAP/DB_DUMP"
    chmod 600 "$SNAP/VERSION" "$SNAP/ADDR" "$SNAP/DB_DUMP"
    if [ -f "$SNAP/DSN" ]; then chmod 600 "$SNAP/DSN"; fi
    unset SNAPSHOT_DSN
    veil_log "Snapshot: $SNAP"
fi

# --- 5. Install, start, and health-check --------------------------------------
# Every step below must either succeed or trigger the rollback: with
# `set -eu` a bare failure would abort the script and leave the service
# stopped halfway through the swap.
rollback_and_die() {
    veil_warn "$1; restoring $SNAP"
    export VEIL_PREFIX VEIL_BIN VEIL_STATIC_DIR VEIL_USER VEIL_SERVICE VEIL_SERVICE_MANAGER
    if "$SCRIPT_DIR/rollback.sh" --snapshot "$SNAP" --health-timeout "$HEALTH_TIMEOUT"; then
        veil_warn "rollback succeeded; the forum runs $OLD_VERSION again"
    else
        veil_die "rollback itself failed; snapshot at $SNAP, database backup at $DB_DUMP"
    fi
    veil_die "upgrade failed and was rolled back; database backup at $DB_DUMP"
}

if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) would stop the service, install the new binary and static/, start, and wait for /healthz"
    veil_log "(dry-run) on failure it would restore $SNAP automatically"
    veil_log "(dry-run) nothing was changed"
    exit 0
fi

veil_service_stop || rollback_and_die "could not stop $VEIL_SERVICE"
veil_run install -m 0755 "$TOP/veil-forum" "$VEIL_BIN" || rollback_and_die "could not install the new binary"
veil_run rm -rf "$VEIL_STATIC_DIR" || rollback_and_die "could not clear $VEIL_STATIC_DIR"
veil_run mkdir -p "$VEIL_STATIC_DIR" || rollback_and_die "could not recreate $VEIL_STATIC_DIR"
veil_run cp -r "$TOP/static/." "$VEIL_STATIC_DIR/" || rollback_and_die "could not install the new static assets"
veil_run chmod -R a+rX "$VEIL_STATIC_DIR" || rollback_and_die "could not fix static asset permissions"
veil_service_start || rollback_and_die "could not start $VEIL_SERVICE"

if veil_wait_healthz "$ADDR" "$HEALTH_TIMEOUT"; then
    veil_log ""
    veil_log "Done: $OLD_VERSION -> $("$VEIL_BIN" --version | sed -n 's/^veil-forum //p')"
    veil_log "Health: http://$ADDR/healthz says ok"
    veil_log "Backup: $DB_DUMP"
    veil_log "If anything looks wrong later: sudo scripts/rollback.sh --snapshot $SNAP"
    exit 0
fi
rollback_and_die "new release failed its health check"
