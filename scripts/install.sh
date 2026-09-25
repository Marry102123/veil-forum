#!/bin/sh
# veil-forum installer: PostgreSQL role/database, files, service, first run.
#
# Usage:
#   sudo scripts/install.sh [options]
#
# Options:
#   --prefix DIR            install prefix (default /usr/local)
#   --user NAME             service user and default DB role (default veil-forum)
#   --db-user NAME          database role (default: same as --user)
#   --db-name NAME          database name (default veil_forum)
#   --db-socket DIR         PostgreSQL socket directory (default /var/run/postgresql)
#   --port PORT             listener port (default 8001, loopback only)
#   --addr HOST:PORT        full listener address (default 127.0.0.1:PORT)
#   --allow-nonloopback     put VEIL_ALLOW_NONLOOPBACK=1 in the unit (not recommended;
#                           keep the loopback listener and expose it via Tor/I2P)
#   --binary PATH           binary to install (default: the source build or the
#                           release archive binary next to this script)
#   --static DIR            static assets to install (default: ./static)
#   --admin-password-file F file holding the 15-128 character first-run admin
#                           password (or export VEIL_ADMIN_PASSWORD). Only needed
#                           when the database is still empty.
#   --no-service            install files and seed the database, but do not
#                           install or start a system service
#   --service-manager M     systemd|openrc|none (default: auto-detect)
#   --dry-run               print every step without changing anything
#
# Idempotent: re-running it repairs a half-finished install instead of failing.
# Only the binary and static/ travel with the release; templates, locales and
# migrations are embedded in the binary.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
REPO="$SCRIPT_DIR/.."

PREFIX="$VEIL_PREFIX"
USER="$VEIL_USER"
DB_USER=""
DB_NAME="$VEIL_DB_NAME"
DB_SOCKET="$VEIL_DB_SOCKET"
PORT="$VEIL_PORT"
ADDR=""
ALLOW_NONLOOPBACK=0
BINARY=""
STATIC_SRC=""
ADMIN_PASSWORD_FILE=""
NO_SERVICE=0
SERVICE_MANAGER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=${2:?--prefix needs a directory}; shift 2 ;;
        --user) USER=${2:?--user needs a name}; shift 2 ;;
        --db-user) DB_USER=${2:?--db-user needs a name}; shift 2 ;;
        --db-name) DB_NAME=${2:?--db-name needs a name}; shift 2 ;;
        --db-socket) DB_SOCKET=${2:?--db-socket needs a directory}; shift 2 ;;
        --port) PORT=${2:?--port needs a port}; shift 2 ;;
        --addr) ADDR=${2:?--addr needs HOST:PORT}; shift 2 ;;
        --allow-nonloopback) ALLOW_NONLOOPBACK=1; shift ;;
        --binary) BINARY=${2:?--binary needs a path}; shift 2 ;;
        --static) STATIC_SRC=${2:?--static needs a directory}; shift 2 ;;
        --admin-password-file) ADMIN_PASSWORD_FILE=${2:?--admin-password-file needs a file}; shift 2 ;;
        --no-service) NO_SERVICE=1; shift ;;
        --service-manager) SERVICE_MANAGER=${2:?--service-manager needs systemd|openrc|none}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h | --help) sed -n '2,/^set -eu$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) veil_die "unknown option $1 (try --help)" ;;
    esac
done

if [ "$DRY_RUN" -eq 0 ]; then
    veil_need_root
fi
if [ -z "$DB_USER" ]; then DB_USER="$USER"; fi
if [ -z "$ADDR" ]; then ADDR="127.0.0.1:$PORT"; fi
BIN="$PREFIX/bin/veil-forum"
STATIC_DIR="$PREFIX/static"
if [ -n "$SERVICE_MANAGER" ]; then VEIL_SERVICE_MANAGER="$SERVICE_MANAGER"; fi

# Every interpolated value is validated before use: names flow into su/psql
# command lines, paths and addresses into su -c quoting and sed replacements.
veil_valid_name "$USER" || veil_die "--user must be a plain name ([A-Za-z0-9_.-], not starting with - or .)"
veil_valid_name "$DB_USER" || veil_die "--db-user must be a plain name ([A-Za-z0-9_.-], not starting with - or .)"
veil_valid_name "$DB_NAME" || veil_die "--db-name must be a plain name ([A-Za-z0-9_.-], not starting with - or .)"
veil_valid_path "$PREFIX" || veil_die "--prefix must be a plain path without quoting or shell metacharacters"
veil_valid_path "$DB_SOCKET" || veil_die "--db-socket must be a plain path without quoting or shell metacharacters"
veil_valid_path "$ADDR" || veil_die "--addr must be HOST:PORT without quoting or shell metacharacters"
case "$ADDR" in
    127.* | \[::1\]* | localhost* | \[::ffff:127.*) ;;
    *)
        if [ "$ALLOW_NONLOOPBACK" -ne 1 ]; then
            veil_die "--addr $ADDR is not loopback; keep 127.0.0.1 and expose it via Tor/I2P, or pass --allow-nonloopback"
        fi
        veil_warn "--addr $ADDR is not loopback; the unit will carry VEIL_ALLOW_NONLOOPBACK=1" ;;
esac

if [ -z "$BINARY" ]; then
    if [ -x "$REPO/target/release/veil-forum" ]; then
        BINARY="$REPO/target/release/veil-forum"
    elif [ -x "$REPO/veil-forum" ]; then
        BINARY="$REPO/veil-forum"
    else
        veil_die "no binary found; build with 'cargo build --release' or pass --binary PATH"
    fi
fi
if [ -z "$STATIC_SRC" ]; then STATIC_SRC="$REPO/static"; fi
[ -x "$BINARY" ] || veil_die "binary is not executable: $BINARY"
# The seed step interpolates these into a single-quoted su command line.
veil_valid_path "$BINARY" || veil_die "--binary must be a plain path without quoting or shell metacharacters"
veil_valid_path "$STATIC_SRC" || veil_die "--static must be a plain path without quoting or shell metacharacters"
[ -d "$STATIC_SRC" ] || veil_die "static directory not found: $STATIC_SRC"
[ -f "$STATIC_SRC/style.css" ] || veil_die "static directory looks wrong (no style.css): $STATIC_SRC"

DSN=$(veil_socket_dsn "$DB_USER" "$DB_SOCKET" "$DB_NAME")

ADMIN_PASSWORD="${VEIL_ADMIN_PASSWORD:-}"
if [ -n "$ADMIN_PASSWORD_FILE" ]; then
    veil_valid_path "$ADMIN_PASSWORD_FILE" || veil_die "--admin-password-file must be a plain path without quoting or shell metacharacters"
    [ -f "$ADMIN_PASSWORD_FILE" ] || veil_die "password file not found: $ADMIN_PASSWORD_FILE"
    ADMIN_PASSWORD=$(cat "$ADMIN_PASSWORD_FILE")
fi

MANAGER=$(veil_service_manager)
if [ "$NO_SERVICE" -eq 0 ] && [ "$MANAGER" = "none" ]; then
    veil_die "no service manager found (need systemctl or rc-service); re-run with --no-service to install files only"
fi

veil_need psql su install curl
case "$MANAGER" in
    systemd) [ "$NO_SERVICE" -eq 1 ] || veil_need systemctl ;;
    openrc) [ "$NO_SERVICE" -eq 1 ] || veil_need rc-service ;;
esac

veil_log "Install plan:"
veil_log "  binary:  $BINARY -> $BIN"
veil_log "  static:  $STATIC_SRC -> $STATIC_DIR"
veil_log "  user:    $USER (home $VEIL_STATE_DIR)"
veil_log "  database: [redacted PostgreSQL connection string]"
veil_log "  listen:  $ADDR"
veil_log "  service: $([ "$NO_SERVICE" -eq 1 ] && printf 'none (--no-service)' || printf '%s/%s' "$MANAGER" "$VEIL_SERVICE")"

# --- 1. Service user -------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) would create system user $USER and $VEIL_STATE_DIR"
else
    if id "$USER" >/dev/null 2>&1; then
        veil_log "User $USER already exists"
    elif command -v useradd >/dev/null 2>&1; then
        veil_run useradd --system --group --home "$VEIL_STATE_DIR" --create-home --shell /usr/sbin/nologin "$USER"
    elif command -v adduser >/dev/null 2>&1; then
        veil_run adduser --system --group --home "$VEIL_STATE_DIR" --shell /usr/sbin/nologin "$USER"
    else
        veil_die "need useradd or adduser to create $USER"
    fi
    veil_run install -d -m 700 -o "$USER" -g "$USER" "$VEIL_STATE_DIR"
fi

# --- 2. PostgreSQL role and database (peer authentication, no password) ----
as_postgres() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '+ su -s /bin/sh postgres -c %s\n' "$1"
        return 0
    fi
    su -s /bin/sh postgres -c "$1"
}

if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) would create role $DB_USER and database $DB_NAME, and check pg_trgm"
else
    if [ "$(as_postgres "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'\"")" = "1" ]; then
        veil_log "Role $DB_USER already exists"
    else
        as_postgres "psql -v ON_ERROR_STOP=1 -c \"CREATE ROLE \\\"$DB_USER\\\" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\""
    fi
    role_flags=$(as_postgres "psql -tAc \"SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname='$DB_USER'\"")
    if [ "$role_flags" != "f|f|f|f|f|t" ]; then
        veil_die "role $DB_USER has excessive privileges or cannot log in. This installer will not change passwords or expand privileges. As a PostgreSQL administrator, review pg_roles and explicitly ALTER ROLE to LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS, then re-run."
    fi
    if [ "$(as_postgres "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='$DB_NAME'\"")" = "1" ]; then
        veil_log "Database $DB_NAME already exists"
    else
        as_postgres "psql -v ON_ERROR_STOP=1 -c \"CREATE DATABASE \\\"$DB_NAME\\\" OWNER \\\"$DB_USER\\\";\""
    fi
    if [ "$(as_postgres "psql -tAc \"SELECT 1 FROM pg_available_extensions WHERE name='pg_trgm'\"")" != "1" ]; then
        veil_die "the pg_trgm extension is missing; install the PostgreSQL contrib package (for example postgresql-contrib) and re-run"
    fi
fi

# --- 3. Binary and static assets -------------------------------------------
veil_run install -m 0755 "$BINARY" "$BIN"
veil_run rm -rf "$STATIC_DIR"
veil_run mkdir -p "$STATIC_DIR"
veil_run cp -r "$STATIC_SRC/." "$STATIC_DIR/"
veil_run chmod -R a+rX "$STATIC_DIR"
veil_log "Installed $($BIN --version 2>/dev/null || printf 'veil-forum')"

# --- 4. Service unit --------------------------------------------------------
install_systemd_unit() {
    _src="$REPO/deploy/veil-forum.service"
    [ -f "$_src" ] || veil_die "unit template not found: $_src"
    _tmp=$(mktemp)
    # The unit template carries example --addr/--database-url values; the
    # installed unit always reflects this run. Values are sed-escaped because
    # even validated input may carry & (harmless in a name, special to sed).
    _bin_esc=$(veil_sed_escape "$BIN")
    _addr_esc=$(veil_sed_escape "$ADDR")
    _dsn_esc=$(veil_sed_escape "$DSN")
    sed "s|^ExecStart=.*|ExecStart=${_bin_esc} --addr ${_addr_esc} --database-url ${_dsn_esc}|" "$_src" >"$_tmp"
    if [ "$ALLOW_NONLOOPBACK" -eq 1 ]; then
        sed "/^\\[Service\\]$/a Environment=VEIL_ALLOW_NONLOOPBACK=1" "$_tmp" >"$_tmp.env"
        mv "$_tmp.env" "$_tmp"
    fi
    veil_run install -m 0644 "$_tmp" "/etc/systemd/system/$VEIL_SERVICE.service"
    rm -f "$_tmp"
    veil_run systemctl daemon-reload
    unset _src _tmp _bin_esc _addr_esc _dsn_esc
}

install_openrc_script() {
    _src="$REPO/deploy/veil-forum.openrc"
    [ -f "$_src" ] || veil_die "openrc template not found: $_src"
    _tmp=$(mktemp)
    _bin_esc=$(veil_sed_escape "$BIN")
    _args_esc=$(veil_sed_escape "--addr $ADDR --database-url $DSN")
    sed -e "s|^command=.*|command=\"${_bin_esc}\"|" \
        -e "s|^command_args=.*|command_args=\"${_args_esc}\"|" \
        "$_src" >"$_tmp"
    veil_run install -m 0755 "$_tmp" "/etc/init.d/$VEIL_SERVICE"
    rm -f "$_tmp"
    unset _src _tmp _bin_esc _args_esc
}

if [ "$NO_SERVICE" -eq 0 ]; then
    case "$MANAGER" in
        systemd) install_systemd_unit ;;
        openrc) install_openrc_script ;;
    esac
fi

# --- 5. First run: migrations plus the initial administrator ---------------
fresh_database() {
    # 0 when the users table is missing or empty. Probes run as the postgres
    # superuser because peer authentication maps the OS user to the role.
    _count=$(as_postgres "psql -d '$DB_NAME' -tAc 'SELECT COUNT(*) FROM users'" 2>/dev/null) || return 0
    [ "$_count" = "0" ]
    unset _count
}

if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) would seed the database (migrations + initial admin) and start the service"
else
    if fresh_database; then
        [ -n "$ADMIN_PASSWORD" ] || veil_die "the database is empty: provide the first admin password via --admin-password-file or VEIL_ADMIN_PASSWORD (15-128 characters)"
        case "$ADMIN_PASSWORD" in
            *"
"*) veil_die "the admin password must not contain a newline" ;;
        esac
        admin_password_chars=$(printf '%s' "$ADMIN_PASSWORD" | wc -m)
        if [ "$admin_password_chars" -lt 15 ] || [ "$admin_password_chars" -gt 128 ]; then
            veil_die "VEIL_ADMIN_PASSWORD must contain 15-128 characters and pass the application's strength check"
        fi
        unset admin_password_chars
        _env=$(mktemp)
        chmod 600 "$_env"
        chown "$USER" "$_env"
        _escaped=$(printf '%s' "$ADMIN_PASSWORD" | sed "s/'/'\\\\''/g")
        printf "VEIL_ADMIN_PASSWORD='%s'\n" "$_escaped" >"$_env"
        # Seed outside the service manager so every layout (including
        # --no-service) initializes the same way; the env file (0600) keeps
        # the password out of the process table.
        su -s /bin/sh "$USER" -c "set -a; . '$_env'; set +a; exec '$BIN' --addr '$ADDR' --database-url '$DSN'" &
        _pid=$!
        # An interrupted install must neither leak the password file nor leave
        # the seed process behind.
        trap 'kill $_pid 2>/dev/null || true; rm -f $_env' EXIT HUP INT TERM
        if veil_wait_healthz "$ADDR" 60; then
            veil_log "First run healthy; stopping the seed process"
        else
            kill "$_pid" 2>/dev/null || true
            wait "$_pid" 2>/dev/null || true
            rm -f "$_env"
            trap - EXIT HUP INT TERM
            veil_die "seed process never became healthy; fix the database and re-run"
        fi
        kill "$_pid" 2>/dev/null || true
        wait "$_pid" 2>/dev/null || true
        rm -f "$_env"
        trap - EXIT HUP INT TERM
        unset _env _escaped _pid
    else
        veil_log "Database already initialized; keeping the existing administrator"
    fi
fi

# --- 6. Start ---------------------------------------------------------------
if [ "$NO_SERVICE" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    veil_service_enable_start
    if veil_wait_healthz "$ADDR" 30; then
        veil_log "Service $VEIL_SERVICE is up: http://$ADDR/healthz says ok"
    else
        veil_die "service started but /healthz never answered; inspect the logs (journalctl -u $VEIL_SERVICE or /var/log)"
    fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
    veil_log "(dry-run) nothing was changed"
    exit 0
fi

veil_log ""
veil_log "Done: $($BIN --version) listening on $ADDR"
veil_log "Open http://$ADDR locally, then expose it only through Tor or I2P (docs/onion-i2p-deployment.md)."
veil_log "Back up with: scripts/db-maintenance.sh backup '$DSN' $VEIL_BACKUP_DIR"
if fresh_database; then
    veil_warn "fresh_database probe says the database is still empty, which should not happen; check the seed log above"
fi
