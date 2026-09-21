# veil-forum

An experimental, self-hosted forum for Tor Onion Service and I2P deployments.
Written in Rust with Axum and PostgreSQL, it serves HTML without requiring
JavaScript and listens on loopback by default.

**Alpha software. [AGPL-3.0-only](LICENSE).** It is intended for review and
experimental deployment, not as a guarantee of anonymity or production security.

## What it includes

- **Forum:** boards, threads, nested replies, full-text search, and optional
  anonymous posts per board.
- **Safe content:** sanitized Markdown, no remote images, and restrictive CSP.
- **Accounts:** open, invite-only, or closed registration, Argon2id passwords,
  expiring sessions, CSRF and Origin checks.
- **Two-step verification:** optional TOTP (RFC 6238) per account, with inline
  SVG enrolment QR codes, one-time recovery codes, single-use codes, and
  administrator policy switches for staff-only or site-wide enforcement.
- **Abuse controls:** independently configurable PoW and self-hosted image
  CAPTCHA for registration, login, and posting.
- **Administration:** board and invite management, configurable site/footer
  text, announcements, locale, registration policy, and audit logs.
- **Governance:** reports, moderation actions, soft-delete recovery, scoped
  roles, and session revocation.
- **Deployment:** one binary plus `static/`, embedded PostgreSQL migrations,
  scripted install/upgrade/rollback, `pg_dump` backups, a local Unix-socket
  connection with peer authentication, and loopback-only-by-default operation
  for a local Tor or I2P gateway.

## Quick start

Pick one path. Production means path B plus a Tor/I2P gateway.

### A. Try it from source (5 minutes, local only)

Requirements: Rust 1.88 or newer and PostgreSQL 15 or newer (with the
`pg_trgm` extension from the contrib modules). The repository pins the CI and
local development toolchain through `rust-toolchain.toml`.

```bash
sudo -u postgres createuser --no-createdb --no-superuser "$USER"
sudo -u postgres createdb -O "$USER" veil_forum
cargo build
VEIL_ADMIN_PASSWORD='replace-with-a-long-random-password' \
  ./target/debug/veil-forum --db-user "$USER"
```

Open `http://127.0.0.1:8001` locally. `--db-user`/`--db-name`/`--db-socket`
compose the Unix-socket connection string for you; `--database-url` (or
`DATABASE_URL`) overrides them with a full connection string.

### B. Install a release on a server (recommended)

Download the archive for your CPU architecture and its checksum from the
[releases page](https://github.com/Marry102123/veil-forum/releases), then
verify and extract it:

```bash
sha256sum -c veil-forum-*-checksums.txt
tar -xzf veil-forum-*-x86_64-unknown-linux-musl.tar.gz
cd veil-forum-*
```

Preview what the installer will do, then run it:

```bash
sudo ./scripts/install.sh --dry-run
sudo ./scripts/install.sh --admin-password-file /root/veil-adminpw
```

The installer creates the `veil-forum` system user, the PostgreSQL role and
database (peer authentication, no password stored anywhere), installs the
binary to `/usr/local/bin` with `static/` next to it, installs the systemd
(or OpenRC) unit, seeds the first administrator, and verifies `/healthz`.
Only the binary and `static/` are required at runtime: templates, locales
and migrations are embedded in the binary.

To install by hand instead, see [Operations](docs/operations.md#manual-installation).

### C. Expose it through Tor or I2P

Keep the loopback listener and put the gateway in front of it:

```text
HiddenServiceDir /var/lib/tor/veil-forum/
HiddenServicePort 80 127.0.0.1:8001
```

Details: [Onion and I2P deployment](docs/onion-i2p-deployment.md). The server
refuses non-loopback listeners unless `VEIL_ALLOW_NONLOOPBACK=1` is
explicitly set.

## Configuration

`./veil-forum --help` prints everything. The common settings:

| Setting | Flag | Environment | Default |
|---|---|---|---|
| Listener | `--addr HOST:PORT` | — | `127.0.0.1:8001` |
| Database (socket parts) | `--db-user/--db-name/--db-socket` | — | `veil-forum` / `veil_forum` / `/var/run/postgresql` |
| Database (full URL) | `--database-url URL` | `DATABASE_URL` | socket DSN above |
| First admin (first run only) | — | `VEIL_ADMIN_PASSWORD` (12-128 chars) | required when the DB is empty |
| Allow non-loopback | — | `VEIL_ALLOW_NONLOOPBACK=1` | refused |
| Force secure cookies | — | `VEIL_SESSION_COOKIE_SECURE=0/1` | `Secure` off on loopback, on otherwise |
| Backup retention | — | `VEIL_BACKUP_RETAIN` | `30` |

`--database-url` and the `--db-*` parts cannot be combined. Passwords in a
connection string are never printed; startup errors show them as `***`.
Remove `VEIL_ADMIN_PASSWORD` from the service environment after the first
start.

## Operating it

```bash
# Back up the database (verified, mode 600, keeps 30 archives)
sudo scripts/db-maintenance.sh backup

# Upgrade from a release archive (verifies checksums, backs up first,
# snapshots the running release, health-checks, rolls back on failure)
sudo scripts/upgrade.sh veil-forum-*.tar.gz --checksums veil-forum-*-checksums.txt

# Roll back to the previous snapshot (database untouched)
sudo scripts/rollback.sh
```

Full procedures, including restoring a database backup when a failed release
already applied a migration: [Operations](docs/operations.md).

## Screenshots

The following screenshots show the English demo instance and its server-rendered administration workspaces.

![Forum home](docs/screenshots/home.png)

![Technology board](docs/screenshots/board-tech.png)

![System settings](docs/screenshots/settings.png)

![Governance workspace](docs/screenshots/governance.png)

## Architecture

```text
Tor Onion Service ─┐
                   ├── 127.0.0.1:8001 ── veil-forum ── PostgreSQL (Unix socket)
I2P HTTP Server ───┘
```

## Security and Privacy

The application does not require email addresses, client IP addresses, third
party authentication, analytics, CDNs, remote fonts, or external images. It
uses restrictive response headers, sanitized Markdown, CSRF protection, and
absolute plus idle session expiry.

Deployment remains the operator's responsibility. Protect the database and its
server, gateway private keys, backups, operating system, and
service egress. Anonymous display names are not a guarantee of anonymity.

## Documentation

- [Operations: install, backup, upgrade, rollback, systemd](docs/operations.md)
- [Onion and I2P deployment](docs/onion-i2p-deployment.md)
- [Release checklist](docs/release.md)
- [Anonymous deployment security checklist](docs/security-checklist.md)
- [Security reporting policy](SECURITY.md)
- [Changelog and known dependency limitations](CHANGELOG.md)

## Development

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets
tests/scripts.sh
tests/deploy-scripts.sh
cargo build --release
cargo audit --ignore RUSTSEC-2023-0071
```

The optional `external-go-interop` feature requires a separate Go compatibility
project. Set `VEIL_GO_PROJECT` and optionally `VEIL_GO_BIN` before enabling it.

## License

Copyright (C) 2026 veil-forum contributors.

veil-forum is licensed under the GNU Affero General Public License, version 3
only. Network deployments of modified versions must provide corresponding
source to remote users as required by AGPL section 13.
