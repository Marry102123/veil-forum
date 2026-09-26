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
  scripted install/upgrade/rollback, age-encrypted `pg_dump` backups, a local
  Unix-socket connection with peer authentication, and
  loopback-only-by-default operation for a local Tor or I2P gateway.

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
| Listener | `--addr HOST:PORT` | none | `127.0.0.1:8001` |
| Database (socket parts) | `--db-user/--db-name/--db-socket` | none | `veil-forum` / `veil_forum` / `/var/run/postgresql` |
| Database (full URL) | `--database-url URL` | `DATABASE_URL` | socket DSN above |
| First admin (first run only) | none | `VEIL_ADMIN_PASSWORD` (15-128 chars, strong) | required when the DB is empty |
| Allow non-loopback | none | `VEIL_ALLOW_NONLOOPBACK=1` | refused |
| Force secure cookies | none | `VEIL_SESSION_COOKIE_SECURE=0/1` | `Secure` off on loopback, on otherwise |
| Backup retention | none | `VEIL_BACKUP_RETAIN` | `30` |

`--database-url` and the `--db-*` parts cannot be combined. Passwords in a
connection string are never printed; startup errors show them as `***`.
Remove `VEIL_ADMIN_PASSWORD` from the service environment after the first
start.

## Operating it

```bash
# Back up the database (verified .dump.age, mode 600, keeps 30 archives).
# Do not rely on sudo inheriting this variable from the ordinary shell.
sudo env VEIL_BACKUP_RECIPIENT_FILE=/etc/veil-forum/backup-recipients \
  scripts/db-maintenance.sh backup

# Upgrade one release archive (verifies checksums and signatures, backs up
# first, snapshots the running release, health-checks, rolls back on failure)
sudo env VEIL_BACKUP_RECIPIENT_FILE=/etc/veil-forum/backup-recipients \
  scripts/upgrade.sh /srv/releases/veil-forum-vVERSION-x86_64-unknown-linux-musl.tar.gz \
  --checksums /srv/releases/veil-forum-vVERSION-checksums.txt \
  --signatures /srv/releases/signatures

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
                   ├─ 127.0.0.1:8001 ─ veil-forum ─ PostgreSQL (Unix socket)
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
DATABASE_URL=postgres://user@%2Fvar%2Frun%2Fpostgresql/veil_forum_test \
  cargo test --all-targets
cargo clippy --all-targets --all-features
tests/scripts.sh
tests/deploy-scripts.sh
sh tests/backup_upgrade_e2e.sh
DATABASE_URL=postgres://user@%2Fvar%2Frun%2Fpostgresql/veil_forum_test \
  tests/startup-smoke.sh
cargo build --release
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --ignore RUSTSEC-2023-0071
cargo install cargo-deny --version 0.20.2 --locked
cargo deny check
```

`tests/performance-baseline.sh` is separate from the gate because it measures a
running instance rather than a test harness:

```bash
BASE_URL=http://127.0.0.1:8001 REPEATS=25 tests/performance-baseline.sh
```

`cargo audit` and `cargo deny` must both be at least 0.22.2 and 0.20.2. Older
releases cannot parse advisory-database entries that carry a CVSS 4.0 score and
fail before scanning anything.

The audit tools are pinned so a green run is reproducible. `cargo audit` scans
the whole lockfile, which is why it still needs `--ignore RUSTSEC-2023-0071` for
the unused `sqlx-mysql` entry; `cargo deny check` inspects the enabled feature
graph instead and needs no exception. CI uploads both reports as
`target/cargo-audit.txt` and `target/cargo-deny.txt` even when a check fails.

`cargo test --all-targets` automatically compiles and runs Rust integration
targets under `tests/`, including the `*_e2e.rs` suites. The `#[sqlx::test]`
suites require `DATABASE_URL` to point at a PostgreSQL database for which the
current user can create disposable test databases. This command does not run
shell E2E scripts. Each Rust E2E writes a credential-free JSON report under
`target/` on success, error, and panic paths. CI uploads the authentication,
configuration, forum lifecycle, governance, and search reports together with the
backup/upgrade report, the startup smoke report, the sanitized application JSON
log, and both supply-chain audit logs.

`tests/startup-smoke.sh` starts the release binary against a scratch database
and writes `target/startup-smoke-report.json` on both the success and the
failure path. It checks the health endpoint, the redacted startup banner, the
baseline migration, the first-run administrator, SIGTERM shutdown, refusal of a
non-loopback listener, and that a database password never reaches the log in any
connection-string form sqlx accepts. `tests/performance-baseline.sh` writes
`target/performance-baseline-report.json` with per-path mean, minimum, and
maximum latency. Neither report contains a password, cookie, request body, or
connection string, and neither is committed: `/target` is ignored.

The backup/upgrade E2E uses a real PostgreSQL server, a temporary age identity,
and passwordless `sudo -n -u postgres`; it does not rely on sudo inheriting
ordinary shell variables. Every run writes the credential-free report
`target/backup-upgrade-e2e-report.json`, including the exact regeneration
command. Per-phase seed, backup, upgrade, rollback, restore, and service logs
remain under its private temporary directory for the run and are deleted by its
cleanup trap on both success and failure. The same cleanup stops the service
process, drops the temporary database, drops a role it created or restores the
original attributes of a role it narrowed, and removes identity keys, backups,
snapshots, and PID files. CI retains the credential-free JSON reports and the
sanitized application JSON log, but not raw temporary logs or key material.

Published tag assets are verified by CI before the draft release becomes
public. The same command can be rerun against a published tag:

```bash
GH_TOKEN=... RELEASE_TAG=vVERSION RELEASE_REPO=OWNER/REPO sh tests/release_packages_e2e.sh
```

This downloads every asset, verifies checksums, archive paths and ELF target
metadata, and runs a native archive against a temporary PostgreSQL cluster.
Its report is `target/release-packages-e2e-report.json` and sanitized logs are
under `target/release-packages-e2e-logs/`. Failures include missing or
unauthenticated GitHub access, absent or mismatched release assets, corrupt
archives, wrong executable architecture, failed migrations/health/SIGTERM, and
leftover temporary resources.

The optional `external-go-interop` feature requires a separate Go compatibility
project. Set `VEIL_GO_PROJECT` and optionally `VEIL_GO_BIN` before enabling it.

## License

Copyright (C) 2026 veil-forum contributors.

veil-forum is licensed under the GNU Affero General Public License, version 3
only. Network deployments of modified versions must provide corresponding
source to remote users as required by AGPL section 13.
