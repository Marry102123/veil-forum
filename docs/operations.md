# Operations

## Installation

### Scripted install (recommended)

From a release archive or a source checkout:

```bash
sudo ./scripts/install.sh --dry-run
sudo ./scripts/install.sh --admin-password-file /root/veil-adminpw
```

The installer is idempotent: re-running it repairs a half-finished install.
It creates the `veil-forum` system user, the PostgreSQL role and database
with peer authentication (no password stored anywhere), installs the binary
to `/usr/local/bin` with `static/` beside it, installs the systemd (or
OpenRC) unit, seeds the first administrator, and verifies `/healthz`.

Useful options (`scripts/install.sh --help` lists all of them):

| Option | Meaning |
|---|---|
| `--dry-run` | Print every step without changing anything |
| `--admin-password-file FILE` | 12-128 character first admin password (`VEIL_ADMIN_PASSWORD` also works); only needed when the database is empty |
| `--prefix DIR` | Install prefix (default `/usr/local`) |
| `--user/--db-user/--db-name/--db-socket` | Service user, database role, name, socket directory |
| `--port PORT` / `--addr HOST:PORT` | Listener (default `127.0.0.1:8001`; non-loopback needs `--allow-nonloopback`) |
| `--binary PATH` / `--static DIR` | Install from somewhere other than the default build/archive layout |
| `--no-service` | Install files and seed only; skip the service unit |
| `--service-manager systemd\|openrc\|none` | Override auto-detection |

User, role and database names are limited to letters, digits, underscore,
dash and dot (and may not start with a dash or dot), and paths may not
contain quoting or shell metacharacters, so installer inputs can never escape
the `su`/`psql` command lines the scripts build. `upgrade.sh` and
`rollback.sh` enforce the same rules.

Only the binary and `static/` are required at runtime. Templates, locales
and migrations are embedded in the binary, so the release `locales/` and
`migrations/` directories are reference material, not install inputs.

### Manual installation

If you prefer to do each step yourself:

```bash
sudo apt-get install -y postgresql          # provides PostgreSQL 15+ and pg_trgm
sudo adduser --system --group --home /var/lib/veil-forum veil-forum
sudo -u postgres createuser --no-createdb --no-superuser veil-forum
sudo -u postgres createdb -O veil-forum veil_forum
sudo install -d -m 700 -o veil-forum -g veil-forum /var/lib/veil-forum
```

Copy the binary to `/usr/local/bin/veil-forum` and `static/` to
`/usr/local/static` (the unit resolves `../static` relative to the binary).
Install `deploy/veil-forum.service` as
`/etc/systemd/system/veil-forum.service` (or `deploy/veil-forum.openrc` as
`/etc/init.d/veil-forum`), adjusting the `--addr` and `--database-url` in
`ExecStart` if yours differ, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now veil-forum
curl --fail http://127.0.0.1:8001/healthz
```

For the first start only, supply the administrator password through the
service manager environment (`VEIL_ADMIN_PASSWORD`, 12-128 characters), then
remove it and restart. The database role and the service user must share a
name, because the default socket connection relies on peer authentication.

Recommended hardening in `postgresql.conf`:

```conf
listen_addresses = ''          # no TCP listener at all
password_encryption = scram-sha-256
```

With `listen_addresses = ''` only the Unix socket remains. Keep the `local`
peer rule in `pg_hba.conf` and leave the `host` lines unused. The schema
requires the `pg_trgm` extension (usually `postgresql-contrib`); the database
owner creates it automatically at startup, so no superuser is needed at
runtime.

## Backup and restore

While the service is running:

```bash
sudo scripts/db-maintenance.sh check
sudo scripts/db-maintenance.sh backup postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum \
                                    /srv/veil-forum-backups
```

Both arguments default to the local socket connection string and
`/srv/veil-forum-backups`; `DATABASE_URL` is honoured when the first argument
is omitted. `check` verifies connectivity and that the schema is present,
then runs `pg_amcheck` when installed. `backup` writes a custom-format
archive with `pg_dump --format=custom`, verifies it with `pg_restore
--list`, renames it into place atomically, keeps the 30 most recent archives,
and sets mode 600 in a 0700 directory. It requires `pg_dump` and
`pg_restore`. The older `scripts/backup.sh` remains available for
compatibility and takes the same arguments.

Retention is `VEIL_BACKUP_RETAIN` (default 30). A value of `0`, an empty
value, or anything that is not a number is refused with a warning and falls
back to 30, because a retention of zero would delete the archive the run just
wrote.

Both scripts pass the connection string to `pg_dump`, `pg_amcheck` and `psql`
on the command line, where other local users can read it from the process
table. The default Unix-socket string carries no password; for a TCP
connection prefer `PGPASSWORD` or a mode 600 `~/.pgpass` over an inline
password in the DSN, and run maintenance as a user nobody else shares.

Restore into an empty database to verify a backup:

```bash
sudo -u postgres createdb -O veil-forum veil_forum_restore
pg_restore --dbname veil_forum_restore --no-owner --exit-on-error forum-<stamp>.dump
```

Backups contain sessions, password hashes, and deleted content, so treat them
as sensitive data. Encrypt them before moving them off-host. Never include
Onion private keys, I2P Destination keys, passwords, or service environment
files in a backup.

## Upgrade

From a verified release archive:

```bash
sha256sum -c veil-forum-*-checksums.txt
sudo scripts/upgrade.sh veil-forum-*.tar.gz --checksums veil-forum-*-checksums.txt
```

`upgrade.sh` verifies the checksum, **backs up the database first**,
snapshots the running binary and `static/` to a versioned directory under
`/var/lib/veil-forum/rollback/`, stops the service, installs the new files,
starts it, and waits for `/healthz`. If the health check fails it **restores
the snapshot automatically** and reports the pre-upgrade backup. The unit file
is left untouched.

Manual fallback (the same steps the script automates):

1. Read the release notes and make an encrypted backup. Record its filename
   and keep the currently installed archive or binary.
2. Download the archive and checksum file outside the repository, then verify
   them before extracting: `sha256sum -c veil-forum-*-checksums.txt`.
3. Stop the service. Install the new binary together with its accompanying
   `static/` directory. Keep the previous complete release directory or
   archive until validation succeeds.
4. Start the service and inspect `journalctl -u veil-forum`.
5. Verify `/healthz` says `ok`, plus the login page, an existing session, and
   a read-only thread request.

Migrations are embedded in the binary and applied during startup under a
PostgreSQL advisory lock, so two instances starting at once cannot interleave
schema changes. Each migration runs in a transaction, which means PostgreSQL
rolls it back completely if the process is interrupted. Do not run tests
against the production database.

## Rollback

If an upgrade misbehaves after the fact:

```bash
sudo scripts/rollback.sh
```

This restores the newest snapshot's binary and `static/` and restarts the
service. The database is **not** touched, which is correct when the failed
release applied no migration. List or pick a snapshot explicitly with
`--snapshot DIR`.

When the failed release **did** apply a migration, an older binary cannot
read the newer schema. Restore the pre-upgrade backup into a fresh database
first:

```bash
sudo scripts/rollback.sh --restore-db /srv/veil-forum-backups/forum-<stamp>.dump
```

`--restore-db` drops the configured database and recreates it from the dump,
so it asks for confirmation (pass `--yes` only from automation you trust).
The snapshot records which backup was taken before the upgrade (`DB_DUMP`
file next to `VERSION` in the snapshot directory).

Manual fallback: after stopping the service and preserving the failed
release's journal output, restore the prior binary **and** its matching
static assets, then start the service and repeat the smoke checks. If the
failed startup applied a migration, restore the pre-upgrade dump into a fresh
database before starting the older binary, and point it at that database.

## Service management

The unit declares `Requires=postgresql.service`, so the database starts
first. The application retries the initial connection, which covers the
remaining startup window. It limits restart bursts to five failures in five
minutes, preventing a persistent failure from spinning indefinitely. After
correcting the cause, inspect the journal and run
`sudo systemctl reset-failed veil-forum` before starting it again.

Validate the installed unit before enabling it and inspect the hardening
score:

```bash
sudo systemd-analyze verify /etc/systemd/system/veil-forum.service
systemd-analyze security veil-forum.service
```

`ProtectProc=invisible` and `ProcSubset=pid` need systemd 247 or newer. On an
older systemd, remove only those two directives as noted in the unit
comments, then rerun both commands. If `SystemCallFilter=@system-service`
causes a startup failure on a vendor-specific systemd/kernel combination,
remove that single filter and retain the other restrictions. Confirm the
service still starts before deployment.

Set `VEIL_ADMIN_PASSWORD` only for the first start using a protected service
manager mechanism, then remove it and restart the service.

## Two-step verification (TOTP)

Members can enable a second factor from `/account`: the page shows a QR code
(inline SVG, so no script and no external request) and the base32 secret for
manual entry. Enrolment only becomes active after the member proves they can
read a code from it.

Administrators configure the feature in **System settings**:

- **Offer TOTP to members** turns the whole feature on or off.
- **Require it from** is `nobody (optional)`, `staff only`, or `everyone`. A
  required policy never blocks signing in: a member without a second factor is
  simply shown a page pointing at their account page until they enrol.

Recovery codes are issued once at enrolment and can be reissued from the
account page after confirming the password. They are stored as SHA-256 hashes
and each one works once. There is no email address, so recovery codes and an
owner-side reset are the only ways to recover an account.

Operational notes:

- The **server clock** decides whether a code is accepted, with one 30 second
  step of tolerance. Keep the host synchronised; drift beyond that rejects valid
  codes.
- Users need a roughly correct clock on their own device too.
- A code is accepted only once. Signing in twice inside the same 30 second
  window is refused with "that code was already used"; the next code works.
- TOTP secrets are stored as bearer credentials, like every mainstream forum.
  A database dump is enough to generate codes, so keep backups encrypted and
  remove the factor from accounts you no longer trust.
- Disabling the feature site-wide leaves existing secrets in place but stops
  asking for codes; they are used again if you turn it back on.

## Governance roles and recovery

The governance migration assigns an initial `owner` role to every administrator.
An `owner` can manage site settings, global administrators, audit records, and
sessions; `admin` manages global users and content; `moderator` is restricted to
boards explicitly assigned to it. Keep at least two separately protected owner
accounts when practical. The application refuses changes that would leave no
owner or allow a lower role to alter an equal or higher role.

Use the administration audit view after granting roles, assigning moderators,
moderating reports, restoring content, or revoking sessions. Audit records must
never include client IP addresses, User-Agent strings, or cookie values. Deleted
content enters the recovery queue first. Only an owner may permanently purge it;
make and verify an encrypted database backup before doing so.

## Upgrading from the SQLite backend

Releases up to `0.1.0-alpha.17` stored data in a SQLite file. `0.1.0-alpha.18`
shipped `veil-forum-import` for that one migration and the importer has since
been removed, so an installation that is still on SQLite has to import once with
the alpha.18 archive:

```bash
# 1. Stop the old service and keep the file untouched.
sudo systemctl stop veil-forum
sudo -u postgres createdb -O veil-forum veil_forum

# 2. Import with the alpha.18 binary (still in the v0.1.0-alpha.18 release).
sudo -u veil-forum ./veil-forum-import \
  --sqlite /var/lib/veil-forum/forum.db \
  --database-url postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum

# 3. Install the current release and start it.
sudo systemctl start veil-forum
```

The importer opened the SQLite file read-only, copied every table with its
original identifiers in foreign-key order, converted all historical timestamp
formats to `TIMESTAMPTZ`, restored owner roles for administrator accounts,
advanced the identity sequences, and printed a per-table row-count
reconciliation that had to match. The whole import ran in one transaction, so a
malformed legacy row rolled back rather than leaving a half-filled database.

## Troubleshooting

- **Startup fails:** the error identifies the PostgreSQL target,
  administrator initialization, or listener address. Check that the database
  is running, that the role can log in over the socket, that the first-run
  `VEIL_ADMIN_PASSWORD` is 12-128 characters, and that the configured
  loopback port is not already in use. Connection errors never include the
  password; the target is printed with the password replaced by `***`.
- **`/healthz` never answers:** the process is up but the database is not.
  Inspect `journalctl -u veil-forum` and run
  `scripts/db-maintenance.sh check` with the same connection string the unit
  uses.
- **Checksum mismatch on upgrade:** do not install the archive. Re-download
  both files and verify again; `upgrade.sh` refuses to proceed.
- **Upgrade failed and rolled back:** the previous release is running again.
  Read the journal from the failed start, fix the cause (often the database
  or a port conflict), restore service with
  `sudo systemctl reset-failed veil-forum`, and re-run `upgrade.sh`.
- **Which release is running:** `veil-forum --version`, or the version shown
  in the administration workspace. Rollback snapshots live in
  `/var/lib/veil-forum/rollback/` with a `VERSION` file each.
