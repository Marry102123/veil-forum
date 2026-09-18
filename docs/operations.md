# Operations

## PostgreSQL setup

veil-forum stores everything in PostgreSQL and applies its schema automatically
at startup. A local server reached over the Unix socket is the recommended
deployment: PostgreSQL then never listens on the network and no database
password exists in configuration, environment files, or the unit.

```bash
sudo apt-get install -y postgresql          # provides PostgreSQL 15+ and pg_trgm
sudo -u postgres createuser --no-createdb --no-superuser veil-forum
sudo -u postgres createdb -O veil-forum veil_forum
```

The service user and the database role must share a name, because the default
connection string `postgres:///veil_forum?host=/var/run/postgresql` relies on
peer authentication.

Recommended hardening in `postgresql.conf`:

```conf
listen_addresses = ''          # no TCP listener at all
password_encryption = scram-sha-256
```

With `listen_addresses = ''` only the Unix socket remains, which keeps the
deployment loopback-only in the same sense as the application listener. Keep
`pg_hba.conf` entries for `local` peer authentication and leave the `host`
lines unused.

The schema requires the `pg_trgm` extension (part of PostgreSQL's contrib
modules, usually `postgresql-contrib`). The database owner can create it, so no
superuser is needed at runtime.

## Backup

Use the included maintenance script while the service is running:

```bash
sudo scripts/db-maintenance.sh check  postgres:///veil_forum?host=/var/run/postgresql
sudo scripts/db-maintenance.sh backup postgres:///veil_forum?host=/var/run/postgresql \
                                    /srv/veil-forum-backups
```

Both arguments default to the local socket connection string and
`/srv/veil-forum-backups`, and `DATABASE_URL` is honoured when the first
argument is omitted.

`check` verifies connectivity and that the schema is present, then runs
`pg_amcheck` when it is installed. `backup` writes a custom-format archive with
`pg_dump --format=custom`, verifies it by listing it with `pg_restore --list`,
renames it into place atomically, keeps the 30 most recent archives, and sets
mode 600 in a 0700 directory. It requires `pg_dump` and `pg_restore`. The older
`scripts/backup.sh` remains available for compatibility and takes the same
arguments.

Retention is `VEIL_BACKUP_RETAIN` (default 30). A value of `0`, an empty value,
or anything that is not a number is refused with a warning and falls back to 30,
because a retention of zero would delete the archive the run just wrote.

Both scripts pass the connection string to `pg_dump`, `pg_amcheck` and `psql` on
the command line, where other local users can read it from the process table.
The default Unix-socket string carries no password; for a TCP connection prefer
`PGPASSWORD` or a mode 600 `~/.pgpass` over an inline password in the DSN, and
run maintenance as a user nobody else shares.

Restore into an empty database to verify a backup:

```bash
sudo -u postgres createdb -O veil-forum veil_forum_restore
pg_restore --dbname veil_forum_restore --no-owner --exit-on-error forum-<stamp>.dump
```

Backups contain sessions, password hashes, and deleted content, so treat them as
sensitive data. Encrypt them before moving them off-host. Never include Onion
private keys, I2P Destination keys, passwords, or service environment files in a
backup.

## Upgrade

1. Read the release notes and make an encrypted backup. Record its filename and
   retain the currently installed archive or binary.
2. Download the archive and checksum file outside the repository, then verify
   them before extracting: `sha256sum -c veil-forum-*-checksums.txt`.
3. Stop the service. Install the new binary together with its accompanying
   `static/` and `locales/` directories. Keep the previous complete release
   directory or archive until validation succeeds.
4. Start the service and inspect `journalctl -u veil-forum`.
5. Verify the login page, an existing session, and a read-only thread request.

Migrations are embedded in the binary and applied during startup under a
PostgreSQL advisory lock, so two instances starting at once cannot interleave
schema changes. Each migration runs in a transaction, which means PostgreSQL
rolls it back completely if the process is interrupted. Do not run tests against
the production database.## Upgrading from the SQLite backend

Releases before `0.1.0-alpha.18` stored data in a SQLite file. Those
installations must be imported once:

```bash
# 1. Stop the old service and keep the file untouched.
sudo systemctl stop veil-forum
sudo -u postgres createdb -O veil-forum veil_forum

# 2. Copy the SQLite file somewhere readable and import it.
sudo -u veil-forum /usr/local/bin/veil-forum-import \
  --sqlite /var/lib/veil-forum/forum.db \
  --database-url postgres:///veil_forum?host=/var/run/postgresql

# 3. Install the new release and start it.
sudo systemctl start veil-forum
```

The importer opens the SQLite file read-only, copies every table with its
original identifiers in foreign-key order, converts all historical timestamp
formats to `TIMESTAMPTZ`, restores owner roles for administrator accounts,
advances the identity sequences, and prints a per-table row-count reconciliation
that must match. It refuses to write into a database that already holds forum
data unless `--force` is passed, which deletes the existing rows first.
`--dry-run` reports what would be copied without writing anything.
Session rows are skipped by default; add `--include-sessions` to carry active
logins across.

Keep the SQLite file until the new deployment has been verified, then archive it
somewhere encrypted or delete it: it contains password hashes and deleted
content.

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

### Rollback

Only roll back after stopping the service and preserving the failed release's
journal output. Restore the prior binary **and** its matching static assets and
locales, then start the service and repeat the smoke checks. If the failed
startup applied a migration, do not assume an older binary can read the newer
schema: restore the pre-upgrade database dump into a fresh database before
starting that older binary, and point it at that database.

`scripts/release.sh` builds the release binary and produces a tar archive and
sha256 checksums in `dist/`, matching the files published for each release.

If startup fails, the error identifies the PostgreSQL target, administrator
initialization, or listener address. Check that the database is running, that
the role can log in over the socket, that the first-run `VEIL_ADMIN_PASSWORD` is
12-128 characters, and that the configured loopback port is not already in use.
Connection errors never include the password; the target is printed with the
password replaced by `***`.

## systemd

Create a dedicated user, install `deploy/veil-forum.service` as
`/etc/systemd/system/veil-forum.service`, then run:

```bash
sudo adduser --system --group --home /var/lib/veil-forum veil-forum
sudo -u postgres createuser --no-createdb --no-superuser veil-forum
sudo -u postgres createdb -O veil-forum veil_forum
sudo systemctl daemon-reload
sudo systemctl enable --now veil-forum
sudo systemctl status veil-forum
sudo journalctl -u veil-forum --since '-10 min'
```

The unit declares `Requires=postgresql.service`, so the database starts first.
The application retries the initial connection for five seconds, which covers
the remaining startup window.

Validate the installed unit before enabling it and inspect the hardening score:

```bash
sudo systemd-analyze verify /etc/systemd/system/veil-forum.service
systemd-analyze security veil-forum.service
```

`ProtectProc=invisible` and `ProcSubset=pid` need systemd 247 or newer. On an
older systemd, remove only those two directives as noted in the unit comments,
then rerun both commands. If `SystemCallFilter=@system-service` causes a
startup failure on a vendor-specific systemd/kernel combination, remove that
single filter and retain the other restrictions. Confirm the service still
starts before deployment.

Set `VEIL_ADMIN_PASSWORD` only for the first start using a protected service
manager mechanism, then remove it and restart the service.

The unit limits restart bursts to five failures in five minutes, preventing a
persistent failure from spinning indefinitely. After correcting the cause,
inspect the journal and run `sudo systemctl reset-failed veil-forum` before
starting it again.
