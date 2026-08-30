# Operations

## Backup

Use the included SQLite maintenance script while the service is running:

```bash
sudo scripts/db-maintenance.sh check /var/lib/veil-forum
sudo scripts/db-maintenance.sh backup /var/lib/veil-forum /srv/veil-forum-backups
```

`check` runs SQLite `PRAGMA integrity_check` and exits non-zero on corruption.
`backup` uses SQLite's online `.backup` command, verifies the resulting file
with `integrity_check`, atomically renames it into place, keeps the 30 most
recent backups, and sets mode 600 on backup files. It requires `sqlite3` and
never falls back to copying a live WAL database. The older `scripts/backup.sh`
remains available for compatibility.

Protect the database, `-wal`, and `-shm` files as sensitive data because they
can contain sessions and deleted content.

Encrypt backups before moving them off-host. Never include Onion private keys,
I2P Destination keys, passwords, or service environment files in a backup.

## Upgrade

1. Read the release notes and make an encrypted backup. Record its filename and
   retain the currently installed archive or binary.
2. Download the archive and checksum file outside the repository, then verify
   them before extracting: `sha256sum -c veil-forum-*-checksums.txt`.
3. Stop the service. Install the new binary and its accompanying `static/`,
   `locales/`, and `migrations/` directories together. Keep the previous
   complete release directory or archive until validation succeeds.
4. Start the service and inspect `journalctl -u veil-forum`.
5. Verify the login page, an existing session, and a read-only thread request.

Migrations are applied during startup. Do not interrupt a migration and do not
run tests against the production database.

### Rollback

Only roll back after stopping the service and preserving the failed release's
journal output. Restore the prior binary **and** its matching static assets,
locales, and migrations, then start the service and repeat the smoke checks.
If the failed startup applied a migration, do not assume an older binary can
read the newer database schema: restore the encrypted pre-upgrade database
backup before starting that older binary. Confirm the restored backup has mode
`600` and is owned by `veil-forum` before starting the service.

`scripts/release.sh` builds the release binary and produces a tar archive and
sha256 checksums in `dist/`, matching the files published for each release.

If startup fails, the error identifies the database path, administrator
initialization, or listener address. Check that the data directory is writable,
that the first-run `VEIL_ADMIN_PASSWORD` is 12-128 characters, and that the
configured loopback port is not already in use.

## systemd

Create a dedicated user and data directory, install `deploy/veil-forum.service`
as `/etc/systemd/system/veil-forum.service`, then run:

```bash
sudo install -d -o veil-forum -g veil-forum -m 700 /var/lib/veil-forum
sudo systemctl daemon-reload
sudo systemctl enable --now veil-forum
sudo systemctl status veil-forum
sudo journalctl -u veil-forum --since '-10 min'
```

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
