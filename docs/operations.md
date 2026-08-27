# Operations

## Backup

Stop the service before a simple file backup, or use SQLite backup tooling
while the service is running. Protect the database, `-wal`, and `-shm` files
as sensitive data because they can contain sessions and deleted content.

```bash
sudo systemctl stop veil-forum
sudo install -d -m 700 /srv/veil-forum-backups
sudo cp --preserve=mode /var/lib/veil-forum/forum.db /srv/veil-forum-backups/forum.db
sudo chmod 600 /srv/veil-forum-backups/forum.db
sudo systemctl start veil-forum
```

Encrypt backups before moving them off-host. Never include Onion private keys,
I2P Destination keys, passwords, or service environment files in a backup.

## Upgrade

1. Read the release notes and make an encrypted backup.
2. Stop the service.
3. Replace the binary and keep the previous binary for rollback.
4. Start the service and inspect `journalctl -u veil-forum`.
5. Verify the login page, an existing session, and a read-only thread request.

Migrations are applied during startup. Do not interrupt a migration and do not
run tests against the production database.

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
sudo journalctl -u veil-forum
```

Set `VEIL_ADMIN_PASSWORD` only for the first start using a protected service
manager mechanism, then remove it and restart the service.
