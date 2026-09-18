# Anonymous deployment security checklist

Run these checks before exposing a Tor Onion Service or I2P Destination:

1. The Rust process listens on `127.0.0.1` and the gateway is the only
   network-facing process.
2. The service user cannot read Onion or I2P private keys, and Tor/I2P cannot
   read the forum database unless the deployment explicitly requires it.
   PostgreSQL is reached over the local Unix socket with peer authentication;
   the `veil-forum` role has no superuser or `CREATEDB` privilege and only owns
   its own database.
3. No `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, User-Agent, or Cookie value
   is written to logs.
4. Browser network inspection shows no DNS, clearnet, CDN, font, image, or
   analytics request.
5. Direct POST requests without the rendered CSRF token return `403`.
6. A banned account's old session cannot read or modify protected content.
7. `listen_addresses` in `postgresql.conf` is empty, so the database has no
   network listener, and backup archives are mode 600 and encrypted before they
   leave the host.
8. `VEIL_ADMIN_PASSWORD` is removed from the service environment after first
   initialization and never appears in process logs.
9. If TOTP is offered, the operator understands that shared secrets are bearer
   credentials: database backups must be encrypted, and the host clock must stay
   synchronised for codes to validate.
10. `cargo test`, `cargo clippy --all-targets --all-features`, and
   `cargo audit` pass in the build environment.
11. A second-factor policy is a redirect, not a wall: it points members without a
   factor at their account page but never blocks signing in, and it is enforced
   with the same session parser the handlers use (covered by
   `crafted_session_cookie_cannot_bypass_the_policy_gate`).
12. Enrolling or disabling a second factor costs the account password and revokes
   the account's other sessions, so a stolen session cannot change how the
   account authenticates.
13. `scripts/db-maintenance.sh` writes into a 0700 directory, the dump files are
   mode 600, and the connection string used for `pg_dump`/`psql` carries no
   password unless `PGPASSWORD` or `~/.pgpass` supplies it (the process table is
   world-readable).
14. The migration import runs with `--dry-run` first, and the target database is
   backed up before `--force`, because `--force` replaces existing rows.

The application does not protect against a global traffic observer. This
checklist is an application and deployment hardening baseline, not a claim of
absolute anonymity.
