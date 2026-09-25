# Onion / I2P deployment

veil-forum is intended to sit behind a local Tor Onion Service or I2P HTTP
server. Keep the Rust listener on loopback and expose only the gateway.

## Tor Onion Service

Run the forum as a dedicated unprivileged user and use a private service
directory readable only by that user and Tor:

```text
HiddenServiceDir /var/lib/tor/veil-forum/
HiddenServicePort 80 127.0.0.1:8001
```

Do not publish the Rust port, enable a Tor control port, or copy
`hs_ed25519_secret_key` into the repository or backups without encryption.
Use a separate Onion identity for administration.

## I2P

Create a dedicated HTTP Server tunnel whose local target is
`127.0.0.1:8001`. Keep the Destination private key in the I2P data directory
with mode `0600`. Do not put the Destination, router metadata, or tunnel
credentials in application configuration or logs.

## Application

The process refuses non-loopback addresses unless `VEIL_ALLOW_NONLOOPBACK=1`
is explicitly set. Prefer the default loopback listener and a local gateway.
A loopback listener defaults to non-`Secure` session cookies because Tor Onion
Service and I2P HTTP tunnels normally present HTTP to the browser. A
non-loopback listener defaults to `Secure` session cookies and refuses an
attempt to disable them. `VEIL_SESSION_COOKIE_SECURE=1` can also force the
attribute for an HTTPS browser-facing deployment. Do not expose a cleartext
browser-facing listener.

The gateway host must not add `X-Forwarded-For` or `Forwarded` headers that
are later trusted by the application. Block direct egress from the service
user so the forum cannot bypass Tor or I2P.

PostgreSQL runs on the same host and is reached over the local Unix socket with
peer authentication. Set `listen_addresses = ''` in `postgresql.conf` so the
database has no network listener at all, and let `pg_hba.conf` keep the `local`
peer rule. The service user is then also the database role, so no password needs
to be stored or forwarded. If the database is on another host, the connection
must stay inside the Tor or I2P boundary and the URL must be supplied through
`--database-url` or `DATABASE_URL`; passwords in a connection string are printed
as `***` in every error message and startup banner.

For first initialization, set `VEIL_ADMIN_PASSWORD` only in the service
manager environment and remove it after the first successful startup. The
value must be 15-128 characters, pass the application's strength check, and
must never be logged.
