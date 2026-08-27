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
The gateway host must not add `X-Forwarded-For` or `Forwarded` headers that
are later trusted by the application. Block direct egress from the service
user so the forum cannot bypass Tor or I2P.

For first initialization, set `VEIL_ADMIN_PASSWORD` only in the service
manager environment and remove it after the first successful startup. The
value must be 12-128 characters and must never be logged.
