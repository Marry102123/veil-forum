# Anonymous deployment security checklist

Run these checks before exposing a Tor Onion Service or I2P Destination:

1. The Rust process listens on `127.0.0.1` and the gateway is the only
   network-facing process.
2. The service user cannot read Onion or I2P private keys, and Tor/I2P cannot
   read the forum database unless the deployment explicitly requires it.
3. No `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, User-Agent, or Cookie value
   is written to logs.
4. Browser network inspection shows no DNS, clearnet, CDN, font, image, or
   analytics request.
5. Direct POST requests without the rendered CSRF token return `403`.
6. A banned account's old session cannot read or modify protected content.
7. Database, WAL, SHM, session and audit files are owned by the service user
   and are not group/world-readable.
8. `VEIL_ADMIN_PASSWORD` is removed from the service environment after first
   initialization and never appears in process logs.
9. `cargo test`, `cargo clippy --all-targets --all-features`, and
   `cargo audit` pass in the build environment.

The application does not protect against a global traffic observer. This
checklist is an application and deployment hardening baseline, not a claim of
absolute anonymity.
