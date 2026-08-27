# veil-forum

An experimental, self-hosted forum for Tor Onion Service and I2P deployments.

**Alpha software. Licensed under [AGPL-3.0-only](LICENSE).**

veil-forum is written in Rust with Axum and SQLite. It uses server-rendered
HTML and keeps its HTTP listener on loopback by default, so a local Tor Onion
Service or I2P HTTP tunnel can be the only network-facing component.

This project is for review and experimental deployment. It is not production
ready and does not provide absolute anonymity. It cannot protect against host
compromise, malicious administrators, endpoint fingerprinting, or global
traffic analysis.

## Features

- Boards, threads, nested replies, and full-text search
- Per-board anonymous posting controls
- Markdown with sanitized HTML and no remote images
- Open, invite-only, and closed registration modes
- Invite-only registration by default on new installations
- Argon2id passwords, expiring sessions, CSRF and Origin checks
- Proof of work for registration, login, and posting
- Administrator controls for boards, invites, users, moderation, and notices
- Administrator audit log
- SQLite persistence with migrations and restrictive data-directory permissions
- Core posting and administration workflows work without JavaScript

## Quick Start

### From a release archive

Download the Linux x86_64 archive and its checksum from the
[releases page](https://github.com/Marry102123/veil-forum/releases), then:

```bash
sha256sum -c veil-forum-v*-checksums.txt
tar -xzf veil-forum-v*-x86_64-unknown-linux-gnu.tar.gz
cd veil-forum-v*
```

### From source

Requirements: Rust 1.88 or newer and SQLite. The repository pins the CI and
local development toolchain through `rust-toolchain.toml`.

```bash
cargo build --release
```

### First run

Set a unique 12-128 character administrator password only for the first start:

```bash
VEIL_ADMIN_PASSWORD='replace-with-a-long-random-password' \
  ./target/release/veil-forum \
  --addr 127.0.0.1:8001 \
  --data ./data/forum.db
```

For a release archive, run `./veil-forum` instead. Open
`http://127.0.0.1:8001` locally. Remove `VEIL_ADMIN_PASSWORD` from the service
environment after initialization.

The server refuses non-loopback listeners unless `VEIL_ALLOW_NONLOOPBACK=1` is
explicitly set. Keep the default listener and expose it only through a local
Tor or I2P gateway.

## Architecture

```text
Tor Onion Service ─┐
                   ├── 127.0.0.1:8001 ── veil-forum ── SQLite
I2P HTTP Server ───┘
```

## Security and Privacy

The application does not require email addresses, client IP addresses, third
party authentication, analytics, CDNs, remote fonts, or external images. It
uses restrictive response headers, sanitized Markdown, CSRF protection, and
absolute plus idle session expiry.

Deployment remains the operator's responsibility. Protect the database,
`-wal`, and `-shm` files, gateway private keys, backups, operating system, and
service egress. Anonymous display names are not a guarantee of anonymity.

## Documentation

- [Onion and I2P deployment](docs/onion-i2p-deployment.md)
- [Operations: backup, recovery, upgrade, and systemd](docs/operations.md)
- [Anonymous deployment security checklist](docs/security-checklist.md)
- [Security reporting policy](SECURITY.md)
- [Changelog and known dependency limitations](CHANGELOG.md)

## Development

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets
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
