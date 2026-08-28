# Changelog

## 0.1.0-alpha.4

- Fix tagged CI release builds for the current inline-template layout and
  publish downloadable Linux x86_64 GNU release assets.

## 0.1.0-alpha.3

- Remove login Proof-of-Work and its configuration, state, and stale locale
  keys; registration and posting PoW are unchanged.
- Serialize SQLite through a single connection with WAL, foreign keys, and a
  busy timeout, and move reply-count updates into the same transactions as
  post creation and deletion.
- Remove the unused PoW challenge API rate-limit state and dead search, theme,
  and challenge handlers from the previous cleanup.
- Remove the unused Go-era `templates/` directory; the Rust binary renders all
  pages server-side.
- Add `scripts/backup.sh` for consistent online SQLite backups and
  `scripts/release.sh` for reproducible release archives with sha256 checksums.

## 0.1.0-alpha.2

- Clarify browser Proof-of-Work (PoW) anti-abuse checks in English, Chinese,
  and Russian user interfaces.
- Bound PoW form inputs and challenge issuance to reduce resource abuse.
- Make `/healthz` verify SQLite readiness and prevent stale static assets after
  upgrades.
- Pin the development toolchain to stable Rust and document the Rust 1.88 MSRV.
- Add PoW and Origin validation tests and improve startup error diagnostics.

## 0.1.0-alpha.1

Initial public Alpha release.

- Server-rendered forum with boards, threads, replies, search, moderation and
  English, Chinese and Russian locale resources.
- Tor Onion Service and I2P HTTP Server deployment model.
- CSRF, Origin/Host checks, Argon2id passwords, expiring sessions and SQLite
  permission hardening.
- Experimental privacy design. This release is not production-ready and does
  not provide absolute anonymity.

Known limitations and dependency advisories are documented in `README.md` and
`docs/`.

The current dependency audit has no fixed upgrade for the `rsa` Marvin timing
advisory and reports unmaintained transitive `bincode` and `yaml-rust` through
the Markdown syntax highlighting stack. Do not treat this Alpha release as a
clean security audit.
