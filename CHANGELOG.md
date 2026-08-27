# Changelog

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
