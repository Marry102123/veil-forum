# Changelog

## 0.1.0-alpha.15

- Add process-local privacy-preserving rate limits using `governor`: global
  limits for authentication and PoW issuance, plus keyed posting limits derived
  from a one-way, per-process HMAC of a session ID. The application neither
  records IP addresses nor persists client identifiers for this feature.
- Consolidate session cookie parsing through `axum-extra`, keep the CSRF/Origin
  gate on every mutating form route, and retain the 64 KiB form-body limit.
- Further harden the systemd unit and document `systemd-analyze verify` and
  `systemd-analyze security` compatibility checks.
- Pin GitHub Actions to immutable commits, add weekly Dependabot updates and
  `cargo-deny` supply-chain policy checks.
- Move layout sidebar fragments into embedded Tera partials, reducing manual
  HTML construction while preserving automatic escaping.
- Add a safe SQLite integrity and online-backup maintenance script with
  validated backups and bounded retention.

## 0.1.0-alpha.14

- Replace hand-built server HTML with embedded Tera templates. Templates are
  compiled into the binary, while page handlers pass structured values with
  automatic HTML escaping by default.
- Restore proof of work for login. JavaScript pages calculate it automatically;
  no-JavaScript pages provide a copyable, standard-library Python fallback for
  registration, login, new threads, and replies.
- Add regression, HTTP contract, fuzz-input, migration, Markdown-sanitization,
  and release-archive verification coverage. Harden migration bookkeeping and
  the systemd service unit.
- Keep the experimental privacy posture: the application does not log IP
  addresses, usernames, or session identifiers by default. This remains an
  Alpha release and does not claim absolute anonymity or security.

## 0.1.0-alpha.13

- Fix the PoW challenge API and switch proof of work verification to SHA-256.
- Make theme switching work with JavaScript disabled, including URL fallback.
- Improve Chinese search with an idempotent FTS5 trigram index and safe queries.
- Remove the obsolete Go listener message and harden PoW replay handling.

## 0.1.0-alpha.12

- Build the PowerPC64LE GNU release target with Ubuntu's GCC cross-toolchain.

## 0.1.0-alpha.11

- Link the GCC runtime explicitly for the PowerPC64LE GNU release target.

## 0.1.0-alpha.10

- Use Zig and cargo-zigbuild for reproducible cross-compilation of all listed
  Linux release targets.

## 0.1.0-alpha.9

- Fix cross-target release builds by using the complete `cross` toolchain for
  every Linux target.

## 0.1.0-alpha.8

- Expand the single-release Linux matrix to x86_64, aarch64, armv7, riscv64,
  i686, powerpc64le, and s390x musl/GNU targets.

## 0.1.0-alpha.7

- Fix the multi-architecture release aggregation job and publish both static
  musl archives in one GitHub Release.

## 0.1.0-alpha.6

- Publish x86_64 and aarch64 static musl archives in one GitHub Release.
- Add an OpenRC service template for non-systemd Linux distributions.
- Document architecture-specific release archives and static asset installation.

## 0.1.0-alpha.5

- Publish a statically linked Linux x86_64 musl release for compatibility with
  older Debian systems.

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
