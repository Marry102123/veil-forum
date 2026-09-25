# Changelog

## 0.1.0-alpha.20

**Security release.** This release hardens sessions, credentials, backups, and
the release pipeline. Existing password hashes stay valid, but a database that
has already run `0.1.0-alpha.19` will apply two new migrations on first start.

### Sessions and identity

- Session cookies are now stored only as a digest
  (`migrations/0003_session_security.sql`). A leaked database row therefore no
  longer yields a usable session token, and the absolute and idle expiry bounds
  are enforced on every authenticated request.
- Session cookies are issued with `Secure`, `HttpOnly`, and `SameSite=Strict`
  whenever secure transport is enabled, and are rejected over an insecure
  origin.
- `threads.author_id` is now nullable and anonymous threads store `NULL`
  (`migrations/0004_anonymous_identity.sql`). The migration also clears the
  author on previously created anonymous threads, matched by their first post,
  so an anonymous board cannot attribute a thread to whoever happened to start
  it. Named threads and replies keep their author.

### Credentials and input handling

- Password policy is now uniform across registration, self-service change, and
  administrator change: 15-128 characters with a `zxcvbn` strength of at
  least 3. All three paths emit the same localized hint.
- Password hashing moved to Argon2id with parameters calibrated for the
  deployment, and the bundled `argon2` WebAssembly asset was removed now that
  the server is the only password verifier.
- Markdown rendering strips remote images and other markup that let a stored
  post track readers or execute script.
- Proof-of-work inputs are length- and range-validated before any hashing, and
  rate-limit and captcha state are bounded so a single caller cannot exhaust
  memory.

### Operations, backup, and release

- `install.sh`, `upgrade.sh`, and `rollback.sh` redact the PostgreSQL connection
  string in all output. A snapshot persists only a passwordless peer-socket
  DSN, never a credential-bearing one.
- Rollback restores an encrypted dump as a stream
  (`age --decrypt | pg_restore`) and never writes a decrypted archive to disk.
  It refuses a credential-bearing DSN, requires the restore role to equal the
  service role, and requires the age identity to be root-owned and mode 600.
  A failed service start during rollback is no longer ignored.
- `db-maintenance.sh` builds each backup in a private `mktemp -d` workspace and
  publishes it with an atomic `ln`, so a concurrent run can never observe or
  overwrite a partial archive. `check` no longer requires an age recipient.
- The non-root bypass needs both `VEIL_ALLOW_NONROOT=1` and
  `VEIL_TEST_HARNESS=1`; a single variable no longer disables the root checks.
- CI builds and signs a **draft** release, runs `tests/release_packages_e2e.sh`
  against the draft assets, and only then publishes it. A failed validation
  leaves the release as a draft instead of exposing unverified assets.
  `verify` runs with the least privileges it needs and clippy covers all
  features.
- `release_packages_e2e.sh` derives the expected migration count from the
  migrations shipped inside each archive instead of the current working tree,
  requires `cosign` only on the signed-release path, and can execute
  non-native archives under QEMU user-mode emulation
  (`VEIL_QEMU_BIN_DIR` plus `VEIL_QEMU_SYSROOT_DIR`). It probes each
  emulator/sysroot pair, reports `passed` only when no archive was skipped,
  asserts the service process tree is really gone after SIGTERM, and records
  `passed_with_partial_runs` or `passed_with_runtime_skips` otherwise.
- `tests/deploy-scripts.sh` no longer blocks on an inherited stdin, which had
  made the deployment suite hang indefinitely.

### Tests

- Add real end-to-end suites with credential-free JSON reports:
  authentication, configuration effects, forum lifecycle, governance, search
  privacy, and the backup/upgrade/rollback flow. Each report records a schema,
  UTC timestamps, an input summary, the checks it expected and completed, a
  reproduction command, and `credentials_included=false`, and is written even
  on panic.
- The authentication E2E now exercises weak-password rejection at registration,
  self-service change, and administrator change, and asserts the secure cookie
  attributes on the real response.

## 0.1.0-alpha.19

**Breaking for operators:** the PostgreSQL connection string must now carry a
user and a non-empty host. The Unix-socket form changed from
`postgres:///veil_forum?host=/var/run/postgresql` to
`postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum`. The systemd unit,
the OpenRC script, the maintenance and backup scripts, the defaults and the docs
all use the new form. Password hashes are unaffected: the PHC string that argon2
writes is unchanged, so existing accounts keep working.

- Add `--help`/`--version` and `--db-socket`/`--db-name`/`--db-user`: the
  socket connection string is now composed by the binary, so operators no
  longer hand-encode the `%2F` URL. An explicit `--database-url` (or
  `DATABASE_URL`) still wins and is rejected when mixed with the socket parts.
  The startup banner prints the version.
- Add `scripts/install.sh`: an idempotent installer (system user, PostgreSQL
  role and database with peer authentication, binary plus `static/`, systemd or
  OpenRC unit, first-run seeding, `/healthz` verification) with `--dry-run`.
- Add `scripts/upgrade.sh`: checksum verification, a pre-upgrade database
  backup, a versioned snapshot of the running binary and `static/`, a
  `/healthz` gate, and an automatic rollback on failure.
- Add `scripts/rollback.sh`: restore a snapshot without touching the database,
  or additionally restore a pre-upgrade dump into a fresh database with
  `--restore-db` (required when the failed release already applied a
  migration).
- Document that only `static/` travels with the binary: templates, locales
  and migrations are embedded. `scripts/release.sh` now refuses to package a
  version that disagrees with `Cargo.toml` or has no CHANGELOG entry.
- Remove the one-shot SQLite importer (`veil-forum-import`) and the
  `sqlite-import` feature; the migration is done and the SQLite driver no longer
  belongs in the build. An installation still on SQLite should import once with
  the `veil-forum-import` binary from the `v0.1.0-alpha.18` release and then
  install a later one.
- Upgrade the dependency tree: axum 0.8, sqlx 0.9, tera 2, comrak 0.55, argon2
  0.6, rand 0.10, hmac 0.13, sha2 0.11, base64 0.23, plus semver-compatible
  updates throughout.
  - Routes use axum 0.8's `{parameter}` syntax.
  - Tera 2 resolves includes while parsing, so the embedded templates are
    registered in one batch, and the removed `urlencode` filter is gone: board
    slugs are validated server-side against the URL-safe set instead of being
    escaped at render time.
  - sqlx 0.9 rejects dynamically built SQL strings, so the two statements that
    assemble a compile-time constant now say so explicitly with
    `AssertSqlSafe`.

## 0.1.0-alpha.18

**Breaking:** the storage backend is PostgreSQL only. SQLite support and the
shared-database interop with the earlier Go implementation are removed, so an
existing installation must be imported once with `veil-forum-import`.

- Replace SQLite with PostgreSQL: a single embedded baseline schema, native
  `BOOLEAN` flags, `TIMESTAMPTZ` columns, `BIGINT` identity keys, `RETURNING id`
  instead of `last_insert_rowid()`, and `ON CONFLICT` upserts.
- Move migrations to `sqlx::migrate!`: applied under a PostgreSQL advisory lock,
  transactional, and checksum-verified. The `migrations/` directory is embedded
  in the binary, so a release no longer has to ship it alongside.
- Replace FTS5 search with `pg_trgm`: `ILIKE` matching over GIN trigram indexes
  on `threads.title` and `posts.content_md`, ranked with `similarity()`. Wildcard
  characters in a query are escaped and now match literally. The result set is
  unchanged; the order is relevance-based rather than `rank`-based.
- Collapse the per-search `COUNT(*)` and page query into one round trip with
  `COUNT(*) OVER ()`.
- Replace `--data <path>` with `--database-url <dsn>` (also read from
  `DATABASE_URL`), defaulting to `postgres:///veil_forum?host=/var/run/postgresql`
  so the database uses a local Unix socket and peer authentication. Passwords in
  a connection string are redacted from every error message and log line.
- Add `veil-forum-import`, a one-shot SQLite to PostgreSQL importer that copies
  every table with its original identifiers, converts all historical timestamp
  formats, restores owner roles for administrators, advances identity sequences,
  and prints a per-table row-count reconciliation. `--dry-run` reports without
  writing; a database that already contains forum data requires `--force`.
- Connection handling now retries the initial connection for five seconds, so a
  service that starts alongside PostgreSQL still comes up, and the pool size is
  16 rather than 1.
- `/healthz` reports the real database state again: `SELECT 1` returns `int4` in
  PostgreSQL, so the previous `int8` decode reported the database unavailable.
- Fix a non-terminating loop in the connection-string redaction helper for URLs
  carrying `password=` as a query parameter.
- Deployment: the systemd unit requires `postgresql.service`, drops the data
  directory, and connects over socket; `scripts/db-maintenance.sh` and
  `scripts/backup.sh` use `pg_dump --format=custom` with `pg_restore --list`
  verification; the CI suite runs against a PostgreSQL service container.

- Add an optional TOTP second factor (RFC 6238) with an account page: change
  password, enrol or disable a second factor, reissue recovery codes, and review
  or revoke other sessions. Enrolment is confirmed with a code before it becomes
  active, the QR code is inline SVG so the no-JavaScript pages need no script or
  external image, and secrets are stored base32 like every mainstream forum.
- The password step no longer creates a session when a second factor is active:
  a short-lived pending login is created instead, codes are single use per time
  step, failed attempts are capped at five, and every outcome is audited.
- Add one-time recovery codes (ten, SHA-256 hashed, shown once) and make session
  revocation part of account management.
- Add administrator settings for the feature and its policy (`nobody`, `staff
  only`, or `everyone`). A required policy never blocks signing in; members
  without a factor are pointed at the account page instead.
- Fix seven leftover integer bindings against boolean columns found while adding
  the feature, which affected banning, thread pinning and locking, board updates,
  and the audit log writer.

- Security review follow-ups, each with a regression test:

  - The second-factor enforcement gate and the request handlers now read the
    session cookie with the same parser. A crafted `Cookie: session_id= <id>`
    used to look like a guest to the gate and like a member to the handler,
    which bypassed a required second factor.
  - Enrolling a second factor costs the current password, and switching it on or
    off revokes every other session. A stolen session can no longer bind a
    secret its owner cannot read, or outlive the change.
  - A time step is claimed with one conditional
    `UPDATE ... WHERE totp_last_step < $1`, so a concurrent second login cannot
    spend the same code and a late write cannot reopen a used window.
  - A failed read of the second-factor state now fails closed on the login and
    disable paths instead of falling through to a password-only login.
  - `redact_database_url` covers every connection-string form sqlx accepts,
    including the keyword/value form and passwords containing `@`; the startup
    smoke test asserts that a password never reaches the log.
  - The SQLite importer runs inside a single transaction. A malformed legacy row
    rolls the whole import back instead of leaving a truncated, half-populated
    database.
  - The backup directory is created mode 0700 regardless of the caller's umask,
    and `VEIL_BACKUP_RETAIN=0`, an empty value, or a non-numeric value no longer
    deletes every archive.
  - `--addr` is resolved before the loopback guard, so a hostname cannot bind a
    non-loopback interface while skipping the check, and every connection
    attempt is bounded so startup cannot outlast the service manager's timeout.
  - A thread or reply whose board row cannot be read is refused rather than
    served without the private-board check, and unmatched paths now carry the
    security headers.
  - Restore the alphanumeric CAPTCHA. The interim arithmetic challenge drew two
    small operands, an answer space of about twenty that a script defeats within
    its five attempts, and it needed system font libraries that the static musl
    release targets cannot link.

## 0.1.0-alpha.17

- Let administrators configure the forum footer from System settings, with a localised privacy default when blank. The required Source link to veil-forum remains fixed and cannot be removed.
- Consolidate compatible Dependabot updates for `axum-extra`, `governor`, `tower`, `tower-http`, and GitHub Actions artifacts.
- Ignore local preview runtime data to keep development databases and logs out of releases.

## 0.1.0-alpha.16

- Add self-hosted image CAPTCHA with scoped, single-use HMAC challenges, configurable difficulty, and independent registration, login, and posting policies.
- Add governance and system-settings workspaces for moderation, recovery, roles, sessions, audit history, registration policy, and locale configuration.
- Improve operational safeguards, error handling, migrations, and integration coverage.


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
