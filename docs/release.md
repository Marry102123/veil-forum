# Release checklist

Each release is a git tag `v<VERSION>` (for example `v0.1.0-alpha.19`). The tag,
`Cargo.toml`, and `CHANGELOG.md` must agree; `scripts/release.sh` enforces the
last two, and CI builds the archives from the tag.

## Prepare

1. Move the pending entries out of any scratch notes into a `## <VERSION>`
   section in `CHANGELOG.md`. Call out breaking operator changes first
   (connection string, migration notes, unit file changes).
2. Bump `version` in `Cargo.toml` to `<VERSION>` and run `cargo build` once so
   `Cargo.lock` follows.
3. Run the full gate locally:
   `cargo fmt --all -- --check`,
   `DATABASE_URL=postgres://user@%2Fvar%2Frun%2Fpostgresql/veil_forum_test cargo test --all-targets`,
   `cargo clippy --all-targets --all-features`, `tests/scripts.sh`, `tests/deploy-scripts.sh`,
   and `sh tests/backup_upgrade_e2e.sh` (requires PostgreSQL tools and passwordless
   `sudo`). The `#[sqlx::test]` suites require `DATABASE_URL`; the backup E2E
   invokes sudo with explicit non-interactive environment arguments and does
   not depend on ordinary shell variables being inherited.
4. Sanity-check the new scripts' help: `scripts/install.sh --help`,
   `scripts/upgrade.sh --help`, `scripts/rollback.sh --help`.

## Tag and publish

5. Commit, then tag: `git tag v<VERSION>` (annotated tags are fine too).
6. Push the branch and the tag. CI runs `verify` first, then
   `release-build` cross-compiles every target, and `stage-release` signs and
   uploads all payloads to a **draft** release. `stage-release` has only
   `contents:write` and `id-token:write`. It uses keyless Sigstore/cosign, not
   a repository-held key, and produces a `.sig` bundle and `.pem` Fulcio
   certificate for every archive and for the checksums file. `release-build`
   is read-only and cannot publish or change actions.
7. The tag-only `release-package-e2e` job downloads and exercises those draft
   assets with `RELEASE_TAG=v<VERSION> RELEASE_REPO=OWNER/REPO
   sh tests/release_packages_e2e.sh` and `GH_TOKEN` set. It covers
   authentication/tag/asset lookup, checksum and archive safety, target/ELF
   agreement, CLI contract, real startup, the migration set shipped inside each
   archive, session token digests, administrator/owner seeding, `/healthz`,
   SIGTERM, process-leak, and cleanup. Every archive is expected to execute
   against a real temporary PostgreSQL cluster. Set `VEIL_QEMU_BIN_DIR` to a
   directory of `qemu-<arch>` binaries and `VEIL_QEMU_SYSROOT_DIR` to a matching
   sysroot tree to execute non-native archives under user-mode emulation
   instead of only inspecting them; the script probes each pair and records an
   explicit `runtime_<target>` skip when a guest cannot be loaded, so a report
   can never overstate what actually ran. The result is `passed` only when no
   archive was skipped, `passed_with_partial_runs` when some archives were
   inspected but not executed, and `passed_with_runtime_skips` when nothing
   could be executed. It uploads
   `target/release-packages-e2e-report.json` and
   `target/release-packages-e2e-logs/`. This job is absent from ordinary branch
   and pull-request CI, so those runs never depend on release assets.
8. Only after that E2E passes does `finalize-release` publish the draft with
   `contents:write` only. A failed validation leaves the release as a draft
   rather than exposing unsigned or unverified assets.

## Smoke-test the upgrade path

9. After the draft becomes public, download one archive (at least
   `x86_64-unknown-linux-musl`) and its `.sig` and `.pem` files. Repeat the
   verification locally:
   `cosign verify-blob --certificate-identity-regexp '^https://github.com/Marry102123/veil-forum/\.github/workflows/ci\.yml@refs/tags/v<VERSION>$' --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate <archive>.pem --bundle <archive>.sig <archive>`.
   Also run `sha256sum -c veil-forum-*-checksums.txt` and confirm the archive
   contains `veil-forum`, `deploy/veil-forum.service`, and `static/style.css`.
10. On a scratch host or VM with the previous release installed, put the
   downloaded `.sig` and `.pem` files for the selected archive and checksum
   file in one directory. Configure a mode 600 age recipient file, then name
   exactly one archive and run:
   `sudo env VEIL_BACKUP_RECIPIENT_FILE=/etc/veil-forum/backup-recipients scripts/upgrade.sh <single-archive> --checksums <checksums-file> --signatures <signature-directory>`.
   Both the archive and checksums file are verified with the pinned GitHub
   Actions workflow identity, exact repository/tag, and OIDC issuer before
   the archive is unpacked. `--no-checksum-verify` remains available, but it
   never disables signatures. `cosign` is required.
11. Confirm `/healthz` says `ok`, the banner shows the new version, and a
   rollback snapshot exists under `/var/lib/veil-forum/rollback/`.
12. Optionally exercise `sudo scripts/rollback.sh` and re-upgrade, so both
    directions are proven before operators follow.

## Backup, upgrade, and rollback E2E evidence

Run the real boundary test with `sh tests/backup_upgrade_e2e.sh` from the
repository root. Each run writes `target/backup-upgrade-e2e-report.json`; the
JSON records the command that regenerates and verifies it and contains no
credentials. Per-phase logs live only in the test's private temporary
directory. Its cleanup trap removes those logs, age identities, encrypted
backups, snapshots, service PID files, and temporary database on both success
and failure, and drops a role it created or restores the original attributes
of a role it narrowed. CI retains the credential-free JSON reports and the
sanitized application JSON log, not raw temporary logs or key material. A
failed early startup still leaves a credential-free failure report behind.

## Notes

- `v0.1.0-alpha.19` predates signed assets. It can only be used with the
  explicit, tag-bound emergency escape
  `--no-attestation-verify v0.1.0-alpha.19`. The command prints a prominent
  warning. Use it only for that historical tag, never for a new release.

- The archive still ships `locales/` and `migrations/` for reference, but at
  runtime only the binary and `static/` are required: templates, locales and
  migrations are embedded in the binary.
- Write the GitHub release notes from the CHANGELOG section. If the release
  applied a migration, say so explicitly: downgrading afterwards needs the
  pre-upgrade database backup restored into a fresh database
  (`scripts/rollback.sh --restore-db`).
