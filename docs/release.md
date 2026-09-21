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
   `cargo fmt --all -- --check`, `cargo test --all-targets`,
   `cargo clippy --all-targets`, `tests/scripts.sh`, `tests/deploy-scripts.sh`.
4. Sanity-check the new scripts' help: `scripts/install.sh --help`,
   `scripts/upgrade.sh --help`, `scripts/rollback.sh --help`.

## Tag and publish

5. Commit, then tag: `git tag v<VERSION>` (annotated tags are fine too).
6. Push the branch and the tag. CI runs `verify` first; only then
   `release-build` cross-compiles every target and `publish-release` uploads
   the archives plus `veil-forum-<tag>-checksums.txt`.
7. Download one archive (at least `x86_64-unknown-linux-musl`), verify
   `sha256sum -c veil-forum-*-checksums.txt`, and confirm it contains
   `veil-forum`, `deploy/veil-forum.service`, and `static/style.css`.

## Smoke-test the upgrade path

8. On a scratch host or VM with the previous release installed:
   `sudo scripts/upgrade.sh <archive> --checksums <checksums-file>`.
9. Confirm `/healthz` says `ok`, the banner shows the new version, and a
   rollback snapshot exists under `/var/lib/veil-forum/rollback/`.
10. Optionally exercise `sudo scripts/rollback.sh` and re-upgrade, so both
    directions are proven before operators follow.

## Notes

- The archive still ships `locales/` and `migrations/` for reference, but at
  runtime only the binary and `static/` are required: templates, locales and
  migrations are embedded in the binary.
- Write the GitHub release notes from the CHANGELOG section. If the release
  applied a migration, say so explicitly: downgrading afterwards needs the
  pre-upgrade database backup restored into a fresh database
  (`scripts/rollback.sh --restore-db`).
