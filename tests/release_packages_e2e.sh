#!/bin/sh
# Real GitHub Release package E2E for veil-forum.
#
# Failure modes covered:
# 1. RELEASE_REPO is absent, malformed, or does not identify the origin GitHub repository.
# 2. Cargo.toml has no unambiguous package version, or the default release tag is missing.
# 3. GitHub authentication fails, the release/tag is absent, or release assets cannot be downloaded.
# 4. The release tag, package version, archive names, or asset names disagree.
# 5. A checksum asset is absent, malformed, incomplete, or an archive SHA-256 does not match.
# 6. A Sigstore bundle/certificate is missing, tampered, or has the wrong GitHub identity/issuer.
# 7. An archive is empty, corrupt, has unsafe paths, or lacks the executable, service, or static assets.
# 7. A released executable is not ELF, or its ELF machine and target-triple architecture disagree.
# 8. --version disagrees with Cargo.toml, or --help is missing the documented executable interface.
# 9. A native package cannot start a real temporary PostgreSQL cluster or run migrations.
# 10. The native executable cannot seed the administrator or serve /healthz with "ok".
# 11. The native executable ignores SIGTERM, remains alive, or cannot be stopped cleanly.
# 12. Temporary files, PostgreSQL processes, ports, or database state survive a failed run.
# 13. The final JSON report is malformed, incomplete, or contains credentials.
#
# Environment:
#   RELEASE_TAG    Git tag to test (default: v + current Cargo.toml package version)
#   RELEASE_REPO   GitHub owner/repository (default: owner/repository parsed from origin)
#
# All archives are downloaded and inspected. A package whose target architecture
# matches the host is executed against a real temporary PostgreSQL cluster. A
# package for another architecture is recorded as an explicit runtime skip, never
# as a pass. The same command creates a credential-free, reproducible report at
# target/release-packages-e2e-report.json and sanitized logs under
# target/release-packages-e2e-logs/.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/veil-release-packages-e2e.XXXXXX")
REPORT="$ROOT/target/release-packages-e2e-report.json"
LOG_ROOT="$ROOT/target/release-packages-e2e-logs"
DOWNLOAD="$TMP/download"
EXTRACT="$TMP/extract"
TAG="${RELEASE_TAG:-}"
REPO="${RELEASE_REPO:-}"
VERSION=""
LEGACY_UNSIGNED_TAG="v0.1.0-alpha.19"
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESULT="failed"
FAILURE="E2E did not complete"
STEP="initialization"
CHECKS="$TMP/checks.tsv"
LOG="$TMP/e2e.log"
PIDS=""
PG_CTL=""
PG_DATA=""

mkdir -p "$ROOT/target"
rm -rf "$LOG_ROOT"
mkdir -p "$LOG_ROOT" "$DOWNLOAD" "$EXTRACT"
: > "$CHECKS"
: > "$LOG"

exec > "$LOG" 2>&1

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$PIDS" ]; then
    for pid in $PIDS; do
      kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in $PIDS; do
      wait "$pid" 2>/dev/null || true
    done
  fi
  if [ -n "$PG_CTL" ] && [ -d "$PG_DATA" ]; then
    "$PG_CTL" -D "$PG_DATA" -m fast -w stop >/dev/null 2>&1 || true
  fi
  if python3 - "$LOG" "$TMP/sanitized.log" <<'PY'
import pathlib
import re
import sys
source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
patterns = [
    (r"(?i)(GH_TOKEN|GITHUB_TOKEN)(\s*[=:]\s*)[^\s,;]+", r"\1\2[REDACTED]"),
    (r"(?i)(password\s*[=:]\s*)[^\s,;]+", r"\1[REDACTED]"),
    (r"(?i)(postgres(?:ql)?://[^:/@\s]+:)[^@/\s]+@", r"\1[REDACTED]@"),
]
for pattern, replacement in patterns:
    source = re.sub(pattern, replacement, source)
pathlib.Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY
  then
    cp "$TMP/sanitized.log" "$LOG_ROOT/e2e.log" 2>/dev/null || true
  else
    printf 'release-packages E2E: log sanitization failed\n' >&2
    rm -f "$LOG_ROOT/e2e.log"
  fi
  if ! write_report; then
    printf 'release-packages E2E: could not write report\n' >&2
  fi
  rm -rf "$TMP"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

write_report() {
  mkdir -p "$ROOT/target"
  python3 - "$REPORT" "$TMP" "$ROOT" "$STARTED_AT" "$TAG" "$REPO" "$VERSION" "$RESULT" "$FAILURE" "$STEP" <<'PY'
import datetime
import json
import pathlib
import sys

report, tmp, root, started, tag, repo, version, result, failure, step = sys.argv[1:]
checks_path = pathlib.Path(tmp) / "checks.tsv"
checks = []
for raw in checks_path.read_text(encoding="utf-8").splitlines():
    parts = raw.split("\t", 2)
    if len(parts) == 3:
        checks.append({"name": parts[0], "status": parts[1], "detail": parts[2]})
report_data = {
    "schema_version": 1,
    "test": "real_github_release_packages_e2e",
    "started_at_utc": started,
    "finished_at_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "inputs": {"release_tag": tag, "release_repo": repo, "cargo_version": version},
    "result": result,
    "failed_step": step,
    "failure": failure,
    "checks": checks,
    "artifacts": {
        "report": "target/release-packages-e2e-report.json",
        "logs": "target/release-packages-e2e-logs/e2e.log",
    },
    "verification_command": "RELEASE_TAG=vVERSION RELEASE_REPO=OWNER/REPO tests/release_packages_e2e.sh",
    "credentials_included": False,
}
text = json.dumps(report_data, indent=2, sort_keys=True) + "\n"
for forbidden in ("GH_TOKEN", "GITHUB_TOKEN", "password=", "postgres://postgres:"):
    if forbidden in text:
        raise SystemExit(f"refusing to write credential-bearing report marker: {forbidden}")
pathlib.Path(report).write_text(text, encoding="utf-8")
json.loads(pathlib.Path(report).read_text(encoding="utf-8"))
PY
}

fail() {
  FAILURE=$1
  printf 'release-packages E2E FAILED: %s\n' "$FAILURE" >&2
  exit 1
}

record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$CHECKS"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

repo_from_origin() {
  origin=$(git -C "$ROOT" remote get-url origin 2>/dev/null || true)
  [ -n "$origin" ] || fail 'origin is not configured'
  case "$origin" in
    https://github.com/*) value=${origin#https://github.com/} ;;
    http://github.com/*) value=${origin#http://github.com/} ;;
    git@github.com:*) value=${origin#git@github.com:} ;;
    ssh://git@github.com/*) value=${origin#ssh://git@github.com/} ;;
    *) fail "origin is not a supported GitHub repository URL: $origin" ;;
  esac
  value=${value%.git}
  value=${value#/}
  printf '%s\n' "$value"
}

version_matches_count=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$ROOT/Cargo.toml" | awk 'NF { count++; value=$0 } END { if (count == 1) print value; else print "__INVALID__" }')
[ "$version_matches_count" != __INVALID__ ] || fail 'Cargo.toml must contain exactly one unambiguous package version'
VERSION=$version_matches_count
[ -n "$TAG" ] || TAG="v$VERSION"
[ -n "$REPO" ] || REPO=$(repo_from_origin)
case "$REPO" in
  */*/*|/*|*/|'') fail "RELEASE_REPO must be OWNER/REPOSITORY: $REPO" ;;
  */*) ;;
  *) fail "RELEASE_REPO must be OWNER/REPOSITORY: $REPO" ;;
esac
[ "$REPO" = "Marry102123/veil-forum" ] || fail "release signatures are pinned to Marry102123/veil-forum, not $REPO"
TAG=$(printf '%s' "$TAG" | tr -d '\r\n')
REPO=$(printf '%s' "$REPO" | tr -d '\r\n')
[ "$TAG" = "v$VERSION" ] || fail "release tag $TAG disagrees with Cargo.toml version v$VERSION"
case "$TAG" in
  ''|*[!A-Za-z0-9._-]*) fail "unsafe RELEASE_TAG: $TAG" ;;
esac
case "$REPO" in
  *[!A-Za-z0-9._/-]*) fail "unsafe RELEASE_REPO: $REPO" ;;
esac

for cmd in gh git sha256sum tar file readelf python3 curl find dd od uname sleep awk; do
  need_cmd "$cmd"
done
# cosign is only required when the signed-release verification path actually
# runs. A historical unsigned release must not be blocked by a tool it never
# uses, otherwise the runtime/architecture coverage below becomes unreachable.
if [ "$TAG" != "$LEGACY_UNSIGNED_TAG" ]; then
  need_cmd cosign
fi
gh auth status -h github.com >/dev/null 2>&1 || fail 'GitHub CLI authentication failed'

STEP="download_release_assets"
released_tag=$(gh release view "$TAG" --repo "$REPO" --json tagName --jq '.tagName')
[ "$released_tag" = "$TAG" ] || fail "GitHub release tag mismatch: requested $TAG, received $released_tag"
gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name' > "$TMP/assets.txt"
[ -s "$TMP/assets.txt" ] || fail 'release contains no assets'
CHECKSUM_ASSET="veil-forum-$TAG-checksums.txt"
grep -F -x "$CHECKSUM_ASSET" "$TMP/assets.txt" >/dev/null || fail "missing checksum asset: $CHECKSUM_ASSET"
record checksums_asset_present passed 'required checksum asset was published'

while IFS= read -r asset; do
  case "$asset" in
    ''|*[!A-Za-z0-9._-]*) fail "unsafe release asset name: $asset" ;;
  esac
  printf 'Downloading %s\n' "$asset"
  gh release download "$TAG" --repo "$REPO" --pattern "$asset" --dir "$DOWNLOAD"
done < "$TMP/assets.txt"
record assets_download passed 'all published release assets downloaded'

for asset in "$DOWNLOAD"/*; do
  [ -f "$asset" ] || fail "downloaded asset is not a regular file: $asset"
  [ -s "$asset" ] || fail "downloaded asset is empty: ${asset##*/}"
done
CHECKSUM_PATH="$DOWNLOAD/$CHECKSUM_ASSET"
[ -s "$CHECKSUM_PATH" ] || fail 'checksum asset is empty'

STEP="verify_sha256"
(cd "$DOWNLOAD" && sha256sum -c "$CHECKSUM_ASSET") > "$LOG_ROOT/sha256.log" 2>&1 || {
  cat "$LOG_ROOT/sha256.log" >&2
  fail 'published SHA-256 verification failed'
}
archive_count=0
while IFS= read -r archive; do
  archive_name=${archive##*/}
  awk -v name="$archive_name" '$2 == name { found = 1 } END { exit(found ? 0 : 1) }' "$CHECKSUM_PATH" \
    || fail "checksums omit archive: $archive_name"
  archive_count=$((archive_count + 1))
done <<EOF
$(find "$DOWNLOAD" -maxdepth 1 -type f -name 'veil-forum-*.tar.gz' -print | sort)
EOF
[ "$archive_count" -gt 0 ] || fail 'release contains no tar.gz archives'
record sha256 passed "$archive_count archive(s) matched the published checksum file"

STEP="verify_sigstore"
if [ "$TAG" = "$LEGACY_UNSIGNED_TAG" ]; then
  record sigstore skipped 'historical unsigned release: Sigstore verification is not applicable'
else
  IDENTITY="^https://github.com/Marry102123/veil-forum/\\.github/workflows/ci\\.yml@refs/tags/$TAG$"
  for payload in "$CHECKSUM_PATH" "$DOWNLOAD"/veil-forum-*.tar.gz; do
    name=${payload##*/}
    bundle="$DOWNLOAD/$name.sig"
    certificate="$DOWNLOAD/$name.pem"
    [ -s "$bundle" ] || fail "missing Sigstore bundle: $name.sig"
    [ -s "$certificate" ] || fail "missing Sigstore certificate: $name.pem"
    cosign verify-blob --bundle "$bundle" --certificate "$certificate" \
      --certificate-identity-regexp "$IDENTITY" \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      "$payload" > "$LOG_ROOT/cosign-$name.log" 2>&1 || fail "Sigstore verification failed: $name"
  done
  record sigstore passed 'every payload has a valid keyless bundle for the pinned repository, tag workflow, and OIDC issuer'
fi

# Negative controls ensure a valid-looking release cannot turn verification into a no-op.
if [ "$TAG" != "$LEGACY_UNSIGNED_TAG" ]; then
  negative="$TMP/negative"
mkdir -p "$negative"
cp "$CHECKSUM_PATH" "$negative/$(basename "$CHECKSUM_PATH")"
cp "$CHECKSUM_PATH.sig" "$negative/$(basename "$CHECKSUM_PATH").sig"
cp "$CHECKSUM_PATH.pem" "$negative/$(basename "$CHECKSUM_PATH").pem"
printf '\n# tampered\n' >> "$negative/$(basename "$CHECKSUM_PATH")"
if cosign verify-blob --bundle "$negative/$(basename "$CHECKSUM_PATH").sig" \
  --certificate "$negative/$(basename "$CHECKSUM_PATH").pem" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$negative/$(basename "$CHECKSUM_PATH")" >/dev/null 2>&1; then
  fail 'tampered payload unexpectedly passed Sigstore verification'
fi
if cosign verify-blob --bundle "$CHECKSUM_PATH.sig" --certificate "$CHECKSUM_PATH.pem" \
  --certificate-identity-regexp '^https://github.com/Attacker/veil-forum/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$CHECKSUM_PATH" >/dev/null 2>&1; then
  fail 'wrong repository identity unexpectedly passed Sigstore verification'
fi
record sigstore_negative passed 'tampered content and wrong repository identity both failed closed'
fi

host_arch=$(uname -m)
case "$host_arch" in
  x86_64|amd64) local_prefix=x86_64- ;;
  aarch64|arm64) local_prefix=aarch64- ;;
  i386|i486|i586|i686) local_prefix=i686- ;;
  armv7l|armv7) local_prefix=armv7- ;;
  riscv64) local_prefix=riscv64gc- ;;
  ppc64le) local_prefix=powerpc64le- ;;
  s390x) local_prefix=s390x- ;;
  *) local_prefix='' ;;
esac

# Optional QEMU user-mode emulation. When VEIL_QEMU_BIN_DIR points at a
# directory of qemu-<arch> binaries and VEIL_QEMU_SYSROOT_DIR points at a
# matching sysroot tree, non-native release binaries are really executed
# instead of being recorded as unverifiable runtime skips. A missing or
# unusable emulator is never treated as a pass: it degrades to the previous
# explicit skip so a report can never overstate what was executed.
QEMU_BIN_DIR="${VEIL_QEMU_BIN_DIR:-}"
QEMU_SYSROOT_DIR="${VEIL_QEMU_SYSROOT_DIR:-}"

qemu_for_target() {
  case "$1" in
    aarch64-unknown-linux-gnu) printf 'qemu-aarch64' ;;
    aarch64-unknown-linux-musl) printf 'qemu-aarch64' ;;
    armv7-unknown-linux-musleabihf) printf 'qemu-arm' ;;
    i686-unknown-linux-musl) printf 'qemu-i386' ;;
    riscv64gc-unknown-linux-musl) printf 'qemu-riscv64' ;;
    powerpc64le-unknown-linux-gnu) printf 'qemu-ppc64le' ;;
    s390x-unknown-linux-gnu) printf 'qemu-s390x' ;;
    *) return 1 ;;
  esac
}

# Some architectures ship their sysroot in a per-architecture subdirectory
# (for example sysroots/ppc64le) while others use the root directly. Accept
# either layout so a present sysroot is not reported as missing.
qemu_sysroot_for_target() {
  case "$1" in
    aarch64-*) candidate="$QEMU_SYSROOT_DIR/aarch64" ;;
    powerpc64le-*) candidate="$QEMU_SYSROOT_DIR/ppc64le" ;;
    s390x-*) candidate="$QEMU_SYSROOT_DIR/s390x" ;;
    *) candidate="$QEMU_SYSROOT_DIR" ;;
  esac
  # Prefer the per-architecture tree when it carries a guest dynamic loader, then
  # fall back to the shared root, then the bare configured directory. Checking
  # the loader explicitly avoids claiming coverage for a sysroot that cannot
  # actually start the guest.
  for sysroot_candidate in "$candidate" "$QEMU_SYSROOT_DIR"; do
    [ -d "$sysroot_candidate" ] || continue
    if [ -n "$(find "$sysroot_candidate" -maxdepth 4 -name 'ld-linux*' -o -maxdepth 4 -name 'ld64.so*' -o -maxdepth 4 -name 'ld-musl*' 2>/dev/null | head -n 1)" ]; then
      printf '%s\n' "$sysroot_candidate"
      return 0
    fi
  done
  return 1
}

qemu_runnable() {
  [ -n "$QEMU_BIN_DIR" ] && [ -n "$QEMU_SYSROOT_DIR" ] || return 1
  [ -x "$QEMU_BIN_DIR/$(qemu_for_target "$1")" ] || return 1
  qemu_sysroot_for_target "$1" >/dev/null || return 1
  return 0
}

# The presence of an emulator binary and a sysroot directory does not prove the
# pair can actually load this guest: the dynamic loader may be missing. Probe
# the real binary before claiming runtime coverage, and treat "cannot load" as
# an explicit environment skip rather than a product failure or a pass.
qemu_probe_target() {
  if "$QEMU_BIN_DIR/$(qemu_for_target "$target")" -L "$qemu_sysroot" "$binary" --version \
      > "$TMP/qemu-probe-$target.txt" 2>&1; then
    return 0
  fi
  return 1
}

run_released() {
  target=$1
  shift
  if [ -n "$qemu_bin" ]; then
    "$qemu_bin" -L "$qemu_sysroot" "$binary" "$@"
  else
    "$binary" "$@"
  fi
}

native_count=0
emulated_count=0
skipped_count=0

machine_for_target() {
  case "$1" in
    x86_64-*) printf 'Advanced Micro Devices X86-64' ;;
    aarch64-*) printf 'AArch64' ;;
    i686-*) printf 'Intel 80386' ;;
    armv7-*) printf 'ARM' ;;
    riscv64gc-*) printf 'RISC-V' ;;
    powerpc64le-*) printf 'PowerPC64' ;;
    s390x-*) printf 'IBM S/390' ;;
    *) return 1 ;;
  esac
}

file_arch_for_target() {
  case "$1" in
    x86_64-*) printf 'x86-64' ;;
    aarch64-*) printf 'ARM aarch64' ;;
    i686-*) printf 'Intel i386' ;;
    armv7-*) printf 'ARM' ;;
    riscv64gc-*) printf 'RISC-V' ;;
    powerpc64le-*) printf 'PowerPC or cisco 7500' ;;
    s390x-*) printf 'IBM S/390' ;;
    *) return 1 ;;
  esac
}

STEP="inspect_archives_and_elf"
: > "$TMP/archives.txt"
find "$DOWNLOAD" -maxdepth 1 -type f -name 'veil-forum-*.tar.gz' -print | sort > "$TMP/archives.txt"
while IFS= read -r archive; do
  name=${archive##*/}
  rest=${name#veil-forum-}
  target=${rest%.tar.gz}
  case "$target" in
    "$TAG"-*) target=${target#"$TAG-"} ;;
    *) fail "archive name does not contain release tag $TAG: $name" ;;
  esac
  case "$target" in
    *[!A-Za-z0-9._-]*|'') fail "unsafe target triple in archive name: $name" ;;
  esac
  expected_machine=$(machine_for_target "$target") || fail "unsupported release target: $target"
  expected_file_arch=$(file_arch_for_target "$target") || fail "unsupported release target: $target"
  members="$TMP/members.txt"
  tar -tzf "$archive" > "$members" 2> "$LOG_ROOT/tar-$target.log" || fail "cannot list archive: $name"
  [ -s "$members" ] || fail "archive has no members: $name"
  root="veil-forum-$TAG"
  tar -tvzf "$archive" > "$TMP/verbose-members.txt" 2> "$LOG_ROOT/tar-$target.log" || fail "cannot list archive: $name"
  while IFS= read -r verbose_member; do
    member_type=$(printf '%s' "$verbose_member" | cut -c 1)
    case "$member_type" in
      -|d) ;;
      *) fail "archive contains a non-regular member (links and devices are forbidden): $name" ;;
    esac
  done < "$TMP/verbose-members.txt"
  while IFS= read -r member; do
    case "$member" in
      "$root"/*) ;;
      *) fail "archive member escapes expected root: $name: $member" ;;
    esac
    case "$member" in
      /*|../*|*/../*|*/..) fail "archive contains an unsafe path: $name: $member" ;;
    esac
  done < "$members"
  for required in veil-forum deploy/veil-forum.service static/style.css; do
    grep -F -x "$root/$required" "$members" >/dev/null || fail "archive $name lacks $root/$required"
  done
  archive_root="$EXTRACT/$target"
  mkdir -p "$archive_root"
  tar -xzf "$archive" -C "$archive_root"
  binary="$archive_root/$root/veil-forum"
  [ -f "$binary" ] && [ -s "$binary" ] || fail "archive executable is absent or empty: $name"
  [ -x "$binary" ] || fail "archived executable is not executable: $name"
  magic=$(dd if="$binary" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
  [ "$magic" = 7f454c46 ] || fail "archived executable is not ELF: $name"
  readelf -h "$binary" > "$LOG_ROOT/readelf-$target.txt" 2>&1 || fail "readelf failed for $name"
  grep -F "Machine:" "$LOG_ROOT/readelf-$target.txt" | grep -F "$expected_machine" >/dev/null || fail "ELF machine does not match $target: $name"
  file_output=$(file -b "$binary")
  printf '%s\n' "$file_output" > "$LOG_ROOT/file-$target.txt"
  printf '%s' "$file_output" | grep -F "$expected_file_arch" >/dev/null || fail "file architecture does not match $target: $name"
  record "archive_$target" passed 'members, ELF machine, and file architecture match the target triple'

  qemu_bin=""
  qemu_sysroot=""
  if [ -z "$local_prefix" ]; then
    record "runtime_$target" skipped "unsupported host architecture ($host_arch); ELF was inspected, execution was not attempted"
    skipped_count=$((skipped_count + 1))
    continue
  fi
  case "$target" in
    "$local_prefix"*) ;;
    *)
      if qemu_runnable "$target"; then
        qemu_bin="$QEMU_BIN_DIR/$(qemu_for_target "$target")"
        qemu_sysroot=$(qemu_sysroot_for_target "$target")
        if qemu_probe_target; then
          record "emulation_$target" passed "non-native target really executed under $(qemu_for_target "$target") user-mode emulation against a real sysroot"
        else
          record "runtime_$target" skipped "emulator $(qemu_for_target "$target") could not load this guest against the provided sysroot: $(tr '\n' ' ' < "$TMP/qemu-probe-$target.txt")"
          skipped_count=$((skipped_count + 1))
          continue
        fi
      else
        record "runtime_$target" skipped "non-native architecture ($target; host $host_arch); ELF was inspected, execution was not attempted"
        skipped_count=$((skipped_count + 1))
        continue
      fi
      ;;
  esac

  version_output=$(run_released "$target" --version)
  [ "$version_output" = "veil-forum $VERSION" ] || fail "released --version mismatch: expected 'veil-forum $VERSION', received '$version_output'"
  run_released "$target" --help > "$LOG_ROOT/help-$target.txt" 2>&1 || fail 'released --help exited non-zero'
  grep -F 'usage: veil-forum' "$LOG_ROOT/help-$target.txt" >/dev/null || fail 'released --help lacks usage'
  grep -F -- '--database-url' "$LOG_ROOT/help-$target.txt" >/dev/null || fail 'released --help lacks database option'
  grep -F -- '--version' "$LOG_ROOT/help-$target.txt" >/dev/null || fail 'released --help lacks version option'
  record "cli_$target" passed '--version matched Cargo.toml and --help documented the executable interface'

  STEP="postgres_runtime_$target"
  for cmd in pg_config psql; do
    need_cmd "$cmd"
  done
  PG_BINDIR=$(pg_config --bindir)
  [ -x "$PG_BINDIR/initdb" ] || fail "initdb is missing from $PG_BINDIR"
  [ -x "$PG_BINDIR/pg_ctl" ] || fail "pg_ctl is missing from $PG_BINDIR"
  PG_CTL="$PG_BINDIR/pg_ctl"
  PG_DATA="$TMP/pg-$target"
  PG_SOCKET="$TMP/s-$target"
  mkdir -p "$PG_SOCKET"
  chmod 0700 "$PG_SOCKET"
  PORT=$(python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
  "$PG_BINDIR/initdb" -D "$PG_DATA" -U postgres --auth=trust --encoding=UTF8 --no-locale > "$LOG_ROOT/initdb-$target.log" 2>&1 || fail "initdb failed for $target"
  "$PG_CTL" -D "$PG_DATA" -l "$LOG_ROOT/postgres-$target.log" \
    -o "-F -p $PORT -k $PG_SOCKET -c listen_addresses=''" -w start >/dev/null 2>&1 || fail "temporary PostgreSQL failed to start for $target"
  PG_SOCKET_URL=$(python3 - "$PG_SOCKET" <<'PY'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
)
  DB_URL="postgres://postgres@${PG_SOCKET_URL}/postgres?port=$PORT"
  PASSWORD="release-e2e-$$-Glacier-Maple7-Raven"
  SERVICE_LOG="$LOG_ROOT/service-$target.log"
  SERVICE_PORT=$(python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
  # Launch the released binary (optionally under QEMU) in its own session with
  # exec so $! is the real process that must respond to SIGTERM. A wrapping
  # subshell would be reaped first and would orphan the real guest process,
  # making the SIGTERM assertion below pass while leaking the service.
  if [ -n "$qemu_bin" ]; then
    (
      export VEIL_ADMIN_PASSWORD="$PASSWORD"
      exec "$qemu_bin" -L "$qemu_sysroot" "$binary" \
        --addr "127.0.0.1:$SERVICE_PORT" --database-url "$DB_URL"
    ) > "$SERVICE_LOG" 2>&1 &
  else
    (
      export VEIL_ADMIN_PASSWORD="$PASSWORD"
      exec "$binary" \
        --addr "127.0.0.1:$SERVICE_PORT" --database-url "$DB_URL"
    ) > "$SERVICE_LOG" 2>&1 &
  fi
  SERVICE_PID=$!
  PIDS="$SERVICE_PID"
  HEALTH_URL="http://127.0.0.1:$SERVICE_PORT/healthz"
  ready=0
  attempt=1
  while [ "$attempt" -le 80 ]; do
    if curl --fail --silent --show-error "$HEALTH_URL" > "$TMP/healthz" 2>/dev/null; then
      ready=1
      break
    fi
    if ! kill -0 "$SERVICE_PID" 2>/dev/null; then
      cat "$SERVICE_LOG" >&2
      fail "released service exited before /healthz for $target"
    fi
    sleep 0.25
    attempt=$((attempt + 1))
  done
  [ "$ready" -eq 1 ] || fail "/healthz did not become ready for $target"
  [ "$(cat "$TMP/healthz")" = ok ] || fail "/healthz response is not ok for $target"
  migration_count=$(psql "$DB_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM _sqlx_migrations WHERE success" 2>/dev/null) || fail "cannot inspect migrations for $target"
  # Migrations are embedded at compile time (src/store.rs: sqlx::migrate!("./migrations")),
  # so the applied set must match the migrations shipped inside this release
  # archive. Comparing against the current working tree would wrongly fail any
  # release published before later migrations were added.
  expected_migrations=$(find "$archive_root/$root/migrations" -maxdepth 1 -type f -name '*.sql' | wc -l)
  [ "$migration_count" -eq "$expected_migrations" ] || fail "applied migration count ($migration_count) does not match the release package set ($expected_migrations) for $target"
  admin_count=$(psql "$DB_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM users WHERE username='admin' AND is_admin" 2>/dev/null) || fail "cannot inspect administrator seed for $target"
  [ "$admin_count" -eq 1 ] || fail "administrator seed missing for $target: $admin_count"
  owner_count=$(psql "$DB_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM user_roles WHERE role_name='owner'" 2>/dev/null) || fail "cannot inspect owner seed for $target"
  [ "$owner_count" -eq 1 ] || fail "owner role seed missing for $target: $owner_count"
  session_digest_column=$(psql "$DB_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.columns WHERE table_name='sessions' AND column_name='id'" 2>/dev/null) || fail "cannot inspect session columns for $target"
  [ "$session_digest_column" -eq 1 ] || fail "session token-digest column is absent for $target"
  if grep -F "$PASSWORD" "$SERVICE_LOG" >/dev/null 2>&1; then
    fail "service log contains administrator password for $target"
  fi
  # The startup banner must never disclose a credential. A peer/socket DSN has no
  # password at all, so assert the real contract instead of demanding a marker.
  logged_dsn=$(sed -n 's/^veil-forum database: //p' "$SERVICE_LOG" 2>/dev/null || true)
  case "$logged_dsn" in
    *://*:*@*) fail "startup banner disclosed a password for $target" ;;
  esac
  case "$logged_dsn" in
    *password=*) fail "startup banner disclosed a password parameter for $target" ;;
  esac
  record "postgres_$target" passed "real temporary PostgreSQL started, $migration_count archive-shipped migration(s) applied, session token digests present, and administrator/owner seeded"
  record "health_$target" passed '/healthz returned ok over HTTP'

  kill -TERM "$SERVICE_PID"
  exited=0
  attempt=1
  while [ "$attempt" -le 20 ]; do
    process_state=$(awk '{print $3}' "/proc/$SERVICE_PID/stat" 2>/dev/null || true)
    if [ -z "$process_state" ] || [ "$process_state" = Z ]; then
      exited=1
      break
    fi
    sleep 0.25
    attempt=$((attempt + 1))
  done
  [ "$exited" -eq 1 ] || fail "released service ignored SIGTERM for $target"
  wait "$SERVICE_PID" 2>/dev/null || true
  # A wrapper that exits while the real service survives would make the check
  # above meaningless, and would leak a listening process. Assert the actual
  # process tree is gone, not just that $SERVICE_PID was reaped.
  leaked=""
  attempt=1
  while [ "$attempt" -le 40 ]; do
    leaked=$(pgrep -f "$binary" 2>/dev/null | tr '\n' ' ' || true)
    [ -z "$leaked" ] && break
    sleep 0.25
    attempt=$((attempt + 1))
  done
  [ -z "$leaked" ] || fail "released service process survived SIGTERM for $target: $leaked"
  PIDS=""
  record "sigterm_$target" passed 'service exited after SIGTERM'
  "$PG_CTL" -D "$PG_DATA" -m fast -w stop > "$LOG_ROOT/pg-stop-$target.log" 2>&1 || fail "temporary PostgreSQL did not stop for $target"
  PG_CTL=""
  PG_DATA=""
  if [ -n "$qemu_bin" ]; then
    emulated_count=$((emulated_count + 1))
  else
    native_count=$((native_count + 1))
  fi
done < "$TMP/archives.txt"

[ "$archive_count" -gt 0 ] || fail 'no release archive was inspected'
# A report must never imply full coverage when some archives were only
# inspected. Three outcomes are reported explicitly:
#   passed                       every archive was really executed
#   passed_with_partial_runs     some archives were executed, some only inspected
#   passed_with_runtime_skips    nothing could be executed at all
executed_count=$((native_count + emulated_count))
if [ "$skipped_count" -eq 0 ] && [ "$executed_count" -gt 0 ]; then
  RESULT="passed"
  FAILURE=""
elif [ "$executed_count" -gt 0 ]; then
  RESULT="passed_with_partial_runs"
  FAILURE="$skipped_count of $archive_count release archive(s) were inspected but not executed on this host"
else
  RESULT="passed_with_runtime_skips"
  FAILURE="no release archive could be executed on this host"
fi
STEP="complete"
printf 'Release package E2E result: %s\n' "$RESULT"
printf 'Report: %s\n' "$REPORT"
printf 'Logs: %s\n' "$LOG_ROOT"
