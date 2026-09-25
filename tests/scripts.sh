#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
BACKUPS="$TMP/backups"
COMPAT_BACKUPS="$TMP/compat-backups"
URL='postgres://veil-forum@%2Fvar%2Frun%2Fpostgresql/veil_forum'

# Minimal pg_dump/pg_restore/psql stand-ins: exercise the scripts without a live
# server. They model the exact statements db-maintenance.sh issues.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/age" <<'EOF'
#!/bin/sh
set -eu
out=
input=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=${2:?}; shift 2 ;;
    -o=*) out=${1#-o=}; shift ;;
    -*) shift ;;
    *) input=$1; shift ;;
  esac
done
[ -n "$out" ] || { echo 'age stub: -o required' >&2; exit 1; }
[ -f "$input" ] || exit 1
printf 'AGE-CIPHERTEXT\n' > "$out"
EOF
cat > "$TMP/bin/age-keygen" <<'EOF'
#!/bin/sh
set -eu
out=
for arg in "$@"; do case "$arg" in -o) shift;; -o=*) out=${arg#-o=};; -y) shift;; esac; shift || true; done
[ -n "$out" ] || { printf 'age1testrecipient\n' ; exit 0; }
printf 'AGE-SECRET-KEY-TEST\n' > "$out"; chmod 600 "$out"
EOF
chmod +x "$TMP/bin/age" "$TMP/bin/age-keygen"
cat > "$TMP/bin/pg_dump" <<'EOF'
#!/bin/sh
set -eu
target=
for arg in "$@"; do
  case "$arg" in
    --file=*) target=${arg#--file=} ;;
  esac
done
[ -n "$target" ] || { echo "pg_dump stub: --file required" >&2; exit 1; }
printf '%s %s\n' "$target" "$(stat -c '%a' "$(dirname -- "$target")")" >> "${PG_DUMP_LOG:-/dev/null}"
printf 'PGDMP\000custom archive\n' > "$target"
EOF
cat > "$TMP/bin/pg_restore" <<'EOF'
#!/bin/sh
set -eu
for arg in "$@"; do
  case "$arg" in
    --list)
      case "$arg" in *.age) exit 1;; esac
      case "$*" in *.age) exit 1;; esac
      printf 'archive listing\n'; exit 0 ;;
  esac
done
exit 0
EOF
cat > "$TMP/bin/psql" <<'EOF'
#!/bin/sh
set -eu
printf '12\n'
EOF
chmod +x "$TMP/bin/pg_dump" "$TMP/bin/pg_restore" "$TMP/bin/psql"

# Fix the archive timestamp so the same-second collision policy is observable.
cat > "$TMP/bin/date" <<EOF
#!/bin/sh
set -eu
if [ -f "$TMP/date-fixed" ]; then
  printf '%s\n' '20260925T010203Z'
  exit 0
fi
n=0
[ ! -f "$TMP/date-count" ] || n=\$(cat "$TMP/date-count")
n=\$((n + 1))
printf '%s\n' "\$n" > "$TMP/date-count"
second=\$((3 + n))
printf '20260925T0102%02dZ\n' "\$second"
EOF
chmod +x "$TMP/bin/date"

URL_SECRET='maintenance-DSN-password-7a62d9'
CRED_URL="postgres://veil-forum:${URL_SECRET}@%2Fvar%2Frun%2Fpostgresql/veil_forum"

# Upgrade signature gates are security boundaries. A cosign stub records the
# required verification policy, while the package is inspected only by dry-run.
cat > "$TMP/bin/cosign" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "${COSIGN_LOG:?}"
case "$*" in
  *'Marry102123/veil-forum/'*) ;;
  *) exit 1 ;;
esac
case "$*" in
  *'https://token.actions.githubusercontent.com'*) ;;
  *) exit 1 ;;
esac
exit 0
EOF
chmod +x "$TMP/bin/cosign"

touch "$TMP/date-fixed"
PG_DUMP_LOG="$TMP/pg-dump.log" VEIL_BACKUP_RECIPIENT=age1testrecipient PATH="$TMP/bin:$PATH" \
  "$ROOT/scripts/db-maintenance.sh" backup "$CRED_URL" "$BACKUPS" > "$TMP/canonical.out" 2>&1
VEIL_BACKUP_RECIPIENT=age1testrecipient PATH="$TMP/bin:$PATH" "$ROOT/scripts/backup.sh" "$URL" "$COMPAT_BACKUPS" > "$TMP/compat.out"
if grep -F "$URL_SECRET" "$TMP/canonical.out" >/dev/null || grep -F "$CRED_URL" "$TMP/canonical.out" >/dev/null; then
  echo 'backup output leaked a credential-bearing DSN' >&2; exit 1
fi
for dir in "$BACKUPS" "$COMPAT_BACKUPS"; do
  count=$(find "$dir" -type f -name 'forum-*.dump.age' | wc -l)
  test "$count" -eq 1
  test "$(find "$dir" -type f -name 'forum-*.dump' | wc -l)" -eq 0
  for file in "$dir"/forum-*.dump.age; do
    test "$(stat -c '%a' "$file")" = 600
    test "$(stat -c '%a' "$dir")" = 700
    test "$(wc -c < "$file")" -gt 0
    grep -q '^AGE-CIPHERTEXT$' "$file"
  done
  if PATH="$TMP/bin:$PATH" pg_restore --list "$dir"/*.dump.age >/dev/null 2>&1; then
    echo 'ciphertext was accepted by pg_restore stub' >&2; exit 1
  fi
done
grep -q 'Backup encrypted and verified:' "$TMP/canonical.out"
grep -q 'Backup encrypted and verified:' "$TMP/compat.out"

# The check mode must report the table count from psql and must not require age.
mkdir -p "$TMP/check-bin"
ln -s "$TMP/bin/psql" "$TMP/check-bin/psql"
ln -s "$(command -v dirname)" "$TMP/check-bin/dirname"
ln -s "$(command -v mktemp)" "$TMP/check-bin/mktemp"
PATH="$TMP/check-bin" "$ROOT/scripts/db-maintenance.sh" check "$URL" > "$TMP/check.out"
grep -q 'Connection ok:' "$TMP/check.out"

# The dump is staged below a private, unpredictable directory inside the
# already-private archive directory. The final archive remains encrypted and no
# plaintext dump is left in either location.
work_record=$(head -n 1 "$TMP/pg-dump.log")
work=${work_record% *}
case "$work" in
  "$BACKUPS"/.forum-20260925T010203Z.??????/dump) ;;
  *) echo "backup did not use an unpredictable private work directory: $work" >&2; exit 1 ;;
esac
workdir=${work%/dump}
test "${work_record##* }" = 700
test ! -e "$workdir"
test "$(find "$BACKUPS" -type f -name dump | wc -l)" -eq 0

# A second archive in the same UTC second fails without replacing the first one.
cp "$BACKUPS/forum-20260925T010203Z.dump.age" "$TMP/first-archive"
if VEIL_BACKUP_RECIPIENT=age1testrecipient PATH="$TMP/bin:$PATH" \
  "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$BACKUPS" >"$TMP/same-second.out" 2>&1; then
  echo 'backup overwrote a same-second archive' >&2; exit 1
fi
cmp "$TMP/first-archive" "$BACKUPS/forum-20260925T010203Z.dump.age"
grep -F 'refusing to overwrite an existing backup' "$TMP/same-second.out" >/dev/null

# Remove the deliberately fixed-time archive after proving collision refusal.
# Subsequent retention cases use the real clock and a fresh archive name.
rm "$BACKUPS/forum-20260925T010203Z.dump.age"
rm "$TMP/date-fixed"

# Retention applies only to this script's own archives, leaving unrelated files
# untouched. The default retention is 30 archives.
touch "$BACKUPS/unrelated.dump"
i=1
while [ "$i" -le 31 ]; do
  touch -d "${i} minutes ago" "$BACKUPS/forum-old-$i.dump.age"
  i=$((i + 1))
done
VEIL_BACKUP_RECIPIENT=age1testrecipient PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$BACKUPS" >/dev/null
test -e "$BACKUPS/unrelated.dump"
kept=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump.age' | wc -l)
test "$kept" -eq 30

# The directory holds dumps of sessions and password hashes: it must be private,
# and it must be created private even when the caller's umask is permissive.
test "$(stat -c '%a' "$BACKUPS")" = 700
PERMISSIVE="$TMP/permissive-backups"
(umask 022; VEIL_BACKUP_RECIPIENT=age1testrecipient PATH="$TMP/bin:$PATH" "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$PERMISSIVE" >/dev/null)
test "$(stat -c '%a' "$PERMISSIVE")" = 700

# A retention value that would delete every archive, or that is not a number, is
# refused instead of applied.
for retain in 0 abc ''; do
  before=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump.age' | wc -l)
  VEIL_BACKUP_RECIPIENT=age1testrecipient VEIL_BACKUP_RETAIN="$retain" PATH="$TMP/bin:$PATH" \
    "$ROOT/scripts/db-maintenance.sh" backup "$URL" "$BACKUPS" > "$TMP/retain.out" 2>&1
  after=$(find "$BACKUPS" -maxdepth 1 -type f -name 'forum-*.dump.age' | wc -l)
  test "$after" -ge "$before" ||
    { echo "retention $retain deleted archives: $before -> $after" >&2; exit 1; }
  test "$after" -gt 0 || { echo "retention $retain left no archives" >&2; exit 1; }
done

# Minimal valid-enough package for the pre-installation verification stage.
UPGRADE="$TMP/upgrade"
mkdir -p "$UPGRADE/veil-forum-v0.1.0-alpha.19/static" "$UPGRADE/signatures"
cat > "$UPGRADE/veil-forum-v0.1.0-alpha.19/veil-forum" <<'EOF'
#!/bin/sh
case "$1" in --version) echo 'veil-forum v0.1.0-alpha.19';; esac
EOF
chmod +x "$UPGRADE/veil-forum-v0.1.0-alpha.19/veil-forum"
printf 'body{}\n' > "$UPGRADE/veil-forum-v0.1.0-alpha.19/static/style.css"
tar -czf "$UPGRADE/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz" -C "$UPGRADE" veil-forum-v0.1.0-alpha.19
cd "$UPGRADE"
sha256sum veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz > checksums.txt
for asset in veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz checksums.txt; do
  printf 'bundle\n' > "signatures/$asset.sig"
  printf 'certificate\n' > "signatures/$asset.pem"
done

if VEIL_BIN="$UPGRADE/veil-forum-v0.1.0-alpha.19/veil-forum" \
  VEIL_STATIC_DIR="$UPGRADE/veil-forum-v0.1.0-alpha.19/static" VEIL_SERVICE_MANAGER=none "$ROOT/scripts/upgrade.sh" \
  "$UPGRADE/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz" \
  --checksums "$UPGRADE/checksums.txt" --no-attestation-verify v0.1.0-alpha.19 --dry-run >/dev/null 2>&1; then
  :
else
  echo 'legacy unsigned tag escape failed' >&2; exit 1
fi

if VEIL_BIN="$UPGRADE/veil-forum-v0.1.0-alpha.19/veil-forum" \
  VEIL_STATIC_DIR="$UPGRADE/veil-forum-v0.1.0-alpha.19/static" VEIL_SERVICE_MANAGER=none "$ROOT/scripts/upgrade.sh" \
  "$UPGRADE/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz" \
  --checksums "$UPGRADE/checksums.txt" --dry-run >/dev/null 2>&1; then
  echo 'upgrade accepted a missing signature directory' >&2; exit 1
fi

rm "$UPGRADE/signatures/checksums.txt.sig"
if PATH="$TMP/bin:$PATH" COSIGN_LOG="$UPGRADE/cosign.log" "$ROOT/scripts/upgrade.sh" \
  "$UPGRADE/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz" \
  --checksums "$UPGRADE/checksums.txt" --signatures "$UPGRADE/signatures" --dry-run >/dev/null 2>&1; then
  echo 'upgrade accepted missing checksum signature material' >&2; exit 1
fi

printf 'bundle\n' > "$UPGRADE/signatures/checksums.txt.sig"
if PATH="$TMP/bin:$PATH" COSIGN_LOG="$UPGRADE/cosign.log" \
  VEIL_BIN="$UPGRADE/veil-forum-v0.1.0-alpha.19/veil-forum" \
  VEIL_STATIC_DIR="$UPGRADE/veil-forum-v0.1.0-alpha.19/static" VEIL_SERVICE_MANAGER=none "$ROOT/scripts/upgrade.sh" \
  "$UPGRADE/veil-forum-v0.1.0-alpha.19-x86_64-unknown-linux-musl.tar.gz" \
  --checksums "$UPGRADE/checksums.txt" --signatures "$UPGRADE/signatures" --dry-run >/dev/null 2>&1; then
  :
else
  echo 'upgrade rejected complete signature material' >&2; exit 1
fi
test "$(grep -c 'verify-blob' "$UPGRADE/cosign.log")" -ge 1
grep -F 'Marry102123/veil-forum/' "$UPGRADE/cosign.log" >/dev/null
grep -F 'https://token.actions.githubusercontent.com' "$UPGRADE/cosign.log" >/dev/null

echo 'script smoke tests passed'
