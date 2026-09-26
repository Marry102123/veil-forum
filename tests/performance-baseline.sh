#!/bin/sh
# Small, dependency-free HTTP latency baseline for a running veil-forum instance.
# It measures public/real HTTP entry points only and never records request bodies,
# cookies, headers, or credentials. Run against a disposable deployment.
#
#   BASE_URL=http://127.0.0.1:8001 tests/performance-baseline.sh
#   REPEATS=20 tests/performance-baseline.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE_URL=${BASE_URL:-http://127.0.0.1:8001}
REPEATS=${REPEATS:-10}
case "$REPEATS" in
  ''|*[!0-9]*) echo 'error: REPEATS must be a positive integer' >&2; exit 1 ;;
esac
[ "$REPEATS" -gt 0 ] || { echo 'error: REPEATS must be positive' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'error: curl is required' >&2; exit 1; }
command -v awk >/dev/null 2>&1 || { echo 'error: awk is required' >&2; exit 1; }

REPORT="$ROOT/target/performance-baseline-report.json"
mkdir -p "$ROOT/target"
TMP=$(mktemp)

# Keep paths fixed and credential-free. Login failure is deliberately a GET to
# its public form; CSRF/Origin and secrets are covered by the security E2E suites.
# Results are appended one per line to a separate file, so a partially written
# buffer can never produce a broken JSON report.
measure() {
  label=$1
  path=$2
  : > "$TMP"
  i=1
  while [ "$i" -le "$REPEATS" ]; do
    curl --fail --silent --show-error --output /dev/null \
      --write-out '%{time_total}\n' "$BASE_URL$path" >> "$TMP" || return 1
    i=$((i + 1))
  done
  awk -v label="$label" -v repeats="$REPEATS" '
    { sum+=$1; if (min==0 || $1<min) min=$1; if ($1>max) max=$1 }
    END {
      if (NR == 0) exit 1
      printf "%s\t%d\t%.6f\t%.6f\t%.6f\n", label, repeats, sum/NR, min, max
    }
  ' "$TMP"
}

RESULTS=$(mktemp)
cleanup() { rm -f "$TMP" "$RESULTS"; }
trap cleanup EXIT HUP INT TERM

write_report() {
  result=passed
  [ "${1:-0}" -eq 0 ] || result=failed
  {
    printf '{\n  "schema_version": 1,\n  "test": "http_latency_baseline",\n  "base_url": "%s",\n  "repeats": %s,\n  "result": "%s",\n  "results": [\n' "$BASE_URL" "$REPEATS" "$result"
    awk -F '\t' '
      BEGIN { first = 1 }
      {
        line = "    {\"path\":\"" $1 "\",\"samples\":" $2 ",\"mean_seconds\":" $3 ",\"min_seconds\":" $4 ",\"max_seconds\":" $5 "}"
        if (!first) printf ",\n"
        printf "%s", line
        first = 0
      }
      END { if (!first) printf "\n" }
    ' "$RESULTS"
    printf '  ],\n  "credentials_included": false,\n  "reproduce_command": "BASE_URL=<test-url> REPEATS=<count> tests/performance-baseline.sh"\n}\n'
  } > "$REPORT.tmp"
  mv "$REPORT.tmp" "$REPORT"
}

status=0
for spec in 'health /healthz' 'home /' 'login_failure /login' 'search /search?q=veil'; do
  label=${spec%% *}
  path=${spec#* }
  if result=$(measure "$label" "$path"); then
    printf '%s\n' "$result" >> "$RESULTS"
  else
    printf 'measurement failed for %s\n' "$label" >&2
    status=1
  fi
done
write_report "$status"
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
printf 'performance baseline passed; report: %s\n' "$REPORT"
