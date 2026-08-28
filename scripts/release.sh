#!/bin/sh
# veil-forum release packaging script.
#
# Usage:
#   scripts/release.sh [VERSION]
#
# Builds the release binary, stages the archive directory, and produces:
#   dist/veil-forum-v<VERSION>-<target>.tar.gz
#   dist/veil-forum-v<VERSION>-checksums.txt
#
# Run from the repository root. Requires cargo and sha256sum.
set -eu

VERSION="${1:-}"
if [ -z "${VERSION}" ]; then
    VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
fi
TARGET="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p' || true)"
[ -n "${TARGET}" ] || TARGET="x86_64-unknown-linux-gnu"

BIN_NAME="veil-forum"
DIR_NAME="${BIN_NAME}-v${VERSION}-${TARGET}"
DIST_DIR="dist"
STAGE="${DIST_DIR}/${DIR_NAME}"
ARCHIVE="${DIST_DIR}/${DIR_NAME}.tar.gz"
CHECKSUMS="${DIST_DIR}/${BIN_NAME}-v${VERSION}-checksums.txt"

rm -rf "${STAGE}"
mkdir -p "${STAGE}/docs" "${STAGE}/deploy"

cargo build --release

cp "target/release/${BIN_NAME}" "${STAGE}/${BIN_NAME}"
cp README.md LICENSE CHANGELOG.md "${STAGE}/"
cp docs/*.md "${STAGE}/docs/"
cp deploy/*.service "${STAGE}/deploy/"

cd "${DIST_DIR}"
tar -czf "${DIR_NAME}.tar.gz" "${DIR_NAME}"
(
    cd "${DIR_NAME}"
    sha256sum "${BIN_NAME}" README.md LICENSE CHANGELOG.md docs/*.md deploy/*.service
) > "${CHECKSUMS}"
cd ..

echo "Archive:   ${ARCHIVE}"
echo "Checksums: ${CHECKSUMS}"
