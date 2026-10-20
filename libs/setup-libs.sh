#!/bin/bash
# Download and unpack the prebuilt Windows dependencies used by the Qv2ray
# Windows builds.  Keep this independent of the GitHub API: an API hiccup or
# rate limit used to leave the dependency directory empty, which later showed
# up as a confusing "Could NOT find CURL" CMake error.
set -euo pipefail

DEPS_OS=${1:?Usage: setup-libs.sh <windows> <x64>}
DEPS_CATEGORY=${2:?Usage: setup-libs.sh <windows> <x64>}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK_DIR="$SCRIPT_DIR/deps"
DOWNLOAD_DIR="$WORK_DIR/downloaded"
TARGET_DIR="$SCRIPT_DIR/${DEPS_CATEGORY}-${DEPS_OS}"
RELEASE_URL="https://github.com/Qv2ray/Qv2ray-deps/releases/download/release"

rm -rf "$WORK_DIR"
mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"

for component in curl grpc openssl; do
    NAME="${component}-${DEPS_CATEGORY}-${DEPS_OS}.7z"
    echo "Downloading: $NAME"
    curl -fL --retry 5 --retry-delay 3 --retry-all-errors "$RELEASE_URL/$NAME" -o "$NAME"
    test -s "$NAME"
    7z x -y "$NAME"
done

EXTRACTED_DIR="$DOWNLOAD_DIR/${DEPS_OS}-${DEPS_CATEGORY}"
if [ ! -d "$EXTRACTED_DIR/installed/${DEPS_CATEGORY}-${DEPS_OS}" ]; then
    echo "Dependency archive did not contain the expected ${DEPS_OS}-${DEPS_CATEGORY} layout." >&2
    exit 1
fi

echo "Installing dependencies into: $TARGET_DIR"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cp -rvf "$EXTRACTED_DIR/installed/${DEPS_CATEGORY}-${DEPS_OS}/." "$TARGET_DIR/"

# Fail at the setup step, not much later inside CMake, if an archive was
# incomplete or extraction failed.
test -s "$TARGET_DIR/include/curl/curl.h"
test -s "$TARGET_DIR/lib/libcurl.lib"
test -s "$TARGET_DIR/tools/protobuf/protoc.exe"

rm -rf "$WORK_DIR"
echo "Windows dependencies are ready."
