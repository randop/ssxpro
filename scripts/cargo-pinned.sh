#!/bin/sh
set -eu

# boring-sys honors external BORING_BSSL_* environment overrides. Release and
# CI builds use the version pinned by boring-sys instead of a host installation.
# Reject target-specific source overrides before Cargo can consume them.
if env | LC_ALL=C grep -E '^BORING_BSSL_(PATH|SOURCE_PATH|INCLUDE_PATH|PRECOMPILED_BCM_O|ASSUME_PATCHED)_.+=' >/dev/null; then
  echo 'target-specific BoringSSL overrides are not supported' >&2
  exit 1
fi
exec env \
  -u BORING_BSSL_PATH \
  -u BORING_BSSL_PATH_x86_64-unknown-linux-gnu \
  -u BORING_BSSL_PATH_x86_64_unknown_linux_gnu \
  -u HOST_BORING_BSSL_PATH \
  -u TARGET_BORING_BSSL_PATH \
  -u HOST_BORING_BSSL_SOURCE_PATH \
  -u TARGET_BORING_BSSL_SOURCE_PATH \
  -u HOST_BORING_BSSL_INCLUDE_PATH \
  -u TARGET_BORING_BSSL_INCLUDE_PATH \
  -u HOST_BORING_BSSL_PRECOMPILED_BCM_O \
  -u TARGET_BORING_BSSL_PRECOMPILED_BCM_O \
  -u HOST_BORING_BSSL_ASSUME_PATCHED \
  -u TARGET_BORING_BSSL_ASSUME_PATCHED \
  -u BORING_BSSL_SOURCE_PATH \
  -u BORING_BSSL_INCLUDE_PATH \
  -u BORING_BSSL_PRECOMPILED_BCM_O \
  -u BORING_BSSL_ASSUME_PATCHED \
  cargo "$@"
