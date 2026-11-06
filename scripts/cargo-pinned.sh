#!/bin/sh
set -eu

# boring-sys honors external BORING_BSSL_* environment overrides. Release and
# CI builds use the version pinned by boring-sys instead of a host installation.
exec env \
  -u BORING_BSSL_PATH \
  -u BORING_BSSL_PATH_x86_64-unknown-linux-gnu \
  -u BORING_BSSL_PATH_x86_64_unknown_linux_gnu \
  -u HOST_BORING_BSSL_PATH \
  -u BORING_BSSL_SOURCE_PATH \
  -u BORING_BSSL_INCLUDE_PATH \
  -u BORING_BSSL_PRECOMPILED_BCM_O \
  -u BORING_BSSL_ASSUME_PATCHED \
  cargo "$@"
