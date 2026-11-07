#!/bin/sh
set -eu

expected=${1:?expected kernel label required}
release=$(uname -r)
case "$expected" in
  6-12)
    case "$release" in
      6.12.*) ;;
      *) echo "expected Linux 6.12, found $release" >&2; exit 1 ;;
    esac
    ;;
  stable)
    stable_release=${2:?expected stable release (major.minor.patch) required}
    case "$stable_release" in
      *[!0-9.]*|.*|*.|*..*) echo "invalid stable release: $stable_release" >&2; exit 2 ;;
    esac
    if [ "$(printf '%s' "$stable_release" | awk -F. '{print NF}')" -ne 3 ]; then
      echo "expected major.minor.patch: $stable_release" >&2; exit 2
    fi
    case "$release" in
      "$stable_release"|"$stable_release"-*) ;;
      *) echo "expected Linux $stable_release, found $release" >&2; exit 1 ;;
    esac
    major=$(printf '%s' "$release" | cut -d. -f1)
    minor=$(printf '%s' "$release" | cut -d. -f2)
    if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 12 ]; }; then
      echo "expected latest stable Linux >= 6.12, found $release" >&2
      exit 1
    fi
    ;;
  *) echo "unknown kernel label: $expected" >&2; exit 2 ;;
esac
printf 'Kernel matrix runner: %s (%s)\n' "$expected" "$release"
