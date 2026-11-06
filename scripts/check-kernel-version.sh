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
