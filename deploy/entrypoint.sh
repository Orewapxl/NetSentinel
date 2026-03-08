#!/usr/bin/env sh
set -eu

mkdir -p "${NETSENTINEL_DATA_DIR:-/app/data}" "${NETSENTINEL_RUNTIME_DIR:-/app/data/runtime}"

DEFAULT_INTEL_SOURCE="/app/app/defaults/threat_intel.csv"
TARGET_INTEL="${NETSENTINEL_THREAT_INTEL_CSV:-/app/data/threat_intel.csv}"

if [ ! -f "$TARGET_INTEL" ] && [ -f "$DEFAULT_INTEL_SOURCE" ]; then
  cp "$DEFAULT_INTEL_SOURCE" "$TARGET_INTEL"
fi

exec "$@"
