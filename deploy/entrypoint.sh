#!/usr/bin/env sh
set -eu

mkdir -p "${NETSENTINEL_DATA_DIR:-/app/data}" "${NETSENTINEL_RUNTIME_DIR:-/app/data/runtime}"

if [ ! -f "${NETSENTINEL_THREAT_INTEL_CSV:-/app/data/threat_intel.csv}" ] && [ -f /app/data/threat_intel.csv ]; then
  cp /app/data/threat_intel.csv "${NETSENTINEL_THREAT_INTEL_CSV:-/app/data/threat_intel.csv}" || true
fi

exec "$@"
