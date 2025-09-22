#!/bin/bash

set -euo pipefail

# the NETWORK_DIR var name must stay in sync with the local_install.sh script
NETWORK_DIR="./.devnet"

if ! goal network delete -r "${NETWORK_DIR}" >/dev/null 2>&1; then
  echo "removing manually..."
fi
rm -rf "${NETWORK_DIR}"

