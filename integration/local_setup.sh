#!/bin/bash

set -euo pipefail

# the NETWORK_DIR var name must stay in sync with the local_teardown.sh script
NETWORK_DIR="./.devnet"
NODE_DIR="${NETWORK_DIR}/node1"
NETWORK_SPEC="$(mktemp -t falcon_devnet_template.json)"
NODE_CONFIG="${NETWORK_DIR}/node1/config.json"

trap 'rm -f "${NETWORK_SPEC}"' EXIT

# Delete the working directory if it exists
if [ -d "${NETWORK_DIR}" ]; then
  echo "Directory ${NETWORK_DIR} exists. Deleting it..."
  if ! goal network delete -r "${NETWORK_DIR}" >/dev/null 2>&1; then
    echo "removing manually..."
  fi
  rm -rf "${NETWORK_DIR}"
fi

# Change DevMode to false if you're doing consensus-related tests
echo '{"Genesis":{"NetworkName":"devnet","ConsensusProtocol":"future","LastPartKeyRound":2000,"Wallets":[{"Name":"Wallet1","Stake":100,"Online":true}],"DevMode":true},"Nodes":[{"Name":"node1","Wallets":[{"Name":"Wallet1"}]}]}' > "${NETWORK_SPEC}"

goal network create -t "${NETWORK_SPEC}" -r "${NETWORK_DIR}"
rm -f "${NETWORK_SPEC}"

# Restart kmd with no timeout
goal kmd stop -d "${NODE_DIR}"
goal kmd start -d "${NODE_DIR}"

# Enable the developer API to compile teal in the config file of the main node
echo '{"EnableDeveloperAPI":true,"EnableExperimentalAPI":true}' > "${NODE_CONFIG}"

goal network start -r "${NETWORK_DIR}"

# Set environment variables for the node
export ALGORAND_DATA="${NODE_DIR}"
export ALGOD_URL="http://$(cat "${NODE_DIR}/algod.net")"
export ALGOD_TOKEN="$(cat "${NODE_DIR}/algod.token")"
export KMD_URL="http://$(cat "${NODE_DIR}/kmd-v0.5/kmd.net")"
export KMD_TOKEN="$(cat "${NODE_DIR}/kmd-v0.5/kmd.token")"
