#!/bin/bash
# Create shard configuration for uni-evm partition
#
# This script generates the shard configuration that registers uni-evm
# as partition_id=1 in BFT Core.
#
# Usage: ./create-uni-evm-shard-conf.sh <peer-id> <signing-pubkey> [proof-type] [chain-id] [vkey-path]
#
# Arguments:
#   peer-id       - libp2p peer ID of the uni-evm node
#   signing-pubkey - secp256k1 signing public key
#   proof-type    - (optional) sp1 | light_client | exec (default: empty = m-of-n only)
#   chain-id      - (optional) EVM chain ID for ZK verification (required for sp1/light_client)
#   vkey-path     - (optional) Path to SP1 verification key (required for sp1)

set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <uni-evm-peer-id> <signing-pubkey> [proof-type] [chain-id] [vkey-path]"
    echo "Example: $0 12D3KooWRBhwfeP92XGFRkZC4gRbCARRZv2Wm1VLwbf6bMrV9vR8 0x03abc..."
    echo "Example: $0 12D3KooW... 0x03abc... light_client 3"
    echo "Example: $0 12D3KooW... 0x03abc... sp1 3 /path/to/vkey.bin"
    exit 1
fi

PEER_ID=$1
SIGNING_PUBKEY=$2
PROOF_TYPE=${3:-""}
CHAIN_ID=${4:-""}
VKEY_PATH=${5:-""}

echo "Creating shard configuration for uni-evm partition"
echo "Peer ID: $PEER_ID"
echo "Signing Public Key: $SIGNING_PUBKEY"
echo "Proof Type: ${PROOF_TYPE:-none}"
echo "Chain ID: ${CHAIN_ID:-N/A}"
echo "VKey Path: ${VKEY_PATH:-N/A}"

# Create test-nodes directory if needed
mkdir -p test-nodes/uni-evm

# Create node-info.json for uni-evm
# This format matches BFT Core's validator node-info.json format
cat > test-nodes/uni-evm/node-info.json <<EOF
{
  "nodeId": "$PEER_ID",
  "sigKey": "$SIGNING_PUBKEY",
  "stake": 1
}
EOF

echo "Created node-info.json for uni-evm"

# Generate shard-conf for partition_id=1 (uni-evm)
cd bft-core
./build/ubft shard-conf generate \
  --home ../test-nodes \
  --network-id 3 \
  --partition-id 1 \
  --partition-type-id 1 \
  --epoch-start 0 \
  --node-info ../test-nodes/uni-evm/node-info.json
cd ..

# Inject partition params if proof_type is specified
SHARD_CONF="test-nodes/shard-conf-1_0.json"

if [ -n "$PROOF_TYPE" ]; then
    echo "Injecting partition params for ZK verification..."

    # Build partition params JSON based on proof type
    if [ "$PROOF_TYPE" = "sp1" ] && [ -n "$VKEY_PATH" ] && [ -n "$CHAIN_ID" ]; then
        PARAMS="{\"proof_type\":\"sp1\",\"vkey_path\":\"$VKEY_PATH\",\"chain_id\":\"$CHAIN_ID\"}"
    elif [ "$PROOF_TYPE" = "light_client" ] && [ -n "$CHAIN_ID" ]; then
        PARAMS="{\"proof_type\":\"light_client\",\"chain_id\":\"$CHAIN_ID\"}"
    elif [ "$PROOF_TYPE" = "exec" ]; then
        PARAMS="{\"proof_type\":\"exec\"}"
    else
        echo "Warning: Invalid proof configuration"
        echo "  - sp1 requires chain_id and vkey_path"
        echo "  - light_client requires chain_id"
        PARAMS="{\"proof_type\":\"$PROOF_TYPE\"}"
    fi

    # Merge partition params into shard-conf
    jq --argjson p "$PARAMS" '.partitionParams = $p' "$SHARD_CONF" > "${SHARD_CONF}.tmp"
    mv "${SHARD_CONF}.tmp" "$SHARD_CONF"

    echo "Added partitionParams: $PARAMS"
fi

echo "✓ Shard configuration created: $SHARD_CONF"
