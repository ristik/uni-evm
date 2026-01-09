#!/bin/bash
# Create shard configuration for uni-evm partition
#
# This script generates the shard configuration that registers uni-evm
# as partition_id=1 in BFT Core.
#
# Usage: ./create-uni-evm-shard-conf.sh <peer-id> <signing-pubkey>

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <uni-evm-peer-id> <signing-pubkey>"
    echo "Example: $0 12D3KooWRBhwfeP92XGFRkZC4gRbCARRZv2Wm1VLwbf6bMrV9vR8 0x03abc..."
    exit 1
fi

PEER_ID=$1
SIGNING_PUBKEY=$2

echo "Creating shard configuration for uni-evm partition"
echo "Peer ID: $PEER_ID"
echo "Signing Public Key: $SIGNING_PUBKEY"

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
  --epoch-start 1 \
  --node-info ../test-nodes/uni-evm/node-info.json

echo "✓ Shard configuration created: test-nodes/shard-conf-1_0.json"
cd ..
