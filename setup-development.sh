#!/bin/bash

# Development Environment Setup for uni-evm
# Based on aggregator-go initialization procedures
#
# This script:
# 1. Initializes BFT root node (single validator for dev)
# 2. Creates trust base
# 3. Initializes uni-evm partition (partition-id 8)
# 4. Generates shard configuration
# 5. Uploads configuration to BFT Core
#
# Usage:
#   ./setup-development.sh          # Setup without cleanup
#   ./setup-development.sh --clean  # Clean and setup from scratch

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NETWORK_ID=3  # Must match genesis.json and trust base
PARTITION_ID=8
PARTITION_TYPE_ID=8
T2_TIMEOUT=900000  # 15 minutes in milliseconds (BFT Core expects milliseconds)
EPOCH_START=10

# Directories
BFT_ROOT_DIR="./bft-core/test-nodes/root1"
UNI_EVM_DIR="./test-nodes/uni-evm"
GENESIS_DIR="./test-nodes"
BFT_BUILD="./bft-core/build/ubft"

# Network configuration
ROOT_RPC_PORT=25866
ROOT_P2P_PORT=26866

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}uni-evm Development Environment Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Parse arguments
CLEAN=false
if [ "$1" == "--clean" ] || [ "$1" == "-c" ]; then
    CLEAN=true
fi

# Function: Clean existing data
clean_environment() {
    echo -e "${YELLOW}Cleaning existing environment...${NC}"

    # Stop any running processes
    pkill -f "ubft root-node" 2>/dev/null || true
    pkill -f "uni-evm" 2>/dev/null || true
    sleep 2

    # Remove directories
    rm -rf "$BFT_ROOT_DIR" 2>/dev/null || true
    rm -rf "$UNI_EVM_DIR" 2>/dev/null || true
    rm -rf ./data 2>/dev/null || true

    # Remove generated files
    rm -f "$GENESIS_DIR/trust-base.json" 2>/dev/null || true
    rm -f "$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json" 2>/dev/null || true
    rm -f "$BFT_ROOT_DIR/trust-base-signed.json" 2>/dev/null || true

    echo -e "${GREEN}✓ Environment cleaned${NC}"
    echo ""
}

# Function: Check if BFT Core is built
check_bft_build() {
    if [ ! -f "$BFT_BUILD" ]; then
        echo -e "${RED}ERROR: BFT Core binary not found at $BFT_BUILD${NC}"
        echo "Please build BFT Core first:"
        echo "  cd bft-core && make build"
        exit 1
    fi
    echo -e "${GREEN}✓ BFT Core binary found${NC}"
}

# Function: Initialize BFT root node
init_root_node() {
    echo -e "${BLUE}Step 1: Initializing BFT root node${NC}"

    if [ -f "$BFT_ROOT_DIR/node-info.json" ]; then
        echo -e "${YELLOW}Root node already initialized, skipping...${NC}"
    else
        mkdir -p "$BFT_ROOT_DIR"

        echo "  Creating root genesis..."
        $BFT_BUILD root-node init --home "$BFT_ROOT_DIR" -g

        echo -e "${GREEN}✓ Root node initialized${NC}"
    fi
    echo ""
}

# Function: Generate trust base
generate_trust_base() {
    echo -e "${BLUE}Step 2: Generating trust base${NC}"

    if [ -f "$GENESIS_DIR/trust-base.json" ]; then
        echo -e "${YELLOW}Trust base already exists, skipping...${NC}"
    else
        mkdir -p "$GENESIS_DIR"

        echo "  Generating trust base for network-id=$NETWORK_ID..."
        $BFT_BUILD trust-base generate \
            --home "$GENESIS_DIR" \
            --network-id "$NETWORK_ID" \
            --node-info "$BFT_ROOT_DIR/node-info.json"

        echo "  Signing trust base..."
        $BFT_BUILD trust-base sign \
            --home "$BFT_ROOT_DIR" \
            --trust-base "$GENESIS_DIR/trust-base.json"

        echo -e "${GREEN}✓ Trust base generated and signed${NC}"
    fi

    # Display trust base info
    if [ -f "$GENESIS_DIR/trust-base.json" ]; then
        ROOT_NODE_ID=$(grep -o '"nodeId": "[^"]*"' "$GENESIS_DIR/trust-base.json" | head -1 | cut -d'"' -f4)
        echo "  Root node ID: $ROOT_NODE_ID"
    fi
    echo ""
}

# Function: Initialize uni-evm partition node
init_uni_evm_node() {
    echo -e "${BLUE}Step 3: Initializing uni-evm partition node${NC}"

    if [ -f "$UNI_EVM_DIR/node-info.json" ]; then
        echo -e "${YELLOW}uni-evm node already initialized, skipping...${NC}"
    else
        mkdir -p "$UNI_EVM_DIR"

        echo "  Creating uni-evm shard node genesis..."
        $BFT_BUILD shard-node init --home "$UNI_EVM_DIR" --generate

        echo -e "${GREEN}✓ uni-evm node initialized${NC}"
    fi

    # Display node info
    if [ -f "$UNI_EVM_DIR/node-info.json" ]; then
        UNI_NODE_ID=$(grep -o '"nodeId": "[^"]*"' "$UNI_EVM_DIR/node-info.json" | head -1 | cut -d'"' -f4)
        UNI_SIG_KEY=$(grep -o '"signingPublicKey": "[^"]*"' "$UNI_EVM_DIR/node-info.json" | head -1 | cut -d'"' -f4)
        echo "  uni-evm node ID: $UNI_NODE_ID"
        echo "  Signing key: $UNI_SIG_KEY"
    fi
    echo ""
}

# Function: Generate shard configuration
generate_shard_config() {
    echo -e "${BLUE}Step 4: Generating shard configuration for partition $PARTITION_ID${NC}"

    SHARD_CONF_FILE="$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json"

    if [ -f "$SHARD_CONF_FILE" ]; then
        echo -e "${YELLOW}Shard configuration already exists, skipping...${NC}"
    else
        echo "  Generating configuration..."
        echo "    Partition ID: $PARTITION_ID"
        echo "    Partition Type: $PARTITION_TYPE_ID"
        echo "    T2 Timeout: $T2_TIMEOUT ms"
        echo "    Epoch Start: $EPOCH_START"

        $BFT_BUILD shard-conf generate \
            --home "$GENESIS_DIR" \
            --network-id "$NETWORK_ID" \
            --partition-id "$PARTITION_ID" \
            --partition-type-id "$PARTITION_TYPE_ID" \
            --t2-timeout "$T2_TIMEOUT" \
            --epoch-start "$EPOCH_START" \
            --node-info="$UNI_EVM_DIR/node-info.json"

        echo -e "${GREEN}✓ Shard configuration generated: $SHARD_CONF_FILE${NC}"
    fi
    echo ""
}

# Function: Create partition genesis state
create_partition_genesis() {
    echo -e "${BLUE}Step 5: Creating partition genesis state${NC}"

    if [ -f "$UNI_EVM_DIR/state.cbor" ]; then
        echo -e "${YELLOW}Genesis state already exists, skipping...${NC}"
    else
        echo "  Creating genesis state from shard configuration..."

        $BFT_BUILD shard-conf genesis \
            --home "$UNI_EVM_DIR" \
            --shard-conf "$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json"

        echo -e "${GREEN}✓ Genesis state created${NC}"
    fi
    echo ""
}

# Function: Copy configuration to root node
copy_config_to_root() {
    echo -e "${BLUE}Step 6: Copying configuration to root node${NC}"

    echo "  Copying shard-conf-${PARTITION_ID}_0.json to $BFT_ROOT_DIR/..."
    cp "$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json" "$BFT_ROOT_DIR/"

    echo "  Copying ethrex-vkey.bin to $BFT_ROOT_DIR/..."
    cp ethrex-vkey.bin "$BFT_ROOT_DIR/uni-evm-vkey.bin"

    echo -e "${GREEN}✓ Configuration copied${NC}"
    echo ""
}

# Function: Start BFT root node
start_root_node() {
    echo -e "${BLUE}Step 7: Starting BFT root node${NC}"

    # Check if already running
    if pgrep -f "ubft root-node" > /dev/null; then
        echo -e "${YELLOW}Root node already running${NC}"
        return
    fi

    echo "  Starting root node on ports:"
    echo "    P2P: $ROOT_P2P_PORT"
    echo "    RPC: $ROOT_RPC_PORT"

    # Start in background
    nohup $BFT_BUILD root-node run \
        --home "$BFT_ROOT_DIR" \
        --address "/ip4/127.0.0.1/tcp/$ROOT_P2P_PORT" \
        --trust-base "$GENESIS_DIR/trust-base.json" \
        --rpc-server-address "localhost:$ROOT_RPC_PORT" \
        --log-level INFO --log-format text --log-file bft-root.log \
        --zk-verification-enabled=true --zk-vkey-path="$BFT_ROOT_DIR/uni-evm-vkey.bin" \
        > ./bft-root.out 2>&1 &

    ROOT_PID=$!
    echo "  Root node PID: $ROOT_PID"

    # Wait for node to start
    echo -n "  Waiting for root node to be ready"
    for i in {1..30}; do
        if curl -s "http://localhost:$ROOT_RPC_PORT/api/v1/info" > /dev/null 2>&1; then
            echo ""
            echo -e "${GREEN}✓ Root node is ready${NC}"
            return
        fi
        echo -n "."
        sleep 1
    done

    echo ""
    echo -e "${RED}WARNING: Root node may not be ready yet${NC}"
    echo "Check logs: tail -f ./bft-root.log"
    echo ""
}

# Function: Upload shard configuration
upload_shard_config() {
    echo -e "${BLUE}Step 8: Uploading shard configuration to BFT Core${NC}"

    echo "  Uploading to http://localhost:$ROOT_RPC_PORT/api/v1/configurations..."

    # Wait a bit to ensure root node is fully ready
    sleep 2

    RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        -d "@$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json" \
        "http://localhost:$ROOT_RPC_PORT/api/v1/configurations")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n1)

    if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 201 ]; then
        echo -e "${GREEN}✓ Configuration uploaded successfully${NC}"
    else
        echo -e "${YELLOW}Upload response: HTTP $HTTP_CODE${NC}"
        echo "$BODY"
    fi
    echo ""
}

# Function: Display summary
display_summary() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Setup Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Configuration:"
    echo "  Network ID:       $NETWORK_ID"
    echo "  Partition ID:     $PARTITION_ID"
    echo "  Partition Type:   $PARTITION_TYPE_ID"
    echo "  T2 Timeout:       60s ($T2_TIMEOUT ms)"
    echo ""
    echo "BFT Root Node:"
    echo "  RPC:   http://localhost:$ROOT_RPC_PORT"
    echo "  P2P:   /ip4/127.0.0.1/tcp/$ROOT_P2P_PORT"
    echo "  Logs:  tail -f ./bft-root.log"
    echo ""
    echo "uni-evm Node:"
    echo "  Config: ./config.toml"
    echo "  Data:   ./data/"
    echo ""
    echo "Files Generated:"
    echo "  Trust Base:    $GENESIS_DIR/trust-base.json"
    echo "  Shard Config:  $GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json"
    echo "  Genesis State: $UNI_EVM_DIR/state.cbor"
    echo ""
    echo "Next Steps:"
    echo "  1. Update config.toml with correct partition_id and peer IDs"
    echo "  2. Build uni-evm: cargo build --release"
    echo "  3. Run uni-evm: ./target/release/uni-evm"
    echo ""
    echo "To stop root node:"
    echo "  pkill -f 'ubft root-node'"
    echo ""
}

# Main execution
main() {
    # Clean if requested
    if [ "$CLEAN" = true ]; then
        clean_environment
    fi

    # Run setup steps
    check_bft_build
    init_root_node
    generate_trust_base
    init_uni_evm_node
    generate_shard_config
    create_partition_genesis
    copy_config_to_root
    start_root_node
    upload_shard_config
    display_summary
}

# Run main
main

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Development environment is ready!${NC}"
echo -e "${BLUE}========================================${NC}"
