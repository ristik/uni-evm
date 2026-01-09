#!/bin/bash

# Verify Development Environment Setup
# Checks that all components are correctly configured

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Verifying uni-evm Development Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

ERRORS=0

# Check 1: Required files exist
echo -e "${BLUE}1. Checking required files...${NC}"

check_file() {
    if [ -f "$1" ]; then
        echo -e "  ${GREEN}✓${NC} $1"
    else
        echo -e "  ${RED}✗${NC} $1 (MISSING)"
        ((ERRORS++))
    fi
}

check_file "./bft-core/test-nodes/root1/node-info.json"
check_file "./bft-core/test-nodes/root1/keys.json"
check_file "./test-nodes/trust-base.json"
check_file "./test-nodes/uni-evm/node-info.json"
check_file "./test-nodes/uni-evm/keys.json"
check_file "./test-nodes/shard-conf-8_0.json"
check_file "./config.toml"
check_file "./keys/signing.key"

echo ""

# Check 2: Network ID consistency
echo -e "${BLUE}2. Checking network ID consistency...${NC}"

TRUST_BASE_NETWORK_ID=$(grep -o '"networkId": [0-9]*' ./test-nodes/trust-base.json | head -1 | cut -d' ' -f2)
SHARD_CONF_NETWORK_ID=$(grep -o '"networkId": [0-9]*' ./test-nodes/shard-conf-8_0.json | head -1 | cut -d' ' -f2)

echo "  Trust base network ID: $TRUST_BASE_NETWORK_ID"
echo "  Shard config network ID: $SHARD_CONF_NETWORK_ID"

if [ "$TRUST_BASE_NETWORK_ID" = "$SHARD_CONF_NETWORK_ID" ]; then
    echo -e "  ${GREEN}✓${NC} Network IDs match"
else
    echo -e "  ${RED}✗${NC} Network IDs mismatch!"
    ((ERRORS++))
fi

echo ""

# Check 3: Node ID consistency
echo -e "${BLUE}3. Checking node ID consistency...${NC}"

UNI_NODE_ID=$(grep -o '"nodeId": "[^"]*"' ./test-nodes/uni-evm/node-info.json | head -1 | cut -d'"' -f4)
SHARD_VALIDATOR_NODE_ID=$(grep -o '"nodeId": "[^"]*"' ./test-nodes/shard-conf-8_0.json | grep -v "validators" | head -1 | cut -d'"' -f4)
CONFIG_NODE_ID=$(grep 'node_id =' ./config.toml | cut -d'"' -f2)

echo "  uni-evm node-info.json:  $UNI_NODE_ID"
echo "  Shard config validator:  $SHARD_VALIDATOR_NODE_ID"
echo "  config.toml:             $CONFIG_NODE_ID"

if [ "$UNI_NODE_ID" = "$SHARD_VALIDATOR_NODE_ID" ] && [ "$UNI_NODE_ID" = "$CONFIG_NODE_ID" ]; then
    echo -e "  ${GREEN}✓${NC} Node IDs match"
else
    echo -e "  ${RED}✗${NC} Node IDs mismatch!"
    echo ""
    echo "  This will cause 'node is not in trustbase' errors!"
    echo "  Fix: Run ./update-config.sh to regenerate config.toml"
    ((ERRORS++))
fi

echo ""

# Check 4: Signing key consistency
echo -e "${BLUE}4. Checking signing key consistency...${NC}"

UNI_SIG_KEY=$(grep -o '"sigKey": "[^"]*"' ./test-nodes/uni-evm/node-info.json | head -1 | cut -d'"' -f4)
SHARD_SIG_KEY=$(grep -o '"sigKey": "[^"]*"' ./test-nodes/shard-conf-8_0.json | grep -v "validators" | head -1 | cut -d'"' -f4)

echo "  uni-evm node-info.json: $UNI_SIG_KEY"
echo "  Shard config validator: $SHARD_SIG_KEY"

if [ "$UNI_SIG_KEY" = "$SHARD_SIG_KEY" ]; then
    echo -e "  ${GREEN}✓${NC} Signing keys match"
else
    echo -e "  ${RED}✗${NC} Signing keys mismatch!"
    ((ERRORS++))
fi

echo ""

# Check 5: BFT Core running
echo -e "${BLUE}5. Checking BFT Core status...${NC}"

if pgrep -f "ubft root-node" > /dev/null; then
    echo -e "  ${GREEN}✓${NC} BFT Core root node is running"

    # Try to query the API
    if curl -s "http://localhost:25866/api/v1/info" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} BFT Core API is responsive"
    else
        echo -e "  ${YELLOW}⚠${NC}  BFT Core API not responding on port 25866"
    fi
else
    echo -e "  ${YELLOW}⚠${NC}  BFT Core root node is not running"
    echo "     Start it with: ./setup-development.sh (without --clean)"
fi

echo ""

# Check 6: Partition registration
echo -e "${BLUE}6. Checking partition registration with BFT Core...${NC}"

if pgrep -f "ubft root-node" > /dev/null; then
    # Give it a moment to ensure shard config was uploaded
    sleep 1

    # Try to fetch partition info (this endpoint may not exist, so we'll check logs instead)
    echo "  Check BFT Core logs for partition 8 registration:"
    echo "    tail -f ./bft-root.log | grep 'partition 8\\|shard.*8'"
else
    echo -e "  ${YELLOW}⚠${NC}  Cannot check - BFT Core not running"
fi

echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Your development environment is correctly configured."
    echo ""
    echo "Next steps:"
    echo "  1. Build uni-evm: cargo build --release"
    echo "  2. Run uni-evm: ./target/release/uni-evm"
else
    echo -e "${RED}✗ Found $ERRORS error(s)${NC}"
    echo ""
    echo "Please fix the errors above before running uni-evm."
    echo ""
    echo "Common fixes:"
    echo "  - Node ID mismatch: Run ./update-config.sh"
    echo "  - Missing files: Run ./setup-development.sh --clean"
    echo "  - Network ID mismatch: Run ./setup-development.sh --clean"
fi
echo -e "${BLUE}========================================${NC}"

exit $ERRORS
