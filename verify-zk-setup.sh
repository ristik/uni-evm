#!/bin/bash

# Verify ZK Proving Setup
# Quick health check for ZK environment

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}ZK Proving Setup Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

ERRORS=0
WARNINGS=0

# Check 1: Rust nightly
echo -n "Checking Rust toolchain... "
if rustup show active-toolchain | grep -q nightly; then
    echo -e "${GREEN}✓ nightly${NC}"
else
    echo -e "${RED}✗ NOT nightly${NC}"
    echo "  Run: rustup override set nightly"
    ((ERRORS++))
fi

# Check 2: SP1 toolchain
echo -n "Checking SP1 toolchain... "
if command -v cargo-prove &> /dev/null; then
    SP1_VERSION=$(cargo-prove --version 2>&1 | head -1 || echo "unknown")
    echo -e "${GREEN}✓ installed${NC} ($SP1_VERSION)"
else
    echo -e "${YELLOW}⚠ not found${NC}"
    echo "  Install: curl -L https://sp1.succinctlabs.com | bash && sp1up"
    ((WARNINGS++))
fi

# Check 3: Guest program ELF
echo -n "Checking guest ELF binary... "
if [ -f "guest-program/src/sp1/out/uni-evm-sp1-elf" ]; then
    ELF_SIZE=$(du -h guest-program/src/sp1/out/uni-evm-sp1-elf | cut -f1)
    echo -e "${GREEN}✓ exists${NC} ($ELF_SIZE)"

    # Verify it's a valid ELF
    if file guest-program/src/sp1/out/uni-evm-sp1-elf | grep -q "RISC-V"; then
        echo "  Type: $(file guest-program/src/sp1/out/uni-evm-sp1-elf | cut -d: -f2 | xargs)"
    else
        echo -e "  ${RED}✗ Invalid ELF format${NC}"
        ((ERRORS++))
    fi
else
    echo -e "${RED}✗ not found${NC}"
    echo "  Build: ./setup-zk.sh"
    ((ERRORS++))
fi

# Check 4: Main binary with SP1
echo -n "Checking uni-evm binary... "
if [ -f "target/release/uni-evm" ]; then
    BINARY_SIZE=$(du -h target/release/uni-evm | cut -f1)
    echo -e "${GREEN}✓ exists${NC} ($BINARY_SIZE)"

    # Check if extract-vkey command exists (indicates SP1 feature)
    if ./target/release/uni-evm extract-vkey --help &>/dev/null; then
        echo "  Features: SP1 enabled (extract-vkey command available)"
    else
        echo -e "  ${YELLOW}⚠ SP1 features may not be compiled${NC}"
        echo "    Rebuild: cargo build --release --features sp1"
        ((WARNINGS++))
    fi
else
    echo -e "${RED}✗ not found${NC}"
    echo "  Build: cargo build --release --features sp1"
    ((ERRORS++))
fi

# Check 5: Verification key
echo -n "Checking verification key... "
if [ -f "ethrex-vkey.bin" ]; then
    VKEY_SIZE=$(du -h ethrex-vkey.bin | cut -f1)
    VKEY_HASH=$(shasum -a 256 ethrex-vkey.bin | cut -d' ' -f1 | cut -c1-16)
    echo -e "${GREEN}✓ exists${NC} ($VKEY_SIZE, hash: $VKEY_HASH...)"
else
    echo -e "${RED}✗ not found${NC}"
    echo "  Extract: cd tools/extract-vkey && cargo run --release"
    ((ERRORS++))
fi

# Check 6: Config file
echo -n "Checking config.toml... "
if [ -f "config.toml" ]; then
    PROVER_TYPE=$(grep 'prover_type = ' config.toml | cut -d'"' -f2)
    BLOCK_TIME=$(grep 'block_time_ms = ' config.toml | grep -o '[0-9]*')

    echo -e "${GREEN}✓ exists${NC}"
    echo "  prover_type: $PROVER_TYPE"
    echo "  block_time_ms: $BLOCK_TIME ($(($BLOCK_TIME / 1000))s)"

    if [ "$PROVER_TYPE" = "sp1" ]; then
        if [ "$BLOCK_TIME" -lt 60000 ]; then
            echo -e "  ${YELLOW}⚠ block_time_ms too short for SP1 proving${NC}"
            echo "    Recommended: 120000 (2 minutes) for CPU, 30000 (30s) for GPU"
            ((WARNINGS++))
        fi
    fi
else
    echo -e "${RED}✗ not found${NC}"
    echo "  Create: ./update-config.sh"
    ((ERRORS++))
fi

# Check 7: BFT Core
echo -n "Checking BFT root node... "
if pgrep -f "ubft root-node" > /dev/null; then
    echo -e "${GREEN}✓ running${NC}"

    # Check if accessible
    if curl -s http://localhost:25866/api/v1/info > /dev/null 2>&1; then
        echo "  RPC: http://localhost:25866 (accessible)"
    else
        echo -e "  ${YELLOW}⚠ RPC not accessible${NC}"
        ((WARNINGS++))
    fi
else
    echo -e "${YELLOW}⚠ not running${NC}"
    echo "  Start: ./setup-development.sh"
    ((WARNINGS++))
fi

# Check 8: Dependencies
echo -n "Checking key dependencies... "
MISSING_DEPS=()

if ! command -v cargo &> /dev/null; then
    MISSING_DEPS+=("cargo")
fi
if ! command -v cast &> /dev/null; then
    MISSING_DEPS+=("cast")
fi
if ! command -v jq &> /dev/null; then
    MISSING_DEPS+=("jq")
fi

if [ ${#MISSING_DEPS[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ all installed${NC}"
else
    echo -e "${RED}✗ missing: ${MISSING_DEPS[*]}${NC}"
    ((ERRORS++))
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Ready to run ZK tests:"
    echo "  ./test-zk.sh"
    EXIT_CODE=0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}✓ Setup complete with $WARNINGS warning(s)${NC}"
    echo ""
    echo "You can run tests, but review warnings above"
    echo "  ./test-zk.sh"
    EXIT_CODE=0
else
    echo -e "${RED}✗ Setup incomplete: $ERRORS error(s), $WARNINGS warning(s)${NC}"
    echo ""
    echo "Fix errors before running tests"
    echo ""
    echo "Quick fix:"
    echo "  ./setup-zk.sh --clean"
    EXIT_CODE=1
fi

echo ""
echo "Environment Variables:"
if [ -n "$SP1_PROVER" ]; then
    echo "  SP1_PROVER=$SP1_PROVER"
else
    echo "  SP1_PROVER=(not set, defaults to cpu)"
fi

echo ""
echo "For help:"
echo "  cat ZK_TESTING.md"
echo ""

exit $EXIT_CODE
