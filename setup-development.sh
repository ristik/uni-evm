#!/usr/bin/env bash

# ------------------------------------------------------------
# uni‑evm Development Environment Setup
# ------------------------------------------------------------
# 1. Init BFT root node (single validator)
# 2. Generate & sign trust base
# 3. Init the uni‑evm shard node
# 4. Build a shard‑conf JSON with optional ZK‑proof settings
# 5. Create the partition genesis state
# 6. Copy config to the root node, start it and upload the shard‑conf
#
# Usage:
#   ./setup-development.sh          # normal run
#   ./setup-development.sh --clean  # wipe everything first
#
# ------------------------------------------------------------

# ---- Bash safety -------------------------------------------------
set -euo pipefail               # abort on any error / undefined var / pipeline failure
IFS=$'\n\t'                    # sane word splitting

# ---- Colours (optional, keep for pretty output) ------------------
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
BLUE=$(printf '\033[0;34m')
YELLOW=$(printf '\033[1;33m')
NC=$(printf '\033[0m')         # No Colour

# ---- Configuration ------------------------------------------------
NETWORK_ID=3                     # must match genesis.json & trust‑base
PARTITION_ID=8
PARTITION_TYPE_ID=8
T2_TIMEOUT_MS=900000            # 15 min in ms (BFT Core expects ms)
EPOCH_START=10

PROOF_TYPE="light_client"       # "" | sp1 | light_client | exec
VKEY_PATH=""                    # required only for sp1, e.g. /etc/bft-core/uni‑evm-vkey.bin

# Paths (relative to repo root)
BFT_ROOT_DIR="./bft-core/test-nodes/root1"
UNI_EVM_DIR="./test-nodes/uni-evm"
GENESIS_DIR="./test-nodes"
BFT_BUILD="./bft-core/build/ubft"

ROOT_RPC_PORT=25866
ROOT_P2P_PORT=26866

# ---- Helper: pretty‑print a step header -------------------------
step() {
    echo -e "${BLUE}=== $* ===${NC}"
}

# ---- Argument parsing ---------------------------------------------
CLEAN=false
if [[ ${1:-} == "--clean" || ${1:-} == "-c" ]]; then
    CLEAN=true
fi

clean_environment() {
    step "Cleaning existing environment"

    # Kill any leftover processes (fail‑safe, ignore “not found” errors)
    pkill -f "ubft root-node" || true
    pkill -f "uni-evm"       || true
    sleep 1

    # Remove generated dirs / files
    rm -rf "$BFT_ROOT_DIR" "$UNI_EVM_DIR" ./data \
           "$GENESIS_DIR/trust-base.json" \
           "$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json" \
           "$BFT_ROOT_DIR/trust-base-signed.json"
    echo -e "${GREEN}✓ cleaned${NC}"
}

check_bft_build() {
    step "Checking BFT Core build"

    if [[ ! -x $BFT_BUILD ]]; then
        echo -e "${RED}ERROR:${NC} BFT binary not found at $BFT_BUILD"
        echo "Build it first:"
        echo "  cd bft-core && make build-with-ffi"
        exit 1
    fi
    echo -e "${GREEN}✓ $BFT_BUILD is present${NC}"
}

init_root_node() {
    step "Initialising BFT root node"

    if [[ -f "$BFT_ROOT_DIR/node-info.json" ]]; then
        echo -e "${YELLOW}Root already initialised → skip${NC}"
        return
    fi

    mkdir -p "$BFT_ROOT_DIR"
    $BFT_BUILD root-node init --home "$BFT_ROOT_DIR" -g
    echo -e "${GREEN}✓ root node ready${NC}"
}

generate_trust_base() {
    step "Generating trust‑base"

    if [[ -f "$GENESIS_DIR/trust-base.json" ]]; then
        echo -e "${YELLOW}trust‑base already exists → skip${NC}"
        return
    fi

    mkdir -p "$GENESIS_DIR"
    $BFT_BUILD trust-base generate \
        --home "$GENESIS_DIR" \
        --network-id "$NETWORK_ID" \
        --node-info "$BFT_ROOT_DIR/node-info.json"

    $BFT_BUILD trust-base sign \
        --home "$BFT_ROOT_DIR" \
        --trust-base "$GENESIS_DIR/trust-base.json"

    echo -e "${GREEN}✓ trust‑base generated & signed${NC}"
}

init_uni_evm_node() {
    step "Initialising uni‑evm shard node"

    if [[ -f "$UNI_EVM_DIR/node-info.json" ]]; then
        echo -e "${YELLOW}uni‑evm already initialised → skip${NC}"
        return
    fi

    mkdir -p "$UNI_EVM_DIR"
    $BFT_BUILD shard-node init --home "$UNI_EVM_DIR" --generate
    echo -e "${GREEN}✓ uni‑evm node ready${NC}"
}

inject_partition_params() {
    local json_file=$1   # path to the just‑created shard‑conf.json
    local proof_type=$2
    local vkey_path=$3

    if [[ -z $proof_type ]]; then
        echo "  Proof type: (none – m‑of‑n only)"
        return
    fi

    echo "  Proof type: $proof_type"
    # Build a tiny JSON snippet that we will merge into the shard‑conf
    local params="{\"proof_type\":\"$proof_type\"}"
    [[ $proof_type == sp1 && -n $vkey_path ]] && params="{\"proof_type\":\"sp1\",\"vkey_path\":\"$vkey_path\"}"

    # jq merges the new object under .partitionParams
    jq --argjson p "$params" '.partitionParams = $p' "$json_file" > "${json_file}.tmp"
    mv "${json_file}.tmp" "$json_file"
}

generate_shard_config() {
    step "Generating shard‑conf for partition $PARTITION_ID"

    local conf="$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json"
    if [[ -f $conf ]]; then
        echo -e "${YELLOW}shard‑conf already exists → skip${NC}"
        return
    fi

    $BFT_BUILD shard-conf generate \
        --home "$GENESIS_DIR" \
        --network-id "$NETWORK_ID" \
        --partition-id "$PARTITION_ID" \
        --partition-type-id "$PARTITION_TYPE_ID" \
        --t2-timeout "$T2_TIMEOUT_MS" \
        --epoch-start "$EPOCH_START" \
        --node-info "$UNI_EVM_DIR/node-info.json"

    inject_partition_params "$conf" "$PROOF_TYPE" "$VKEY_PATH"
    echo -e "${GREEN}✓ shard‑conf written to $conf${NC}"
}

create_partition_genesis() {
    step "Creating partition genesis state"

    if [[ -f "$UNI_EVM_DIR/state.cbor" ]]; then
        echo -e "${YELLOW}state.cbor already exists → skip${NC}"
        return
    fi

    $BFT_BUILD shard-conf genesis \
        --home "$UNI_EVM_DIR" \
        --shard-conf "$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json"

    echo -e "${GREEN}✓ state.cbor created${NC}"
}

copy_config_to_root() {
    step "Copying shard‑conf (and optional vkey) to root node"

    cp "$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json" "$BFT_ROOT_DIR/"

    if [[ $PROOF_TYPE == sp1 && -f ethrex-vkey.bin ]]; then
        cp ethrex-vkey.bin "$BFT_ROOT_DIR/uni-evm-vkey.bin"
    fi
}

start_root_node() {
    step "Starting BFT root node (background)"

    # If already running, just return – useful for re‑runs after `--clean`
    if pgrep -f "ubft root-node" > /dev/null; then
        echo -e "${YELLOW}Root node already running${NC}"
        return
    fi

    nohup $BFT_BUILD root-node run \
        --home "$BFT_ROOT_DIR" \
        --address "/ip4/127.0.0.1/tcp/$ROOT_P2P_PORT" \
        --trust-base "$GENESIS_DIR/trust-base.json" \
        --rpc-server-address "localhost:$ROOT_RPC_PORT" \
        --log-level DEBUG --log-format text --log-file bft-root.log \
        > ./bft-root.out 2>&1 &

    local pid=$!
    echo "  PID = $pid"

    # Wait until the RPC endpoint answers (max 30 s)
    for i in {1..30}; do
        if curl -s "http://localhost:$ROOT_RPC_PORT/api/v1/info" > /dev/null; then
            echo -e "${GREEN}✓ root node ready${NC}"
            return
        fi
        sleep 1
    done

    echo -e "${RED}WARNING:${NC} root node did not answer within 30 s"
    echo "Check the log: tail -f ./bft-root.log"
}

upload_shard_config() {
    step "Uploading shard‑conf to BFT Core"

    # Small pause – ensures the RPC server is fully up
    sleep 2

    local url="http://localhost:$ROOT_RPC_PORT/api/v1/configurations"
    local resp=$(curl -s -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        -d "@$GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json" "$url")

    local body=${resp%?*}
    local code=${resp##*$'\n'}

    if (( code == 200 || code == 201 )); then
        echo -e "${GREEN}✓ uploaded (HTTP $code)${NC}"
    else
        echo -e "${YELLOW}Upload failed – HTTP $code${NC}"
        echo "$body"
    fi
}

display_summary() {
    step "Setup complete"

    local root_peer=$(jq -r '.rootNodes[0].nodeId' "$GENESIS_DIR/trust-base.json")
    local evm_peer=$(jq -r '.nodeId' "$UNI_EVM_DIR/node-info.json")

    cat <<EOF
${GREEN}Configuration:${NC}
  Network ID      : $NETWORK_ID
  Partition ID    : $PARTITION_ID
  Partition Type  : $PARTITION_TYPE_ID
  T2 timeout      : $(($T2_TIMEOUT_MS/60000))m ($T2_TIMEOUT_MS ms)
  Proof type      : ${PROOF_TYPE:-none}
  Vkey path       : ${VKEY_PATH:-N/A}

${BLUE}Peer IDs (copy into config.toml):${NC}
  Root node   : $root_peer
  uni‑evm     : $evm_peer

BFT root RPC    : http://localhost:$ROOT_RPC_PORT
Root P2P address: /ip4/127.0.0.1/tcp/$ROOT_P2P_PORT

Generated files:
  $GENESIS_DIR/trust-base.json
  $GENESIS_DIR/shard-conf-${PARTITION_ID}_0.json
  $UNI_EVM_DIR/state.cbor

Next steps (quick cheat‑sheet):
  1. Update ./config.toml with the peer IDs above.
  2. Build uni‑evm:   cargo build --release
  3. Run uni‑evm:    ./target/release/uni-evm
  4. Stop root node: pkill -f "ubft root-node"
EOF
}

if $CLEAN; then clean_environment; fi
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