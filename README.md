# Uni-EVM L2

An EVM L2 blockchain that uses [Unicity BFT Core](https://github.com/unicitynetwork/bft-core/tree/l1) as L1.

Communications and consensus model by https://github.com/unicitynetwork/specs/blob/main/bft-core-spec/unicity-bft-core.pdf

Built on [ethrex](https://github.com/lambdaclass/ethrex) EVM.

## Repos:

Main: https://github.com/ristik/uni-evm
BFT Core (proof verification) https://github.com/unicitynetwork/bft-core/tree/l1
bft-go-base needs some limits adjusted: https://github.com/unicitynetwork/bft-go-base/tree/l2
ethrex (state rollback, builtins): https://github.com/ristik/ethrex/tree/uni-evm

Design: https://github.com/unicitynetwork/specs/blob/main/evm/uni-evm.pdf


## What It Does

**Full EVM blockchain** with:
- **EVM execution** - Complete smart contract support (ethrex VM)
- **State management** - MPT state trie, accounts, storage (ethrex storage)
- **Validation modes**
    - **zkVM guest verifier** - SP1 proofs for every block (ethrex-prover)
    - **L1 Light Client validation** - L1 as stateless light client with full block validation
    - **L2 Majority Voting** - L2 honest majority assumption tx validation (BFT Core's default)
- **JSON-RPC API** - 18 standard RPC endpoints
- **Block production** - Automatic sequencing with configurable block time
- **L1 finality** - Each block synchronously certified by Unicity BFT Core consensus
- **UC verification** - Custom precompile for Unicity Certificate validation, trust anchor to validate Unicity L3 artefacts
- **Flexible proving modes** - Choose between exec (testing), light_client (development), or sp1 (production)

## Key Differences from ethrex L2

**What we changed:**

| Component | ethrex L2 | uni-evm |
|-----------|-----------|---------|
| **L1 Integration** | Ethereum (RPC/RLP) | BFT Core (libp2p/CBOR) |
| **Proving Strategy** | Batch multiple blocks | Prove each block synchronously |
| **Proof Format** | Compressed or Groth16 | Compressed only (no wrapping) |
| **Network Mode** | P2P sync with multiple nodes | Single sequencer node |
| **RPC Server** | Full P2P dependencies | Reduced, no sync/peers |
| **Gas Estimation** | Committed state only | Applies pending transactions |
| **Precompiles** | Standard EVM set | + UC verifier at 0x100 |
| **Finality** | Standard rollup soft finality | Strong finality |

**Why these changes:**
- BFT Core is not Ethereum → custom CBOR/libp2p integration
- BFT Core verifies SP1 natively → no Groth16 wrapping needed, other proofs possible
- Single sequencer design → simplified architecture
- User experience → pending state for consecutive transactions, smooths up longer wait until real finality

## Quick Start

### Prerequisites

```bash
# Required: Rust nightly (ethrex uses let_chains)
rustup override set nightly

# Optional: SP1 for real proofs (or use exec mode for testing)
curl -L https://sp1.succinctlabs.com | bash
sp1up
```

### Build & Run

```bash
# Build
cargo build --release --features sp1

# Configure (optional)
cp config.toml.example config.toml
vim config.toml  # Set prover_type = "exec" for testing without proofs

# Run
cargo run --release
```

RPC server starts at `http://localhost:8545`

### Test

```bash
# Basic RPC
cast chain-id --rpc-url http://localhost:8545
cast block-number --rpc-url http://localhost:8545

# Send transaction
cast send 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --value 0.1ether \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --rpc-url http://localhost:8545 \
  --async  # use async if proving is enabled

# Test consecutive transactions (pending state fix)
./test-pending-state.sh
```

## Proving Modes

Uni-EVM supports three proving modes optimized for different use cases:

### 1. Exec Mode (Testing)
```toml
[prover]
prover_type = "exec"
```
- **Proof**: Dummy 4-byte payload
- **Time**: Instant
- **Use case**: Unit tests, CI/CD
- **L1 behavior**: Accepts dummy proofs (not for production)

### 2. Light Client Mode (Development) ⚡ NEW
```toml
[prover]
prover_type = "light_client"
```
- **Proof**: Full witness (~1-5MB)
- **Time**: ~1 second
- **Use case**: Low latency (fast finality), limited total throughput
- **L1 behavior**: Executes validation logic directly
- **Speed**: much faster than SP1 mode
- **Security**: Cryptographically secure without depending on bleeding edge ZK tech

See [LIGHT_CLIENT_MODE.md](LIGHT_CLIENT_MODE.md) for details.

### 3. SP1 Mode (Production)
```toml
[prover]
prover_type = "sp1"
```
- **Proof**: SP1 STARK (~50KB compressed)
- **Time**: 5+ minutes (CPU), 10-30s (GPU)
- **Use case**: Production deployments
- **L1 behavior**: Verifies STARK proof
- **Security**: Succinct, cryptographically secure

### Comparison

| Mode | Time | Proof Size | Use Case |
|------|------|-----------|----------|
| exec | instant | 4 B | Testing |
| **light_client** | **~1s** | **~1-5MB** | Small scale |
| sp1 | 5+ min | 1.5MB | Production |

### Switching Modes

No code changes needed - just update config:
```bash
# For fast development iteration
vim config.toml  # Set prover_type = "light_client"
cargo run --release

# For production deployment
vim config.toml  # Set prover_type = "sp1"
cargo run --release
```

## Project Structure

```
uni-evm/
├── ethrex/                      # Fork of lambdaclass/ethrex (separate repo)
│   ├── crates/vm/              # EVM execution
│   ├── crates/storage/         # State management
│   ├── crates/blockchain/      # Block validation
│   └── crates/prover/          # SP1 proof generation
│
├── crates/                      # Our custom code
│   ├── uni-bft-committer/      # L1 integration (libp2p/CBOR)
│   ├── uni-sequencer/          # Block producer + proof coordinator
│   ├── uni-bft-precompile/     # UC verification precompile
│   └── uni-storage/            # Simplified storage (UCs + proofs)
│
├── cmd/uni-evm/
│   └── src/
│       ├── main.rs             # Node orchestration
│       ├── rpc.rs              # RPC services
│       ├── pending_state.rs    # Gas estimation with pending txs
│       ├── config.rs           # Configuration
│       └── keys.rs             # BFT Core signing keys
│
├── config.toml.example         # Example configuration
├── genesis.json                # Genesis block (minimal post-merge)
└── *.sh                        # Test and setup scripts
```

## Configuration

```toml
[network]
chain_id = 1
genesis_file_path = "./genesis.json"

[sequencer]
block_time_ms = 5000           # 5s for collecting txs ("t1 time")
gas_limit = 30000000

[rpc]
http_addr = "127.0.0.1"
http_port = 8545

[prover]
prover_type = "sp1"            # or "exec" for faster development
proof_format = "compressed"    # No groth16 on top, faster but larger proof

[bft_committer]
bft_core_peers = ["/ip4/127.0.0.1/tcp/30300/p2p/12D3..."]
signing_key_path = "./keys/signing.key"
```

## How It Works

### Block Production Flow

```
User Transaction
  ↓
RPC Server (eth_sendRawTransaction)
  ↓
Mempool (with pending state tracking)
  ↓
Block Producer (every block_time_ms)
  ↓
Execution (ethrex VM)
  ↓
Proof Coordinator
  ├─ Generate witness (ethrex)
  ├─ Build ProgramInput
  └─ prove(Backend::SP1, input, Compressed) → proof bytes
  ↓
BFT Committer
  ├─ Create BlockCertificationRequest (CBOR)
  ├─ Sign with secp256k1
  └─ Send via libp2p to BFT Core
  ↓
BFT Core L1
  ├─ Verify SP1 proof
  ├─ Consensus on state transition
  └─ Return UnicityCertificate
  ↓
Storage (block + UC persisted)
  ↓
Block Finalized ✓
```

## Custom Precompile

**Unicity Certificate Verifier (0x100)**

Verifies signatures from BFT Core validators:

```solidity
interface IUnicityVerifier {
    function verifyUnicityCertificate(bytes calldata ucCbor)
        external view returns (bool valid, bytes32 stateHash, uint64 roundNumber);
}

// Usage
IUnicityVerifier(0x0000000000000000000000000000000000000100)
    .verifyUnicityCertificate(ucBytes);
```

See `crates/uni-bft-precompile/INTEGRATION.md` for implementation details.

## RPC API

**Supported** (18 endpoints):
- `eth_chainId`, `eth_blockNumber`, `eth_getBalance`, `eth_getCode`
- `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getTransactionByHash`
- `eth_getTransactionReceipt`, `eth_sendRawTransaction`
- `eth_call`, `eth_estimateGas` (with pending state)
- `eth_getStorageAt`, `eth_getTransactionCount`, `eth_gasPrice`
- `net_version`, `net_listening`, `net_peerCount`

**Not supported**:
- Engine API (no external consensus, BFT Core handles this)
- Admin API (single-node, no peer management)
- Debug/trace API (planned)

## Development

### Testing Without Proofs

```toml
[prover]
prover_type = "exec"  # Dummy proofs [0xDE, 0xAD, 0xBE, 0xEF]
```

Allows fast iteration without 5min SP1 proving overhead.

### Testing With SP1 STARK Proofs

```toml
[prover]
prover_type = "sp1"
```

Requires SP1 toolchain installed. Increase `block_time_ms` and T2 timeout.

### Running Tests

```bash
# Unit tests
cargo test --workspace

# Manual integration testing
cast send <recipient> --value 1ether --private-key <key> --rpc-url http://localhost:8545
```

## Documentation

**Implementation docs:**
- `AGENTS.md` - Development guide for AI coding agents
- `crates/uni-bft-precompile/INTEGRATION.md` - Precompile integration
- https://github.com/unicitynetwork/bft-core/blob/l1/rootchain/consensus/zkverifier/sp1-verifier-ffi/README.md
- https://github.com/unicitynetwork/bft-core/blob/l1/rootchain/consensus/zkverifier/FFI_INTEGRATION.md


## Known Issues

1. **Rust Nightly Required** - ethrex uses unstable `let_chains`
   - Workaround: `rustup override set nightly`

2. **SP1 Proving Slow** - 5min per block (on my machine)
   - Workaround: Use `prover_type = "exec"` for testing
   - Production: proper CPUs or GPU acceleration (10-30s per block)

3. **Precompile Not Auto-Registered** - Requires manual ethrex modification
   - See `crates/uni-bft-precompile/INTEGRATION.md`


## Performance

TODO

## Resources

- **ethrex**: https://github.com/lambdaclass/ethrex
- **SP1**: https://docs.succinct.xyz/sp1
- **Unicity BFT Core**: https://github.com/unicitynetwork/bft-core/tree/l1
