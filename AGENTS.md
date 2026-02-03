# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, etc.) when working with code in this repository.

## Overview

Uni-EVM is a minimal, single-node L2 blockchain built on ethrex that submits per-block ZK proofs to Unicity BFT Core L1. This is NOT a standard Ethereum L2 - it integrates with a custom non-Ethereum L1 using CBOR over libp2p.

**Key Architectural Decisions**:
- **Per-block proving**: Unlike ethrex which batches, uni-evm proves each block individually
- **No P2P networking**: Single sequencer node, simplified RPC without sync/peer dependencies
- **Custom L1**: BFT Core uses CBOR serialization and libp2p (not Ethereum RPC)
- **SP1 Compressed proofs**: No Groth16 wrapping since BFT Core verifies SP1 directly

## Prerequisites & Build

**CRITICAL**: This project requires Rust nightly due to ethrex's use of unstable `let_chains` feature.

```bash
# Set nightly Rust (REQUIRED)
rustup override set nightly

# For ZK proof generation (optional for testing)
curl -L https://sp1.succinctlabs.com | bash
sp1up

# Build
cargo build --release --features sp1

# Run
cargo run --release --features sp1

# Testing without proofs (faster iteration)
# Edit config.toml: prover_type = "exec"
cargo run --release
```

## Workspace Structure

```
uni-evm/
├── ethrex/                    # Fork of lambdaclass/ethrex (separate git repo)
├── crates/
│   ├── uni-bft-committer/    # L1 integration via libp2p/CBOR
│   ├── uni-bft-precompile/   # EVM precompile for Unicity Certificates
│   ├── uni-sequencer/        # Block production + SP1 proof coordination
│   └── uni-storage/          # Simplified storage (UCs + proofs)
└── cmd/uni-evm/              # Main binary (node orchestration + RPC)
```

## Core Architecture

### Data Flow: Transaction → Proof → L1

1. **RPC Server** (`cmd/uni-evm/src/rpc.rs`) receives `eth_sendRawTransaction`
2. **Block Producer** (`uni-sequencer/block_producer.rs`) builds block every 1s
3. **Proof Coordinator** (`uni-sequencer/proof_coordinator.rs`):
   - Generates `ExecutionWitness` via `blockchain.generate_witness_for_blocks()`
   - Prepares `ProgramInput` with blocks + witness + elasticity_multiplier
   - Calls `prove(Backend::SP1, input, ProofFormat::Compressed)` from ethrex-prover
   - Converts output to `BatchProof` and extracts proof bytes
4. **BFT Committer** (`uni-bft-committer/committer.rs`):
   - Creates `BlockCertificationRequest` with proof in `zk_proof` field (external from InputRecord)
   - Signs with secp256k1, CBOR encodes
   - Sends via libp2p protocol `/ab/block-certification/0.0.1`
5. **BFT Core L1** verifies SP1 proof, returns `UnicityCertificate`
6. **Storage** stores UC associated with block number

### Key Differences from ethrex

**Block Production**:
- ethrex: Fetches L1 messages from Ethereum, batches blocks
- uni-evm: No L1 messages, per-block proving, simpler flow

**Proof Format**:
- ethrex L2: Can wrap in Groth16 for Ethereum L1 verification
- uni-evm: Always `ProofFormat::Compressed` (BFT Core verifies SP1 directly)

**RPC Server**:
- ethrex: Full P2P sync, SyncManager, PeerHandler, NodeRecord
- uni-evm: Single-node, dummy P2P data, 18 endpoints only

**Configuration**:
- ethrex uses `ProverType` enum from ethrex-l2-common
- uni-evm uses `Backend` enum from ethrex-prover (for direct `prove()` call)

### Custom Precompile (0x100)

**Purpose**: Allow smart contracts to verify Unicity Certificates from BFT Core L1

**Location**: `crates/uni-bft-precompile/`

**Status**: Code complete but requires manual integration into ethrex VM
- See `crates/uni-bft-precompile/INTEGRATION.md` for steps
- Must modify `ethrex/crates/vm/levm/src/precompiles.rs`
- Add to `PRECOMPILES` array at index 256

**Solidity Interface**:
```solidity
interface IUnicityVerifier {
    function verifyUnicityCertificate(bytes calldata ucCbor)
        external view returns (bool valid, bytes32 stateHash, uint64 roundNumber);
}
```

**Implementation Details**:
- CBOR deserializes `UnicityCertificate` from calldata
- Verifies secp256k1 signature against Trust Base validators
- Message = Keccak256(CBOR(UC with signature field zeroed))
- Gas: 3000 base + 6/byte

## Configuration

**File**: `config.toml`

**Critical settings**:
```toml
[network]
chain_id = 1                              # Must match genesis.json
genesis_file_path = "./genesis.json"

[prover]
prover_type = "sp1"                       # or "exec" for testing
proof_format = "compressed"               # ALWAYS compressed for BFT Core

[sequencer]
block_time_ms = 1000                      # Must be >= proof generation time
```

**Genesis Block**: `genesis.json` is minimal post-merge config (Shanghai + Cancun activated). Chain ID must match config.

**ZK Verification Key**: `ethrex-vkey.bin` extracted from ethrex's SP1 guest program ELF (the same ELF used for proving). Extract with: `cd tools/extract-vkey && cargo run --release`. BFT-Core verifies proofs using this vkey. Must match the ELF used by ethrex's SP1 backend.

## Common Development Patterns

### Adding New RPC Endpoints

RPC server is simplified - no P2P dependencies. Handler functions reused from ethrex-rpc:

```rust
// cmd/uni-evm/src/rpc.rs
async fn handle_eth_request(req: RpcRequest, ctx: RpcApiContext) -> Result<Value, RpcErr> {
    match req.method.as_str() {
        "eth_newMethod" => eth::new::new_method(req.parse_params()?, ctx).await,
        // ...
    }
}
```

Context conversion creates dummy P2P data (not used):
```rust
impl From<UniEvmRpcContext> for RpcApiContext {
    fn from(ctx: UniEvmRpcContext) -> Self {
        // Creates dummy Node, NodeRecord (required by type system)
    }
}
```

### Modifying Proof Generation

**File**: `crates/uni-sequencer/src/proof_coordinator.rs`

The `generate_proof()` function is the core proving logic:
1. Generate witness: `blockchain.generate_witness_for_blocks(&blocks)`
2. Prepare input: `ProgramInput { blocks, execution_witness, elasticity_multiplier, ... }`
3. Prove: `prove(self.config.prover_backend, program_input, self.config.proof_format)`
4. Convert: `to_batch_proof(proof_output, self.config.proof_format)`
5. Extract: `batch_proof.proof` (Vec<u8>)

**IMPORTANT**:
- `prover_backend` is `Backend` enum from ethrex-prover, NOT `ProverType`
- Always use `ProofFormat::Compressed` for BFT Core
- Execution witness contains all state data for stateless zkVM execution

### BFT Core Integration

**Files**: `crates/uni-bft-committer/`

**Protocol**: libp2p request-response `/ab/block-certification/0.0.1`

**Message Format**:
1. Create `BlockCertificationRequest` with `InputRecord`
2. Set `BlockCertificationRequest.zk_proof = proof_bytes` (ZK proof is separate field, not in InputRecord)
3. Sign entire request with secp256k1
4. CBOR encode with `ciborium` using tuple/array format (`serde_tuple`)
5. Send via libp2p, receive `UnicityCertificate` as CBOR response

**Trust Base**: Validator public keys stored by epoch. Currently static, needs periodic updates from BFT Core (TODO).

## Testing

**Unit tests**:
```bash
cargo test --workspace
```

**Manual RPC testing**:
```bash
# Node must be running
cargo run --release

# In another terminal
cast chain-id --rpc-url http://localhost:8545
cast block-number --rpc-url http://localhost:8545

# Send transaction
cast send 0xRECIPIENT --value 1ether --private-key 0xKEY --rpc-url http://localhost:8545
```

**Testing without SP1 proofs** (for faster iteration):
Edit `config.toml`: `prover_type = "exec"`

## Known Issues

1. **Nightly Rust required**: ethrex uses `let_chains` (unstable)
   - Workaround: `rustup override set nightly`
   - Will be resolved when Rust 1.92+ stabilizes feature or ethrex updates

2. **Proof generation slow**: SP1 takes 5min per block in dev mode
   - Workaround: Use `prover_type = "exec"` for testing
   - Or increase `block_time_ms` to match proving time
   - Production: GPU acceleration brings this to 10-30s

3. **Precompile not auto-registered**: Manual ethrex modification needed
   - See `crates/uni-bft-precompile/INTEGRATION.md`

## Documentation

- `README.md` - Quick start and overview
- `IMPLEMENTATION_COMPLETE.md` - Full architecture and phase-by-phase breakdown
- `TESTING.md` - Comprehensive testing guide
- `KNOWN_ISSUES.md` - Known limitations and workarounds
- `PHASE*.md` - Detailed progress for each implementation phase
- `crates/uni-bft-precompile/INTEGRATION.md` - Precompile integration steps

## Important Notes

- **ethrex is a fork** - it's a separate git repository at `git@github.com:ristik/ethrex.git` (branch: uni-evm). Changes to ethrex should be committed in that repo, then pushed separately
- **Genesis chain_id must match config** - node validates consistency on startup
- **BFT Core peer IDs** in config.toml must be actual libp2p peer IDs from running BFT Core nodes
- **Block time must account for proving** - if `block_time_ms < proof_generation_time`, blocks will queue
- **RPC server is simplified** - don't add P2P features, keep it stateless
- **Per-block proving is intentional** - don't try to batch, it changes the L1 integration flow
