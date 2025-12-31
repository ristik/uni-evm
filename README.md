# Uni-EVM L2

An EVM L2 blockchain built on [ethrex](https://github.com/lambdaclass/ethrex) that submits per-block ZK proofs to Unicity Consensus Layer (BFT Core).

## Features

- 🔒 **EVM-Compatible**: Full Ethereum smart contract support
- ⚡ **ZK-Proven**: SP1-based proof generation for every block
- 🌐 **Custom L1**: Integrates with BFT Core via libp2p
- 🔧 **Custom Precompile**: Unicity Certificate verification at `0x100`
- 📡 **JSON-RPC API**: 18 endpoints for dApp integration
- 🚀 **Simplified**: Single-node L2 architecture, no P2P complexity

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Unicity-EVM L2                      │
│                                                       │
│  Users → RPC → Block Producer → SP1 Prover           │
│                       ↓              ↓                │
│                  Blockchain  →  BFT Committer         │
│                                      ↓                │
└──────────────────────────────────────┼───────────────┘
                                       ↓
                              ┌───────────────────────────┐
                              │  BFT Core L1               │
                              │  (Unicity Consensus Layer) │
                              └───────────────────────────┘
```

## Quick Start

### Prerequisites

```bash
# 1. Install Rust nightly (required for ethrex)
rustup toolchain install nightly
rustup override set nightly

# 2. Install SP1 toolchain
curl -L https://sp1.succinctlabs.com | bash
sp1up
```

### Build

```bash
cargo build --release
```

### Configure

```bash
# Copy example configuration
cp config.toml my-config.toml

# Edit configuration (optional)
vim my-config.toml
```

### Run

```bash
cargo run --release
```

The node will start with:
- **RPC server** at `http://localhost:8545`
- **Block production** every 1 second
- **SP1 proof generation** for each block

### Test

```bash
# Check chain ID
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

# Or use cast (Foundry)
cast chain-id --rpc-url http://localhost:8545
cast block-number --rpc-url http://localhost:8545
```

## Documentation

- **[IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md)** - Complete implementation overview
- **[TESTING.md](TESTING.md)** - Comprehensive testing guide
- **[PHASE5_PROGRESS.md](PHASE5_PROGRESS.md)** - Latest development progress
- **[KNOWN_ISSUES.md](KNOWN_ISSUES.md)** - Known issues and workarounds

### Phase Documentation

- [Phase 1: Repository Setup](PHASE1_COMPLETE.md)
- [Phase 2: BFT Core Integration](PHASE2_COMPLETE.md)
- [Phase 3: Custom Sequencer](PHASE3_COMPLETE.md)
- [Phase 4: Custom Precompile](PHASE4_COMPLETE.md)
- [Phase 5: Complete Integration](PHASE5_PROGRESS.md)

## Project Structure

```
uni-evm/
├── crates/
│   ├── uni-bft-committer/     # Unicity BFT Core integration
│   ├── uni-bft-precompile/    # Unicity trust anchor for EVM
│   ├── uni-sequencer/         # Block producer + proof coordinator
│   └── uni-storage/           # Simplified storage layer
│
├── cmd/uni-evm/               # Main binary
│   └── src/
│       ├── main.rs            # Entry point
│       ├── node.rs            # Node orchestration
│       ├── config.rs          # Configuration
│       └── rpc.rs             # RPC server
│
├── ethrex/                    # Git submodule (upstream)
├── config.toml                # Configuration file
├── genesis.json               # Genesis block
└── README.md                  # This file
```

## Configuration

### Basic Configuration

```toml
[network]
chain_id = 1
genesis_file_path = "./genesis.json"

[sequencer]
block_time_ms = 1000    # 1 second blocks
gas_limit = 30000000    # 30M gas

[rpc]
http_addr = "127.0.0.1"
http_port = 8545

[prover]
prover_type = "sp1"     # or "exec" for testing without proofs
proof_format = "compressed"
```

See `config.toml` for full configuration options.

## RPC API

### Supported Methods

**eth_* namespace** (15 endpoints):
- `eth_chainId`, `eth_blockNumber`, `eth_getBalance`
- `eth_getBlockByNumber`, `eth_getBlockByHash`
- `eth_getTransactionByHash`, `eth_getTransactionReceipt`
- `eth_sendRawTransaction`, `eth_call`, `eth_estimateGas`
- `eth_getCode`, `eth_getStorageAt`, `eth_getTransactionCount`
- `eth_gasPrice`, `eth_getBlockTransactionCount*`

**net_* namespace** (3 endpoints):
- `net_version`, `net_listening`, `net_peerCount`

## Custom Precompile

### Unicity Verifier (0x100)

Verifies Unicity Certificates (the trust anchor of Unicity tokens) from Unicity BFT Core:

```solidity
interface IUnicityVerifier {
    function verifyUnicityCertificate(bytes calldata ucCbor)
        external view
        returns (bool valid, bytes32 stateHash, uint64 roundNumber);
}

contract Example {
    IUnicityVerifier constant VERIFIER = IUnicityVerifier(0x0000000000000000000000000000000000000100);

    function checkCertificate(bytes calldata uc) external view returns (bool) {
        (bool valid, , ) = VERIFIER.verifyUnicityCertificate(uc);
        return valid;
    }
}
```

See `crates/uni-bft-precompile/INTEGRATION.md` for details.

## Development

### Running Tests

```bash
# Unit tests
cargo test --workspace

# Integration tests
./scripts/test-e2e.sh
```

### Testing Mode (No Proofs)

For faster iteration without SP1 proof generation:

```toml
[prover]
prover_type = "exec"  # Skip proof generation
```

### Monitoring

```bash
# Watch blocks being produced
watch -n 1 'cast block-number --rpc-url http://localhost:8545'

# Monitor logs
tail -f ./logs/uni-evm.log
```

## Performance

| Metric | Value |
|--------|-------|
| Block time | 1 second (configurable) |
| Gas limit | 30M per block |
| Proof generation | 30s - 2min (dev mode) |
| RPC latency | < 100ms (local) |

## Known Issues

1. **Requires Rust Nightly**: ethrex uses unstable `let_chains` feature
   - Workaround: `rustup override set nightly`

2. **Proof Generation Slow**: SP1 proving takes 30s-2min per block
   - Workaround: Use `prover_type = "exec"` for testing
   - Or increase `block_time_ms` to match proof time

3. **Precompile Registration**: Custom precompile requires manual ethrex modification
   - See `crates/uni-bft-precompile/INTEGRATION.md`

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for complete list.

## Roadmap

### ✅ Completed

- [x] Repository setup and workspace structure
- [x] BFT Core L1 integration (libp2p + CBOR)
- [x] Block producer and proof coordinator
- [x] Unicity verification precompile
- [x] RPC server (18 endpoints)
- [x] Genesis block initialization
- [x] SP1 proof generation integration

### 🔄 In Progress

- [ ] End-to-end integration testing
- [ ] Trust base update mechanism
- [ ] Precompile registration in ethrex

### 📋 Planned

- [ ] Performance optimization (GPU proving)
- [ ] Monitoring and metrics (Prometheus)
- [ ] Multi-node coordination
- [ ] Additional precompiles
- [ ] Block explorer

## Resources

- **ethrex**: https://github.com/lambdaclass/ethrex
- **SP1**: https://docs.succinct.xyz/sp1
- **Unicity BFT Core**: https://github.com/unicitynetwork/bft-core


## Acknowledgments

- Built on [ethrex](https://github.com/lambdaclass/ethrex) by Lambda Class
- Uses [SP1](https://github.com/succinctlabs/sp1) for ZK proofs
- Integrates with Unicity BFT Core

---

## Support

- **Documentation**: See docs in this repository
- **Issues**: [GitHub Issues](https://github.com/ristik/uni-evm/issues)
- **Community**: [Discord](https://discord.gg/unicity-etc)

---

**Status**: Core implementation complete ✅ | Ready for testing 🧪

For detailed implementation information, see [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md).
