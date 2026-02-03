# uni-evm Staging Environment

This directory contains the Docker Compose setup for running a staging environment that simulates a real-world deployment of the uni-evm system.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    BFT Core Root Chain                          │
│                    (4 nodes, Byzantine Fault Tolerant)          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Root 1   │  │ Root 2   │  │ Root 3   │  │ Root 4   │        │
│  │ (Leader) │  │          │  │          │  │          │        │
│  │ :25866   │  │ :25867   │  │ :25868   │  │ :25869   │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │                │
│       └─────────────┴──────┬──────┴─────────────┘                │
│                            │                                     │
│              Consensus Coordination (libp2p)                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         │                                       │
         ▼                                       ▼
┌─────────────────────┐              ┌─────────────────────┐
│   Go Aggregator     │              │     uni-evm         │
│   (Partition 7)     │              │   (Partition 8)     │
│                     │              │                     │
│   Commitments       │              │   EVM Execution     │
│   Aggregation       │              │   Light Client Mode │
│                     │              │                     │
│   :3000 (API)       │              │   :8545 (JSON-RPC)  │
│   :9100 (P2P)       │              │   :9000 (P2P)       │
├─────────────────────┤              └─────────────────────┘
│   Dependencies:     │
│   - Redis :6379     │
│   - MongoDB :27017  │
└─────────────────────┘
```

## Components

| Service | Description | Ports |
|---------|-------------|-------|
| `bft-root-1` to `bft-root-4` | BFT Core root chain nodes (consensus) | P2P: 26662-26665, RPC: 25866-25869 |
| `aggregator` | Go Aggregator for commitment aggregation | API: 3000, P2P: 9100 |
| `uni-evm` | EVM execution node (light client mode) | RPC: 8545, P2P: 9000 |
| `redis` | Commitment queue cache | 6379 |
| `mongodb` | Aggregator persistent storage | 27017 |

## Quick Start

```bash
# 1. Make the setup script executable (if not already)
chmod +x setup-staging.sh

# 2. Run the setup (builds images and starts all services)
./setup-staging.sh

# 3. Check status
./setup-staging.sh --status

# 4. View logs
./setup-staging.sh --logs
./setup-staging.sh --logs uni-evm  # Specific service

# 5. Stop everything
./setup-staging.sh --down
```

## Light Client Mode

The uni-evm node runs in **light client validation mode**, which:

1. Generates execution witnesses (~1 second) instead of ZK proofs (~5+ minutes)
2. Serializes `ProgramInput` with magic header `"LCPROOF\0"`
3. BFT Core executes validation logic directly (~100ms)
4. Returns Unicity Certificate (UC) for block finalization

This mode is ideal for:
- Development and testing
- Staging environments
- Fast iteration (300x faster than SP1 mode)

## Configuration

### Environment Variables

The docker-compose file sets all required environment variables. Key configurations:

**uni-evm (`config.toml` auto-generated):**
```toml
[prover]
prover_type = "light_client"  # Key setting for light client mode

[network]
partition_id = 8
chain_id = 3
```

**Aggregator:**
```bash
BFT_ENABLED=true
SHARDING_MODE=standalone
```

### BFT Core Trust Base

The trust base is automatically generated with 4 validators:
- Each root node signs the trust base
- Quorum requires 3 of 4 signatures (2f+1 where f=1)

## Testing the Setup

### Test uni-evm JSON-RPC

```bash
# Get chain ID
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

# Expected: {"jsonrpc":"2.0","id":1,"result":"0x3"}

# Get block number
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get balance
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","latest"],"id":1}'
```

### Test Aggregator

```bash
# Health check
curl http://localhost:3000/health

# Get block height
curl -X POST http://localhost:3000 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_block_height","params":[],"id":1}'
```

### Test BFT Core

```bash
# Get trust base from any root node
curl http://localhost:25866/api/v1/trustbase

# Get partition configurations
curl http://localhost:25866/api/v1/configurations
```

## Troubleshooting

### Services not starting

```bash
# Check logs for specific service
docker compose logs bft-root-1
docker compose logs uni-evm

# Restart specific service
docker compose restart uni-evm
```

### Trust base issues

```bash
# View trust base content
docker compose exec bft-root-1 cat /genesis/trust-base.json

# Regenerate everything
./setup-staging.sh --clean
./setup-staging.sh
```

### Network connectivity

```bash
# Check if services can reach each other
docker compose exec uni-evm nc -zv bft-root-1 8000
docker compose exec aggregator nc -zv bft-root-1 8000
```

### Clean restart

```bash
# Remove all data and start fresh
./setup-staging.sh --clean
./setup-staging.sh
```

## Development Workflow

1. Make changes to uni-evm code
2. Rebuild only uni-evm:
   ```bash
   docker compose build uni-evm
   docker compose up -d uni-evm
   ```
3. View logs:
   ```bash
   docker compose logs -f uni-evm
   ```

## Port Reference

| Port | Service | Protocol |
|------|---------|----------|
| 8545 | uni-evm | JSON-RPC HTTP |
| 9000 | uni-evm | libp2p P2P |
| 30303 | uni-evm | Ethereum Discovery |
| 3000 | aggregator | HTTP API |
| 9100 | aggregator | libp2p P2P |
| 25866-25869 | bft-root-1 to 4 | HTTP RPC |
| 26662-26665 | bft-root-1 to 4 | libp2p P2P |
| 6379 | redis | Redis Protocol |
| 27017 | mongodb | MongoDB Protocol |
