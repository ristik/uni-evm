# Unicity Precompile - ethrex Integration Guide

## Overview

This document explains how to integrate the custom Unicity verification precompile (at address `0x100`) into the ethrex VM.

## Current Status

✅ **Implemented**:
- Precompile logic in `precompile.rs`
- Trust base signature verification in `trust_base.rs`
- CBOR deserialization of Unicity Certificates
- Complete test suite with real secp256k1 signatures

⚠️ **Requires Manual Integration**:
Since ethrex is a git submodule, the precompile needs to be manually registered in ethrex's `precompiles.rs` file.

## Integration Steps

### 1. Modify ethrex Precompile Dispatcher

**File**: `ethrex/crates/vm/levm/src/precompiles.rs`

#### Step 1.1: Add Unicity Precompile Import

At the top of the file, add:

```rust
// After other precompile imports
use uni_bft_precompile::{unicity_verify_precompile, UNICITY_VERIFY_ADDRESS};
```

#### Step 1.2: Define Precompile Constant

Around line 100-200, add the precompile definition:

```rust
pub const UNICITY_VERIFY: Precompile = Precompile {
    address: UNICITY_VERIFY_ADDRESS, // 0x100
    name: "UNICITY_VERIFY",
    active_since_fork: Paris,
};
```

#### Step 1.3: Add to PRECOMPILES Array

Around line 280-287, add to the `PRECOMPILES` array:

```rust
const PRECOMPILES: [Precompile; 18] = [  // Increment from 17 to 18
    ECRECOVER,
    SHA2_256,
    RIPEMD_160,
    IDENTITY,
    MODEXP,
    ECADD,
    ECMUL,
    ECPAIRING,
    BLAKE2F,
    POINT_EVALUATION,
    BLS12_G1ADD,
    BLS12_G1MSM,
    BLS12_G2ADD,
    BLS12_G2MSM,
    BLS12_MAP_FP_TO_G1,
    BLS12_MAP_FP2_TO_G2,
    BLS12_PAIRING_CHECK,
    P256VERIFY,
    UNICITY_VERIFY,  // ADD THIS LINE
];
```

#### Step 1.4: Register in execute_precompile

Around line 309-335, add to the const PRECOMPILES array initialization:

```rust
const PRECOMPILES: [Option<PrecompileFn>; 512] = const {
    let mut precompiles = [const { None }; 512];
    precompiles[ECRECOVER.address.0[19] as usize] = Some(ecrecover as PrecompileFn);
    // ... existing precompiles ...

    // ADD THIS LINE (address 0x100 = index 256)
    precompiles[u16::from_be_bytes([UNICITY_VERIFY.address.0[18], UNICITY_VERIFY.address.0[19]]) as usize]
        = Some(unicity_verify_wrapper as PrecompileFn);

    precompiles
};
```

#### Step 1.5: Create Wrapper Function

Since our precompile has signature `fn(&Bytes, &mut u64) -> Result<Bytes, VMError>`
but ethrex expects `fn(&Bytes, &mut u64, Fork) -> Result<Bytes, VMError>`, add a wrapper:

```rust
/// Wrapper for unicity_verify_precompile to match ethrex signature
fn unicity_verify_wrapper(
    calldata: &Bytes,
    gas_remaining: &mut u64,
    _fork: Fork,  // Unused - unicity verify is fork-independent
) -> Result<Bytes, VMError> {
    uni_bft_precompile::unicity_verify_precompile(calldata, gas_remaining)
}
```

### 2. Update ethrex Cargo Dependencies

**File**: `ethrex/Cargo.toml` (workspace root)

Add uni-bft-precompile to workspace dependencies:

```toml
[workspace.dependencies]
# ... existing dependencies ...
uni-bft-precompile = { path = "../crates/bft-precompile" }
```

**File**: `ethrex/crates/vm/levm/Cargo.toml`

Add to dependencies:

```toml
[dependencies]
# ... existing dependencies ...
uni-bft-precompile = { workspace = true }
```

### 3. Trust Base Integration Options

The precompile currently uses a placeholder verification function. To enable real verification, choose one of these options:

#### Option A: Global Trust Base (Recommended for MVP)

Create a global trust base in `cmd/uni-evm/src/node.rs`:

```rust
use std::sync::{Arc, RwLock};
use uni_bft_precompile::UnicityTrustBase;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref GLOBAL_TRUST_BASE: Arc<RwLock<UnicityTrustBase>> =
        Arc::new(RwLock::new(UnicityTrustBase::new()));
}

impl UniEvmNode {
    pub async fn run(self) -> Result<()> {
        // ... initialization ...

        // Initialize trust base with validators
        {
            let mut trust_base = GLOBAL_TRUST_BASE.write().unwrap();
            // Load trust base from BFT Core or config
            // trust_base.add_entry(entry);
        }

        // Spawn background task to update trust base periodically
        tokio::spawn(async {
            update_trust_base_loop().await;
        });

        // ... rest of initialization ...
    }
}

async fn update_trust_base_loop() {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        // Fetch latest trust base from BFT Core
        // Update GLOBAL_TRUST_BASE
    }
}
```

Then modify `precompile.rs` to use the global:

```rust
fn verify_placeholder(uc: &UnicityCertificate) -> bool {
    // Try to use global trust base if available
    #[cfg(feature = "global-trust-base")]
    {
        if let Ok(trust_base) = crate::node::GLOBAL_TRUST_BASE.read() {
            return trust_base.verify_unicity_certificate(uc).unwrap_or(false);
        }
    }

    // Fallback to basic sanity checks
    if uc.version == 0 || uc.signature.is_empty() || uc.state_hash.is_empty() {
        return false;
    }
    true
}
```

#### Option B: VM Extension (More Proper, More Work)

Extend ethrex VM to include trust base in its state:

1. Add `trust_base: Arc<RwLock<UnicityTrustBase>>` to VM struct
2. Pass trust base through to precompile execution
3. Modify precompile signature to accept VM context

This requires more extensive ethrex modifications.

#### Option C: Contract Storage (Future)

Store trust base in a special system contract at address `0x0...0101`:

1. Create `UnicityTrustBaseContract` at deployment
2. Precompile reads trust base from contract storage
3. Contract has privileged update methods

## Testing

### Unit Tests

Run the precompile tests:

```bash
cargo test -p uni-bft-precompile
```

Tests include:
- ✅ CBOR deserialization
- ✅ Signature verification with real secp256k1
- ✅ Invalid signature rejection
- ✅ Epoch calculation
- ✅ Trust base entry management

### Integration Test (After Integration)

Create a test in `ethrex/crates/vm/levm/tests/`:

```rust
#[test]
fn test_unicity_precompile_call() {
    use bytes::Bytes;
    use ethrex_common::H160;
    use uni_bft_committer::types::UnicityCertificate;

    let uc = UnicityCertificate {
        version: 1,
        partition: 1,
        shard: 1,
        round_number: 100,
        state_hash: vec![0xaa; 32],
        tr_hash: vec![0xbb; 32],
        signature: vec![0xcc; 64],
    };

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&uc, &mut cbor_bytes).unwrap();

    let calldata = Bytes::from(cbor_bytes);
    let mut gas = 100000u64;

    let result = execute_precompile(
        H160::from_low_u64_be(0x100),
        &calldata,
        &mut gas,
        Fork::Paris,
    );

    assert!(result.is_ok());
    let output = result.unwrap();
    assert_eq!(output.len(), 72); // 32 + 32 + 8
}
```

### Solidity Contract Test

Create a Forge test in `contracts/test/`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IUnicityVerifier {
    function verifyUnicityCertificate(bytes calldata ucCbor)
        external view
        returns (bool valid, bytes32 stateHash, uint64 roundNumber);
}

contract UnicityPrecompileTest is Test {
    IUnicityVerifier constant VERIFIER = IUnicityVerifier(
        0x0000000000000000000000000000000000000100
    );

    function testUnicityVerification() public {
        // Encode a test UC in CBOR (use test fixture)
        bytes memory ucCbor = hex"..."; // CBOR-encoded UC

        (bool valid, bytes32 stateHash, uint64 round) =
            VERIFIER.verifyUnicityCertificate(ucCbor);

        assertTrue(valid);
        assertEq(stateHash, bytes32(uint256(0xaa)));
        assertEq(round, 100);
    }

    function testInvalidUC() public {
        bytes memory invalidCbor = hex"deadbeef";

        vm.expectRevert(); // Should revert on invalid CBOR
        VERIFIER.verifyUnicityCertificate(invalidCbor);
    }
}
```

## Gas Costs

Current gas costs:
- **Base**: 3000 gas
- **Per byte**: 6 gas (for CBOR decoding + signature verification)

Example:
- 200-byte UC: 3000 + (200 * 6) = 4200 gas

Comparable to:
- ECRECOVER: 3000 gas (fixed)
- SHA256: 60 base + 12/word
- Our precompile: Similar complexity to ECRECOVER

## Solidity Usage Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUnicityVerifier {
    function verifyUnicityCertificate(bytes calldata ucCbor)
        external view
        returns (bool valid, bytes32 stateHash, uint64 roundNumber);
}

contract Bridge {
    IUnicityVerifier constant VERIFIER = IUnicityVerifier(
        0x0000000000000000000000000000000000000100
    );

    mapping(uint64 => bytes32) public certifiedStates;

    function submitUnicityCertificate(bytes calldata ucCbor) external {
        (bool valid, bytes32 stateHash, uint64 round) =
            VERIFIER.verifyUnicityCertificate(ucCbor);

        require(valid, "Invalid UC");
        require(round > latestRound, "Stale UC");

        certifiedStates[round] = stateHash;
        latestRound = round;

        emit StateCertified(round, stateHash);
    }

    function verifyStateProof(
        uint64 round,
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool) {
        require(certifiedStates[round] == stateRoot, "State not certified");
        // Verify Merkle proof against certified state root
        // ...
    }
}
```

## Security Considerations

### Current Placeholder Mode

⚠️ **WARNING**: The current implementation accepts ALL non-empty UCs!

Do NOT use in production without implementing one of the trust base integration options.

### Production Requirements

Before mainnet deployment:

1. ✅ Implement real trust base integration (Option A, B, or C)
2. ✅ Secure trust base update mechanism
3. ✅ Rate limiting on precompile calls
4. ✅ Audit signature verification logic
5. ✅ Test with malicious UC inputs
6. ✅ Verify gas costs can't be exploited
7. ✅ Ensure trust base updates are atomic

## Performance

Expected performance characteristics:

- **CBOR deserialization**: ~10-50 μs for typical UC (200-500 bytes)
- **secp256k1 verification**: ~100-300 μs per signature
- **Total per call**: ~150-400 μs (3000-5000 gas)

For comparison:
- ECRECOVER: ~100-200 μs (3000 gas)
- SHA256: ~5-20 μs (60-1000 gas)

The precompile is slightly more expensive than ECRECOVER due to CBOR parsing overhead.

## Troubleshooting

### Precompile Not Found

Error: `InvalidPrecompileAddress` or `UnknownPrecompile`

**Solution**: Verify address 0x100 is correctly registered in `execute_precompile` const array.

### Gas Cost Too High

Error: `OutOfGas` when calling with sufficient gas

**Solution**: Check `UNICITY_VERIFY_BASE_GAS` and `UNICITY_VERIFY_PER_BYTE_GAS` constants.

### Invalid Signature

Error: `TrustBaseError::InvalidSignature`

**Solution**:
1. Verify trust base has correct validator public keys
2. Check UC signature matches expected format (64-byte compact)
3. Ensure CBOR serialization matches BFT committer

### Epoch Not Found

Error: `TrustBaseError::EpochNotFound(N)`

**Solution**: Ensure trust base is updated with entries for recent epochs.

## Future Enhancements

### Planned Improvements

1. **Multi-signature quorum verification**
   - Current: Verifies single validator
   - Planned: Verify against quorum threshold (2/3+ validators)

2. **Trust base versioning**
   - Support epoch transitions
   - Handle validator set changes

3. **Caching**
   - Cache verified UCs to avoid re-verification
   - TTL-based cache expiration

4. **Metrics**
   - Track verification success/failure rates
   - Monitor gas usage statistics

5. **EIP-7702 delegation support**
   - Allow contracts to delegate UC verification
   - Batched verification for multiple UCs

## References

- Precompile implementation: `crates/bft-precompile/src/precompile.rs`
- Trust base logic: `crates/bft-precompile/src/trust_base.rs`
- ethrex precompiles: `ethrex/crates/vm/levm/src/precompiles.rs`
- BFT committer: `crates/bft-committer/src/committer.rs`

## Support

For questions or issues:
- Check test suite: `cargo test -p uni-bft-precompile`
- Review logs: Set `RUST_LOG=uni_bft_precompile=debug`
- Inspect CBOR encoding: Use `ciborium::de::from_reader` with debug output
