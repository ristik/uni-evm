//! BFT Core Unicity Verification Precompile
//!
//! This crate provides a custom EVM precompile at address 0x100
//! that allows smart contracts to verify Unicity Certificates from BFT Core L1.
//!
//! ## Usage
//!
//! ```solidity
//! interface IUnicityVerifier {
//!     function verifyUnicityCertificate(bytes calldata ucCbor)
//!         external view
//!         returns (bool valid, bytes32 stateHash, uint64 roundNumber);
//! }
//!
//! contract MyContract {
//!     IUnicityVerifier constant VERIFIER = IUnicityVerifier(0x0000000000000000000000000000000000000100);
//!
//!     function processWithUnicity(bytes calldata ucCbor) external {
//!         (bool valid, bytes32 stateHash, uint64 round) = VERIFIER.verifyUnicityCertificate(ucCbor);
//!         require(valid, "Invalid UC");
//!         // ... use certified stateHash ...
//!     }
//! }
//! ```

pub mod precompile;
pub mod trust_base;
pub mod trust_base_updater;

pub use precompile::{init_precompile_trust_base, unicity_verify_precompile, PrecompileError, UNICITY_VERIFY_ADDRESS};
pub use trust_base::UnicityTrustBase;
pub use trust_base_updater::{start_trust_base_updater, TrustBaseUpdateConfig, TrustBaseUpdater};
