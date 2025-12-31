//! Unicity verification precompile implementation

use ethrex_common::H160;
use bytes::Bytes;
use uni_bft_committer::types::UnicityCertificate;
use tracing::{debug, warn};
use crate::trust_base::UnicityTrustBase;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrecompileError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Invalid CBOR encoding: {0}")]
    InvalidCbor(String),
    #[error("Precompile error: {0}")]
    Other(String),
}

/// Global trust base instance shared with precompile
static GLOBAL_TRUST_BASE: OnceLock<Arc<RwLock<UnicityTrustBase>>> = OnceLock::new();

/// Initialize the global trust base for the precompile
pub fn init_precompile_trust_base(trust_base: Arc<RwLock<UnicityTrustBase>>) {
    if GLOBAL_TRUST_BASE.set(trust_base).is_err() {
        warn!("Trust base already initialized for precompile");
    }
}

/// Get the global trust base (returns None if not initialized)
fn get_trust_base() -> Option<Arc<RwLock<UnicityTrustBase>>> {
    GLOBAL_TRUST_BASE.get().cloned()
}

/// Unicity verification precompile at address 0x100
pub const UNICITY_VERIFY_ADDRESS: H160 = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00,
]);

pub struct UnicityVerifyPrecompile;

/// Gas cost for unicity verification
const UNICITY_VERIFY_BASE_GAS: u64 = 3000;
const UNICITY_VERIFY_PER_BYTE_GAS: u64 = 6;

/// Unicity verification precompile
///
/// # Input (CBOR-encoded UnicityCertificate)
/// - Arbitrary length CBOR bytes
///
/// # Output
/// - 32 bytes: bool valid (1 = valid, 0 = invalid)
/// - 32 bytes: state hash
/// - 8 bytes: round number (big-endian u64)
///
/// # Gas Cost
/// - Base: 3000 gas
/// - Per byte: 6 gas (for CBOR decoding + signature verification)
pub fn unicity_verify_precompile(
    calldata: &Bytes,
    gas_remaining: &mut u64,
) -> Result<Bytes, PrecompileError> {
    debug!("Unicity verify precompile called with {} bytes", calldata.len());

    // Calculate gas cost
    let gas_cost = UNICITY_VERIFY_BASE_GAS + (calldata.len() as u64 * UNICITY_VERIFY_PER_BYTE_GAS);

    if *gas_remaining < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    *gas_remaining -= gas_cost;

    // Deserialize CBOR UnicityCertificate
    let uc: UnicityCertificate = ciborium::from_reader(calldata.as_ref())
        .map_err(|e| PrecompileError::InvalidCbor(format!("{}", e)))?;

    let partition = uc.unicity_tree_certificate.as_ref().map(|u| u.partition).unwrap_or(0);
    let round_number = uc.input_record.as_ref().map(|ir| ir.round_number).unwrap_or(0);

    debug!("Decoded UC: partition={}, round={}", partition, round_number);

    // Verify the Unicity Certificate using the trust base
    let is_valid = verify_with_trust_base(&uc);

    debug!("UC verification result: {}", is_valid);

    // Encode output
    let mut output = Vec::with_capacity(72);

    // 32 bytes: valid flag (padded)
    let mut valid_bytes = [0u8; 32];
    valid_bytes[31] = if is_valid { 1 } else { 0 };
    output.extend_from_slice(&valid_bytes);

    // 32 bytes: state hash (padded if needed)
    let mut state_hash = [0u8; 32];
    if let Some(ref ir) = uc.input_record {
        if let Some(ref hash) = ir.hash {
            let hash_len = hash.len().min(32);
            state_hash[32 - hash_len..].copy_from_slice(&hash[..hash_len]);
        }
    }
    output.extend_from_slice(&state_hash);

    // 8 bytes: round number (big-endian)
    output.extend_from_slice(&round_number.to_be_bytes());

    Ok(Bytes::from(output))
}

/// Verify Unicity Certificate using the trust base
fn verify_with_trust_base(uc: &UnicityCertificate) -> bool {
    // Get the global trust base
    let trust_base_arc = match get_trust_base() {
        Some(tb) => tb,
        None => {
            warn!("Trust base not initialized for precompile - rejecting UC");
            return false;
        }
    };

    // We need to use blocking read since precompiles are synchronous
    // Use tokio::runtime::Handle to access the trust base
    let runtime_handle = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle,
        Err(_) => {
            warn!("No tokio runtime available for trust base verification");
            return false;
        }
    };

    // Block on the async read
    runtime_handle.block_on(async {
        let trust_base = trust_base_arc.read().await;

        // Check if we need an update for this round
        let round_number = uc.input_record.as_ref().map(|ir| ir.round_number).unwrap_or(0);
        if trust_base.needs_update_for_round(round_number) {
            warn!(
                "Trust base missing epoch for round {} - verification failed",
                round_number
            );
            return false;
        }

        // Verify the certificate
        match trust_base.verify_unicity_certificate(uc) {
            Ok(valid) => {
                debug!("UC verification completed: {}", valid);
                valid
            }
            Err(e) => {
                warn!("UC verification error: {}", e);
                false
            }
        }
    })
}

// Note: The wrapper function for ethrex integration is defined in ethrex/crates/vm/levm/src/precompiles.rs
// to avoid circular dependencies

#[cfg(test)]
mod tests {
    use super::*;
    use uni_bft_committer::types::UnicityCertificate;

    #[test]
    fn test_unicity_verify_precompile() {
        let uc = UnicityCertificate {
            version: 1,
            partition: 1,
            shard: 1,
            round_number: 100,
            state_hash: vec![0xaa; 32],
            tr_hash: vec![0xbb; 32],
            signature: vec![0xcc; 64],
        };

        // Serialize to CBOR
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&uc, &mut cbor_bytes).unwrap();

        let mut gas = 100000u64;
        let result = unicity_verify_precompile(&Bytes::from(cbor_bytes), &mut gas);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 72); // 32 + 32 + 8

        // Check valid flag
        assert_eq!(output[31], 1);

        // Check state hash
        assert_eq!(&output[32..64], &vec![0xaa; 32][..]);

        // Check round number
        let round_bytes: [u8; 8] = output[64..72].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(round_bytes), 100);
    }
}
