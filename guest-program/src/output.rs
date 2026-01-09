use ethrex_common::H256;
use serde::{Deserialize, Serialize};

/// Public output for uni-evm ZK proofs
///
/// This is a minimal output format designed specifically for BFT-Core verification.
/// Unlike ethrex's ProgramOutput which includes L2-specific fields (l1_out_messages,
/// blob_versioned_hash, etc.), this only outputs the two state roots needed for
/// validating state transitions.
///
/// BFT-Core expects exactly 64 bytes: [prev_state_root (32), new_state_root (32)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UniEvmProgramOutput {
    /// Previous state trie root hash (before block execution)
    pub prev_state_root: H256,
    /// New state trie root hash (after block execution)
    pub new_state_root: H256,
}

impl UniEvmProgramOutput {
    /// Create a new output with the given state roots
    pub fn new(prev_state_root: H256, new_state_root: H256) -> Self {
        Self {
            prev_state_root,
            new_state_root,
        }
    }

    /// Encode to 64-byte format for BFT-Core verification
    ///
    /// Format: [prev_state_root (32 bytes) || new_state_root (32 bytes)]
    ///
    /// This matches the expected public values format in bft-core's
    /// sp1-verifier-ffi which validates:
    /// - Bytes 0-31: prev_state_root
    /// - Bytes 32-63: new_state_root
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(64);
        encoded.extend_from_slice(&self.prev_state_root.to_fixed_bytes());
        encoded.extend_from_slice(&self.new_state_root.to_fixed_bytes());

        // Critical: BFT-Core expects exactly 64 bytes
        assert_eq!(
            encoded.len(),
            64,
            "UniEvmProgramOutput must encode to exactly 64 bytes"
        );

        encoded
    }

    /// Decode from 64-byte format
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!(
                "Invalid encoded length: expected 64 bytes, got {}",
                bytes.len()
            ));
        }

        let prev_state_root = H256::from_slice(&bytes[0..32]);
        let new_state_root = H256::from_slice(&bytes[32..64]);

        Ok(Self::new(prev_state_root, new_state_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let prev = H256::from([1u8; 32]);
        let new = H256::from([2u8; 32]);
        let output = UniEvmProgramOutput::new(prev, new);

        let encoded = output.encode();
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[0..32], &[1u8; 32]);
        assert_eq!(&encoded[32..64], &[2u8; 32]);

        let decoded = UniEvmProgramOutput::decode(&encoded).unwrap();
        assert_eq!(decoded, output);
    }

    #[test]
    fn test_decode_invalid_length() {
        let short = vec![0u8; 32];
        let long = vec![0u8; 128];

        assert!(UniEvmProgramOutput::decode(&short).is_err());
        assert!(UniEvmProgramOutput::decode(&long).is_err());
    }
}
