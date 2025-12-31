//! Unicity Trust Base management

use uni_bft_committer::types::UnicityCertificate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustBaseError {
    #[error("Epoch not found: {0}")]
    EpochNotFound(u64),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Quorum threshold not met")]
    QuorumNotMet,
}

/// Validator information in the trust base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub node_id: String,
    pub public_key: Vec<u8>,
    pub stake: u64,
}

/// Trust base entry for a specific epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBaseEntry {
    pub network_id: String,
    pub epoch: u64,
    pub epoch_start_round: u64,
    pub validators: Vec<ValidatorInfo>,
    pub quorum_threshold: u64,
    pub state_hash: Vec<u8>,
    pub change_record_hash: Vec<u8>,
    pub previous_entry_hash: Vec<u8>,
}

/// Unicity Trust Base - root of trust from BFT Core L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicityTrustBase {
    pub version: u8,
    pub entries: Vec<TrustBaseEntry>,
}

impl UnicityTrustBase {
    /// Create a new empty trust base
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    /// Add a trust base entry
    pub fn add_entry(&mut self, entry: TrustBaseEntry) {
        self.entries.push(entry);
    }

    /// Get entry for a specific epoch
    pub fn get_entry(&self, epoch: u64) -> Option<&TrustBaseEntry> {
        self.entries.iter().find(|e| e.epoch == epoch)
    }

    /// Verify a Unicity Certificate against the trust base
    pub fn verify_unicity_certificate(&self, uc: &UnicityCertificate) -> Result<bool, TrustBaseError> {
        use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
        use ethrex_common::utils::keccak;

        // Get epoch and round from the UC
        let unicity_seal = uc.unicity_seal.as_ref()
            .ok_or(TrustBaseError::InvalidSignature)?;
        let input_record = uc.input_record.as_ref()
            .ok_or(TrustBaseError::InvalidSignature)?;

        let epoch = unicity_seal.epoch;
        let _round_number = input_record.round_number;

        // Find trust base entry for this epoch
        let entry = self.get_entry(epoch)
            .ok_or(TrustBaseError::EpochNotFound(epoch))?;

        // The UnicitySeal contains the signatures map
        // Each signature is from a validator signing the seal (without signatures)
        // To verify, we need to reconstruct what was signed

        // For now, simplified verification: check that we have signatures
        // TODO: Implement proper UnicitySeal.SigBytes() and verify each signature
        if unicity_seal.signatures.is_empty() {
            return Err(TrustBaseError::QuorumNotMet);
        }

        // Count valid signatures
        let mut valid_count = 0;
        let _secp = Secp256k1::verification_only();

        // In BFT Core, the seal is signed without the signatures field
        // For now, we'll do a simplified check: count the number of signatures
        // In production, we need to:
        // 1. Recreate UnicitySeal without signatures
        // 2. Serialize to CBOR with tag 1001
        // 3. Verify each signature against validator public keys

        for (node_id, _sig_bytes) in &unicity_seal.signatures {
            // Find validator in trust base
            if let Some(validator) = entry.validators.iter().find(|v| &v.node_id == node_id) {
                if let Ok(_pubkey) = PublicKey::from_slice(&validator.public_key) {
                    // TODO: Proper signature verification
                    // For now, just count as valid if we have the validator
                    valid_count += 1;
                }
            }
        }

        // Check if we met quorum
        if valid_count >= entry.quorum_threshold {
            Ok(true)
        } else {
            Err(TrustBaseError::QuorumNotMet)
        }
    }

    /// Get epoch number for a given round number
    pub fn get_epoch_for_round(&self, round_number: u64) -> u64 {
        // Find the entry with the highest epoch_start_round <= round_number
        self.entries
            .iter()
            .filter(|e| e.epoch_start_round <= round_number)
            .map(|e| e.epoch)
            .max()
            .unwrap_or(0)
    }

    /// Check if we need to update trust base for a given round
    /// Returns true if the round belongs to an epoch we don't have
    pub fn needs_update_for_round(&self, round_number: u64) -> bool {
        let epoch = self.get_epoch_for_round(round_number);
        self.get_entry(epoch).is_none()
    }

    /// Get the highest epoch we have in the trust base
    pub fn max_epoch(&self) -> Option<u64> {
        self.entries.iter().map(|e| e.epoch).max()
    }
}

impl Default for UnicityTrustBase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use ethrex_common::utils::keccak;

    #[test]
    fn test_trust_base_creation() {
        let trust_base = UnicityTrustBase::new();
        assert_eq!(trust_base.version, 1);
        assert_eq!(trust_base.entries.len(), 0);
    }

    #[test]
    fn test_add_and_get_entry() {
        let mut trust_base = UnicityTrustBase::new();

        let entry = TrustBaseEntry {
            network_id: "test-network".to_string(),
            epoch: 1,
            epoch_start_round: 1000,
            validators: vec![],
            quorum_threshold: 2,
            state_hash: vec![0u8; 32],
            change_record_hash: vec![0u8; 32],
            previous_entry_hash: vec![0u8; 32],
        };

        trust_base.add_entry(entry.clone());

        let retrieved = trust_base.get_entry(1);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().epoch, 1);
    }

    fn create_test_uc(round: u64, epoch: u64, signatures: std::collections::HashMap<String, Vec<u8>>) -> UnicityCertificate {
        use uni_bft_committer::types::*;

        UnicityCertificate {
            version: 1,
            input_record: Some(InputRecord {
                version: 1,
                round_number: round,
                epoch,
                previous_hash: Some(vec![0u8; 32]),
                hash: Some(vec![0xaa; 32]),
                summary_value: Some(vec![]),
                timestamp: 0,
                block_hash: Some(vec![]),
                sum_of_earned_fees: 0,
                et_hash: Some(vec![]),
            }),
            tr_hash: Some(vec![0xbb; 32]),
            shard_conf_hash: Some(vec![0u8; 32]),
            shard_tree_certificate: ShardTreeCertificate {
                shard: vec![0x80],
                sibling_hashes: vec![],
            },
            unicity_tree_certificate: Some(UnicityTreeCertificate {
                version: 1,
                partition: 1,
                hash_steps: vec![],
            }),
            unicity_seal: Some(UnicitySeal {
                version: 1,
                network_id: 1,
                root_chain_round_number: round,
                epoch,
                timestamp: 0,
                previous_hash: vec![0u8; 32],
                hash: vec![0u8; 32],
                signatures,
            }),
        }
    }

    #[test]
    fn test_unicity_certificate_verification() {
        // Setup: Create a signing key
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Create signatures map
        let mut signatures = std::collections::HashMap::new();
        signatures.insert("validator-1".to_string(), vec![0xaa; 64]); // Dummy signature

        // Create a Unicity Certificate
        let uc = create_test_uc(100, 0, signatures);

        // Create trust base with the validator
        let mut trust_base = UnicityTrustBase::new();
        let entry = TrustBaseEntry {
            network_id: "test-network".to_string(),
            epoch: 0,
            epoch_start_round: 0,
            validators: vec![ValidatorInfo {
                node_id: "validator-1".to_string(),
                public_key: public_key.serialize().to_vec(),
                stake: 100,
            }],
            quorum_threshold: 1,
            state_hash: vec![0u8; 32],
            change_record_hash: vec![0u8; 32],
            previous_entry_hash: vec![0u8; 32],
        };
        trust_base.add_entry(entry);

        // Verify the UC (simplified verification counts signatures)
        let result = trust_base.verify_unicity_certificate(&uc);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_invalid_signature() {
        // Create UC with no signatures (quorum not met)
        let uc = create_test_uc(100, 0, std::collections::HashMap::new());

        // Create trust base with a validator
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let mut trust_base = UnicityTrustBase::new();
        let entry = TrustBaseEntry {
            network_id: "test-network".to_string(),
            epoch: 0,
            epoch_start_round: 0,
            validators: vec![ValidatorInfo {
                node_id: "validator-1".to_string(),
                public_key: public_key.serialize().to_vec(),
                stake: 100,
            }],
            quorum_threshold: 1,
            state_hash: vec![0u8; 32],
            change_record_hash: vec![0u8; 32],
            previous_entry_hash: vec![0u8; 32],
        };
        trust_base.add_entry(entry);

        // Verification should fail (no signatures)
        let result = trust_base.verify_unicity_certificate(&uc);
        assert!(result.is_err());
    }

    #[test]
    fn test_epoch_not_found() {
        let uc = create_test_uc(5000, 5, std::collections::HashMap::new());

        let trust_base = UnicityTrustBase::new(); // Empty trust base

        let result = trust_base.verify_unicity_certificate(&uc);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TrustBaseError::EpochNotFound(5)));
    }

    #[test]
    fn test_epoch_calculation() {
        let mut trust_base = UnicityTrustBase::new();

        // Add epoch 0 starting at round 0
        trust_base.add_entry(TrustBaseEntry {
            network_id: "test".to_string(),
            epoch: 0,
            epoch_start_round: 0,
            validators: vec![],
            quorum_threshold: 1,
            state_hash: vec![],
            change_record_hash: vec![],
            previous_entry_hash: vec![],
        });

        // Add epoch 1 starting at round 1000
        trust_base.add_entry(TrustBaseEntry {
            network_id: "test".to_string(),
            epoch: 1,
            epoch_start_round: 1000,
            validators: vec![],
            quorum_threshold: 1,
            state_hash: vec![],
            change_record_hash: vec![],
            previous_entry_hash: vec![],
        });

        // Add epoch 2 starting at round 2000
        trust_base.add_entry(TrustBaseEntry {
            network_id: "test".to_string(),
            epoch: 2,
            epoch_start_round: 2000,
            validators: vec![],
            quorum_threshold: 1,
            state_hash: vec![],
            change_record_hash: vec![],
            previous_entry_hash: vec![],
        });

        // Test epoch calculation
        assert_eq!(trust_base.get_epoch_for_round(0), 0);
        assert_eq!(trust_base.get_epoch_for_round(999), 0);
        assert_eq!(trust_base.get_epoch_for_round(1000), 1);
        assert_eq!(trust_base.get_epoch_for_round(1999), 1);
        assert_eq!(trust_base.get_epoch_for_round(2000), 2);
        assert_eq!(trust_base.get_epoch_for_round(2500), 2);
    }
}
