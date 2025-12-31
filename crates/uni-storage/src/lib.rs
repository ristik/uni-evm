//! Persistent storage for uni-evm
//!
//! This module extends ethrex's storage with uni-evm specific data:
//! - Unicity Certificates per block (stored alongside blocks)
//! - ZK proofs per block
//!
//! Uses RocksDB for persistence to ensure reliable state across restarts.

use uni_bft_committer::types::UnicityCertificate;
use rocksdb::{DB, Options, ColumnFamilyDescriptor};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Unicity certificate not found for block {0}")]
    UnicityCertificateNotFound(u64),
    #[error("Proof not found for block {0}")]
    ProofNotFound(u64),
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
    #[error("CBOR serialization error: {0}")]
    SerializationError(String),
}

const CF_UNICITY_CERTIFICATES: &str = "unicity_certificates";
const CF_PROOFS: &str = "proofs";

/// Uni-EVM specific storage extension with RocksDB persistence
pub struct UniStore {
    db: Arc<DB>,
}

impl UniStore {
    /// Create a new uni-evm store with RocksDB backend
    ///
    /// Stores data in: <data_dir>/uni-storage/
    /// Keeps UCs and proofs alongside blocks for reliable certified state persistence
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self, StorageError> {
        let db_path = data_dir.as_ref().join("uni-storage");
        info!("Opening UniStore at {:?}", db_path);

        // Create column family descriptors
        let uc_cf = ColumnFamilyDescriptor::new(CF_UNICITY_CERTIFICATES, Options::default());
        let proof_cf = ColumnFamilyDescriptor::new(CF_PROOFS, Options::default());

        // Open DB with column families
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let db = DB::open_cf_descriptors(&db_opts, db_path, vec![uc_cf, proof_cf])?;

        info!("UniStore opened successfully with RocksDB backend");

        Ok(Self {
            db: Arc::new(db),
        })
    }

    /// Store a unicity certificate for a block
    ///
    /// UC is stored alongside the block it certifies, ensuring that
    /// the certified state can be reliably persisted and resumed.
    pub fn store_unicity_certificate(
        &self,
        block_number: u64,
        uc: UnicityCertificate,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNICITY_CERTIFICATES)
            .ok_or_else(|| StorageError::SerializationError(
                "Column family 'unicity_certificates' not found".to_string()
            ))?;

        // Serialize UC using CBOR
        let mut uc_bytes = Vec::new();
        ciborium::into_writer(&uc, &mut uc_bytes)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        // Store with block number as key
        let key = block_number.to_be_bytes();
        let bytes_len = uc_bytes.len();
        self.db.put_cf(&cf, key, uc_bytes)?;

        debug!("Stored UC for block {} ({} bytes)", block_number, bytes_len);

        Ok(())
    }

    /// Get a unicity certificate for a block
    pub fn get_unicity_certificate(&self, block_number: u64) -> Result<UnicityCertificate, StorageError> {
        let cf = self.db.cf_handle(CF_UNICITY_CERTIFICATES)
            .ok_or_else(|| StorageError::SerializationError(
                "Column family 'unicity_certificates' not found".to_string()
            ))?;

        let key = block_number.to_be_bytes();
        let uc_bytes = self.db.get_cf(&cf, key)?
            .ok_or(StorageError::UnicityCertificateNotFound(block_number))?;

        // Deserialize UC from CBOR
        let uc: UnicityCertificate = ciborium::from_reader(&uc_bytes[..])
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        Ok(uc)
    }

    /// Store a ZK proof for a block
    pub fn store_proof(&self, block_number: u64, proof: Vec<u8>) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| StorageError::SerializationError(
                "Column family 'proofs' not found".to_string()
            ))?;

        let key = block_number.to_be_bytes();
        let proof_len = proof.len();
        self.db.put_cf(&cf, key, proof)?;

        debug!("Stored proof for block {} ({} bytes)", block_number, proof_len);

        Ok(())
    }

    /// Get a ZK proof for a block
    pub fn get_proof(&self, block_number: u64) -> Result<Vec<u8>, StorageError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| StorageError::SerializationError(
                "Column family 'proofs' not found".to_string()
            ))?;

        let key = block_number.to_be_bytes();
        let proof = self.db.get_cf(&cf, key)?
            .ok_or(StorageError::ProofNotFound(block_number))?;

        Ok(proof)
    }

    /// Get the latest block with a unicity certificate
    ///
    /// This is critical for resuming from the last certified state on restart.
    /// Returns None if no UCs have been stored yet.
    pub fn get_latest_certified_block(&self) -> Option<u64> {
        let cf = self.db.cf_handle(CF_UNICITY_CERTIFICATES)?;

        // Iterate backwards from the end to find the latest UC
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_last();

        if iter.valid() {
            let key = iter.key()?;
            if key.len() == 8 {
                let block_number = u64::from_be_bytes([
                    key[0], key[1], key[2], key[3],
                    key[4], key[5], key[6], key[7],
                ]);
                debug!("Latest certified block: {}", block_number);
                return Some(block_number);
            }
        }

        None
    }

    /// Check if a UC exists for a block
    pub fn has_unicity_certificate(&self, block_number: u64) -> bool {
        let cf = match self.db.cf_handle(CF_UNICITY_CERTIFICATES) {
            Some(cf) => cf,
            None => return false,
        };

        let key = block_number.to_be_bytes();
        self.db.get_cf(&cf, key).ok().flatten().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_uc(round: u64) -> UnicityCertificate {
        UnicityCertificate {
            version: 1,
            input_record: Some(uni_bft_committer::types::InputRecord {
                version: 1,
                round_number: round,
                epoch: 0,
                previous_hash: Some(vec![0xaa; 32]),
                hash: Some(vec![0xbb; 32]),
                summary_value: Some(vec![]),
                timestamp: 0,
                block_hash: Some(vec![0xcc; 32]),
                sum_of_earned_fees: 0,
                et_hash: Some(vec![]),
            }),
            tr_hash: None,
            shard_conf_hash: None,
            shard_tree_certificate: uni_bft_committer::types::ShardTreeCertificate {
                shard: vec![],
                sibling_hashes: vec![],
            },
            unicity_tree_certificate: None,
            unicity_seal: None,
        }
    }

    #[test]
    fn test_store_and_retrieve_uc() {
        let temp_dir = TempDir::new().unwrap();
        let store = UniStore::new(temp_dir.path()).unwrap();

        let uc = create_test_uc(100);
        store.store_unicity_certificate(100, uc.clone()).unwrap();

        let retrieved = store.get_unicity_certificate(100).unwrap();
        assert_eq!(
            retrieved.input_record.as_ref().unwrap().round_number,
            100
        );
    }

    #[test]
    fn test_store_and_retrieve_proof() {
        let temp_dir = TempDir::new().unwrap();
        let store = UniStore::new(temp_dir.path()).unwrap();

        let proof = vec![1, 2, 3, 4, 5];
        store.store_proof(100, proof.clone()).unwrap();

        let retrieved = store.get_proof(100).unwrap();
        assert_eq!(retrieved, proof);
    }

    #[test]
    fn test_latest_certified_block() {
        let temp_dir = TempDir::new().unwrap();
        let store = UniStore::new(temp_dir.path()).unwrap();

        // No UCs yet
        assert_eq!(store.get_latest_certified_block(), None);

        // Store some UCs
        store.store_unicity_certificate(100, create_test_uc(100)).unwrap();
        store.store_unicity_certificate(200, create_test_uc(200)).unwrap();
        store.store_unicity_certificate(150, create_test_uc(150)).unwrap();

        // Should return the highest block number
        assert_eq!(store.get_latest_certified_block(), Some(200));
    }

    #[test]
    fn test_persistence_across_reopens() {
        let temp_dir = TempDir::new().unwrap();

        // Create store, add UC, drop it
        {
            let store = UniStore::new(temp_dir.path()).unwrap();
            store.store_unicity_certificate(100, create_test_uc(100)).unwrap();
        }

        // Reopen store and verify UC is still there
        {
            let store = UniStore::new(temp_dir.path()).unwrap();
            let uc = store.get_unicity_certificate(100).unwrap();
            assert_eq!(uc.input_record.as_ref().unwrap().round_number, 100);
            assert_eq!(store.get_latest_certified_block(), Some(100));
        }
    }

    #[test]
    fn test_has_unicity_certificate() {
        let temp_dir = TempDir::new().unwrap();
        let store = UniStore::new(temp_dir.path()).unwrap();

        assert!(!store.has_unicity_certificate(100));

        store.store_unicity_certificate(100, create_test_uc(100)).unwrap();

        assert!(store.has_unicity_certificate(100));
        assert!(!store.has_unicity_certificate(101));
    }
}
