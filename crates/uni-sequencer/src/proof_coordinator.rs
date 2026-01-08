//! Proof coordinator for uni-evm
//!
//! Coordinates per-block ZK proof generation using SP1.
//! Unlike ethrex which batches multiple blocks, uni-evm generates one proof per block.

use crate::block_producer::BlockProduced;
use ethrex_common::H256;
use ethrex_storage::Store;
use ethrex_l2_common::prover::ProofFormat;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use uni_bft_committer::BftCommitter;
use uni_storage::UniStore;

/// Prover backend type for uni-evm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverBackend {
    /// Exec mode - dummy proofs for testing
    Exec,
    /// SP1 mode - real ZK proofs
    Sp1,
}

#[derive(Debug, Error)]
pub enum ProofCoordinatorError {
    #[error("Prover error: {0}")]
    ProverError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Committer error: {0}")]
    CommitterError(String),
    #[error("Block not found: {0}")]
    BlockNotFound(u64),
}

impl From<ethrex_storage::error::StoreError> for ProofCoordinatorError {
    fn from(err: ethrex_storage::error::StoreError) -> Self {
        ProofCoordinatorError::StorageError(err.to_string())
    }
}

/// Configuration for proof coordinator
#[derive(Debug, Clone, Copy)]
pub struct ProofCoordinatorConfig {
    /// Proof format (Compressed for BFT Core)
    pub proof_format: ProofFormat,
    /// Prover backend (Exec or Sp1)
    pub prover_backend: ProverBackend,
    /// Elasticity multiplier for EIP-1559
    pub elasticity_multiplier: u64,
}

impl Default for ProofCoordinatorConfig {
    fn default() -> Self {
        Self {
            proof_format: ProofFormat::Compressed, // No Groth16 wrapping
            #[cfg(feature = "sp1")]
            prover_backend: ProverBackend::Sp1,
            #[cfg(not(feature = "sp1"))]
            prover_backend: ProverBackend::Exec, // Fallback if SP1 not enabled
            elasticity_multiplier: 2, // Standard EIP-1559 value
        }
    }
}

/// Proof coordinator - manages per-block proving and L1 submission
pub struct ProofCoordinator {
    config: ProofCoordinatorConfig,
    store: Arc<Store>,
    uni_store: Arc<UniStore>,
    bft_committer: Arc<Mutex<BftCommitter>>,
    block_rx: mpsc::Receiver<BlockProduced>,
    blockchain: Arc<ethrex_blockchain::Blockchain>,
}

impl ProofCoordinator {
    /// Create a new proof coordinator
    pub fn new(
        config: ProofCoordinatorConfig,
        store: Arc<Store>,
        uni_store: Arc<UniStore>,
        bft_committer: Arc<Mutex<BftCommitter>>,
        block_rx: mpsc::Receiver<BlockProduced>,
        blockchain: Arc<ethrex_blockchain::Blockchain>,
    ) -> Self {
        info!(
            "Proof coordinator initialized: {:?}, {:?}",
            config.proof_format, config.prover_backend
        );

        Self {
            config,
            store,
            uni_store,
            bft_committer,
            block_rx,
            blockchain,
        }
    }

    /// Run the proof coordinator loop
    pub async fn run(mut self) -> Result<(), ProofCoordinatorError> {
        info!("Starting proof coordinator");

        // Initialize prover (if needed)
        // Note: init_prover is for network prover mode, we're using direct proving
        info!("Prover backend: {:?}", self.config.prover_backend);

        // Process blocks as they arrive
        while let Some(block_info) = self.block_rx.recv().await {
            info!("Received block {} for proving", block_info.block_number);

            if let Err(e) = self.process_block(block_info).await {
                error!("Failed to process block: {}", e);
                // Continue processing next blocks even if one fails
            }
        }

        warn!("Block channel closed, proof coordinator stopping");
        Ok(())
    }

    /// Process a block: generate proof and submit to L1
    async fn process_block(&self, block_info: BlockProduced) -> Result<(), ProofCoordinatorError> {
        let block_number = block_info.block_number;
        info!("Processing block {} for proving", block_number);

        // 1. Fetch block from storage
        let block = self
            .store
            .get_block_by_number(block_number)
            .await?
            .ok_or(ProofCoordinatorError::BlockNotFound(block_number))?;

        debug!("Fetched block {} for proving", block_number);

        // 2. Check if this is genesis block (no previous UC available, h' = nil)
        let is_genesis = block_info.parent_state_root == H256::zero();
        // let is_genesis = if block_number == 0 {
        //     // Block 0: check if we have a genesis UC (round 0)
        //     // self.uni_store.get_unicity_certificate(0).is_err()
        //     self.uni_store.get_unicity_certificate(0).is_err()
        // } else {
        //     // Block N>0: check if we have UC from previous round
        //     self.uni_store.get_unicity_certificate(block_number - 1).is_err()
        // };

        let proof_bytes = if is_genesis {
            info!("⭐ Genesis block {} - skipping proof generation (no previous state)", block_number);
            vec![] // Empty proof for genesis
        } else {
            // 3. Generate SP1 proof for non-genesis blocks
            let proof = self.generate_proof(&block, &block_info).await?;
            info!(
                "Generated proof for block {} ({} bytes)",
                block_number,
                proof.len()
            );
            proof
        };

        // 4. Store proof (empty for genesis)
        self.uni_store
            .store_proof(block_number, proof_bytes.clone())
            .map_err(|e| ProofCoordinatorError::StorageError(e.to_string()))?;

        // 5. Submit to BFT Core L1 (fire-and-forget)
        // The UnicityCertificate will be received asynchronously via callback
        self.submit_to_l1(block_number, block_info, proof_bytes)
            .await?;

        if is_genesis {
            info!(
                "Block {} (genesis) submitted to BFT Core without proof",
                block_number
            );
        } else {
            info!(
                "Block {} proof generated and submitted to BFT Core",
                block_number
            );
        }

        Ok(())
    }

    /// Generate ZK proof for a block using SP1
    async fn generate_proof(
        &self,
        block: &ethrex_common::types::Block,
        _block_info: &BlockProduced,
    ) -> Result<Vec<u8>, ProofCoordinatorError> {
        use guest_program::input::ProgramInput;
        use ethrex_prover_lib::backend::Backend;
        use ethrex_common::types::fee_config::FeeConfig;

        // 1. Generate execution witness
        // The witness contains all state data needed for stateless execution inside the zkVM
        let blocks = vec![block.clone()];

        info!(
            "Block {} details: {} transactions, {} ommers, gas_used: {}, gas_limit: {}",
            block.header.number,
            block.body.transactions.len(),
            block.body.ommers.len(),
            block.header.gas_used,
            block.header.gas_limit
        );

        // Log transaction details
        for (i, tx) in block.body.transactions.iter().enumerate() {
            info!(
                "  Transaction {}: to={:?}, value={}, gas_limit={}, input_len={}",
                i,
                tx.to(),
                tx.value(),
                tx.gas_limit(),
                tx.data().len()
            );
        }

        let execution_witness = self
            .blockchain
            .generate_witness_for_blocks(&blocks)
            .await
            .map_err(|e| {
                ProofCoordinatorError::ProverError(format!(
                    "Failed to generate execution witness: {}",
                    e
                ))
            })?;

        info!(
            "Generated execution witness for block {} ({} codes, {} keys)",
            block.header.number,
            execution_witness.codes.len(),
            execution_witness.keys.len()
        );

        for (i, code) in execution_witness.codes.iter().enumerate().take(5) {
            debug!("  Code {}: size={} bytes", i, code.len());
        }

        // 2. Prepare ProgramInput
        let program_input = ProgramInput {
            blocks: vec![block.clone()],
            execution_witness,
            elasticity_multiplier: self.config.elasticity_multiplier,
            fee_configs: Some(vec![FeeConfig::default()]), // One default FeeConfig per block
            blob_commitment: [0; 48], // Not using blobs
            blob_proof: [0; 48],
        };

        // 3. Generate proof based on backend
        match self.config.prover_backend {
            ProverBackend::Exec => {
                // Exec backend: dummy proofs for testing
                warn!(
                    "Using Exec backend for block {} - generating dummy proof",
                    block.header.number
                );
                Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
            }

            #[cfg(feature = "sp1")]
            ProverBackend::Sp1 => {
                info!(
                    "Generating SP1 proof for block {} using ethrex SP1 backend",
                    block.header.number
                );

                // Use ethrex's proven SP1 backend which works with rkyv
                use ethrex_prover_lib::backend::sp1::prove;
                use ethrex_l2_common::prover::ProofFormat;

                let proof_output = prove(program_input, ProofFormat::Compressed).map_err(|e| {
                    ProofCoordinatorError::ProverError(format!("SP1 proving failed: {}", e))
                })?;

                // Extract public values (should contain state roots)
                let public_values = proof_output.proof.public_values.to_vec();
                info!(
                    "Generated SP1 proof for block {}: {} public value bytes",
                    block.header.number,
                    public_values.len()
                );

                // Serialize proof for BFT-Core (bincode format)
                let proof_bytes = bincode::serialize(&proof_output.proof).map_err(|e| {
                    ProofCoordinatorError::ProverError(format!(
                        "Failed to serialize proof: {}",
                        e
                    ))
                })?;

                info!(
                    "Serialized SP1 proof: {} bytes total",
                    proof_bytes.len()
                );

                Ok(proof_bytes)
            }

            // Note: Backend::SP1 case is only available with sp1 feature enabled
            // If sp1 is not enabled, get_backend() in config.rs will return an error
            // before we reach this code, so we don't need a fallback case here.

            _ => Err(ProofCoordinatorError::ProverError(format!(
                "Unsupported backend: {:?}",
                self.config.prover_backend
            ))),
        }
    }

    /// Submit proof to BFT Core L1
    /// Note: This is fire-and-forget. The UnicityCertificate will be received
    /// asynchronously via the callback configured on the BFT client.
    async fn submit_to_l1(
        &self,
        block_number: u64,
        block_info: BlockProduced,
        proof: Vec<u8>,
    ) -> Result<(), ProofCoordinatorError> {
        debug!("Submitting block {} to BFT Core", block_number);

        // CRITICAL: Use last UC's state hash as previous_hash, NOT parent block's state_root
        // This ensures we extend from BFT Core's certified state, not ethrex's state
        let previous_certified_state = if block_number == 1 {
            // For block 1, query the genesis UC (round 0) from BFT Core
            match self.uni_store.get_unicity_certificate(0) {
                Ok(genesis_uc) => {
                    let genesis_state = genesis_uc.input_record
                        .as_ref()
                        .and_then(|ir| ir.hash.as_ref())
                        .map(|h| ethrex_common::H256::from_slice(&h[..32]))
                        .unwrap_or(ethrex_common::H256::zero());

                    info!(
                        "Using BFT Core genesis state (UC round 0) as previous_hash for block 1: {:?}",
                        genesis_state
                    );
                    genesis_state
                }
                Err(e) => {
                    warn!(
                        "Failed to get genesis UC from storage: {} - falling back to parent state_root",
                        e
                    );
                    warn!("This may cause certification failure if genesis states don't match!");
                    block_info.parent_state_root
                }
            }
        } else {
            // For block N (N>1), use the UC from block N-1
            let prev_round = block_number - 1;
            match self.uni_store.get_unicity_certificate(prev_round) {
                Ok(prev_uc) => {
                    let prev_certified_state = prev_uc.input_record
                        .as_ref()
                        .and_then(|ir| ir.hash.as_ref())
                        .map(|h| ethrex_common::H256::from_slice(&h[..32]))
                        .unwrap_or(ethrex_common::H256::zero());

                    info!(
                        "Using UC round {} state as previous_hash for block {}: {:?}",
                        prev_round, block_number, prev_certified_state
                    );
                    prev_certified_state
                }
                Err(e) => {
                    error!(
                        "Failed to get UC for round {} - cannot build certification request: {}",
                        prev_round, e
                    );
                    return Err(ProofCoordinatorError::StorageError(
                        format!("Missing UC for round {}", prev_round)
                    ));
                }
            }
        };

        let mut committer = self.bft_committer.lock().await;

        committer
            .commit_block(
                block_number,
                block_info.block_hash,     // Block hash
                previous_certified_state,  // Use UC state hash, not parent block state_root
                block_info.state_root,
                proof,
            )
            .await
            .map_err(|e| ProofCoordinatorError::CommitterError(e.to_string()))?;

        info!(
            "Submitted BlockCertification request for block {} to BFT Core",
            block_number
        );
        info!(
            "  previous_hash (from UC round {}): {:?}",
            if block_number == 1 { 0 } else { block_number - 1 },
            previous_certified_state
        );
        info!(
            "  new_state_hash (from block): {:?}",
            block_info.state_root
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ProofCoordinatorConfig::default();
        assert_eq!(config.proof_format, ProofFormat::Compressed);
        #[cfg(feature = "sp1")]
        assert_eq!(config.prover_backend, Backend::SP1);
    }
}
