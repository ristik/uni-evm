//! Proof coordinator for uni-evm
//!
//! Coordinates per-block ZK proof generation using SP1.
//! Unlike ethrex which batches multiple blocks, uni-evm generates one proof per block.

use crate::block_producer::BlockProduced;
use ethrex_storage::Store;
use ethrex_l2_common::prover::ProofFormat;
use ethrex_prover_lib::backend::Backend;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use uni_bft_committer::BftCommitter;
use uni_storage::UniStore;

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
    /// Prover backend (SP1, RISC0, etc.)
    pub prover_backend: Backend,
    /// Elasticity multiplier for EIP-1559
    pub elasticity_multiplier: u64,
}

impl Default for ProofCoordinatorConfig {
    fn default() -> Self {
        Self {
            proof_format: ProofFormat::Compressed, // No Groth16 wrapping
            #[cfg(feature = "sp1")]
            prover_backend: Backend::SP1,
            #[cfg(not(feature = "sp1"))]
            prover_backend: Backend::Exec, // Fallback if SP1 not enabled
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

        // 2. Generate SP1 proof
        let proof_bytes = self.generate_proof(&block, &block_info).await?;

        info!(
            "Generated proof for block {} ({} bytes)",
            block_number,
            proof_bytes.len()
        );

        // 3. Store proof
        self.uni_store
            .store_proof(block_number, proof_bytes.clone())
            .map_err(|e| ProofCoordinatorError::StorageError(e.to_string()))?;

        // 4. Submit to BFT Core L1 (fire-and-forget)
        // The UnicityCertificate will be received asynchronously via callback
        self.submit_to_l1(block_number, block_info, proof_bytes)
            .await?;

        info!(
            "Block {} proof generated and submitted to BFT Core",
            block_number
        );

        Ok(())
    }

    /// Generate ZK proof for a block using SP1
    async fn generate_proof(
        &self,
        block: &ethrex_common::types::Block,
        _block_info: &BlockProduced,
    ) -> Result<Vec<u8>, ProofCoordinatorError> {
        use guest_program::input::ProgramInput;
        use ethrex_prover_lib::{prove, to_batch_proof};
        use ethrex_common::types::fee_config::FeeConfig;

        info!("Generating SP1 proof for block {}", block.header.number);

        // 1. Generate execution witness
        // The witness contains all state data needed for stateless execution inside the zkVM
        let blocks = vec![block.clone()];
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

        // 2. Prepare ProverInputData
        let program_input = ProgramInput {
            blocks: vec![block.clone()],
            execution_witness,
            elasticity_multiplier: self.config.elasticity_multiplier,
            fee_configs: Some(vec![FeeConfig::default()]), // One default FeeConfig per block
            blob_commitment: [0; 48], // Not using blobs
            blob_proof: [0; 48],
        };

        info!(
            "Prepared program input for block {}, proving with {:?}",
            block.header.number, self.config.prover_backend
        );

        // 3. Generate the proof using ethrex's prove function
        // This calls the appropriate backend (SP1, RISC0, etc.) based on prover_backend
        let proof_output = prove(
            self.config.prover_backend,
            program_input,
            self.config.proof_format,
        )
        .map_err(|e| {
            ProofCoordinatorError::ProverError(format!("Failed to generate proof: {}", e))
        })?;

        info!(
            "Generated raw proof for block {}, converting to batch proof format",
            block.header.number
        );

        // 4. Convert to BatchProof (contains proof bytes + other metadata)
        let batch_proof = to_batch_proof(proof_output, self.config.proof_format).map_err(|e| {
            ProofCoordinatorError::ProverError(format!("Failed to convert to batch proof: {}", e))
        })?;

        // 5. Extract proof bytes (use compressed format or dummy for Exec backend)
        let proof_bytes = batch_proof
            .compressed()
            .unwrap_or_else(|| {
                // Exec backend doesn't generate actual proofs, use dummy bytes
                warn!("No compressed proof available (using Exec backend), generating dummy proof bytes");
                vec![0xDE, 0xAD, 0xBE, 0xEF] // 4-byte dummy proof
            });

        info!(
            "Successfully generated proof for block {} ({} bytes, format: {:?})",
            block.header.number,
            proof_bytes.len(),
            self.config.proof_format
        );

        // 6. Return the proof bytes
        Ok(proof_bytes)
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
