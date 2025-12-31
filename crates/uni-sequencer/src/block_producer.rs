//! Block producer for uni-evm
//!
//! Simplified version of ethrex's block producer without:
//! - L1 message fetching from Ethereum
//! - Privileged transactions
//! - Batch management

use crate::block_finalizer::{BlockFinalizerHandle, BlockFinalized, PendingBlock};
use ethrex_blockchain::{
    Blockchain, error::ChainError,
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{Address, H256, types::BlockNumber};
use ethrex_storage::Store;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Error)]
pub enum BlockProducerError {
    #[error("Blockchain error: {0}")]
    BlockchainError(#[from] ChainError),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Failed to get latest block")]
    NoLatestBlock,
    #[error("No transactions available for block")]
    NoTransactions,
}

impl From<ethrex_storage::error::StoreError> for BlockProducerError {
    fn from(err: ethrex_storage::error::StoreError) -> Self {
        BlockProducerError::StorageError(err.to_string())
    }
}

/// Configuration for block producer
#[derive(Debug, Clone)]
pub struct BlockProducerConfig {
    /// Block production interval in milliseconds
    pub block_time_ms: u64,
    /// Fee recipient (coinbase) address
    pub coinbase_address: Address,
    /// Maximum gas per block
    pub gas_limit: u64,
    /// Elasticity multiplier for gas limit
    pub elasticity_multiplier: u64,
}

impl Default for BlockProducerConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 1000, // 1 second blocks
            coinbase_address: Address::zero(),
            gas_limit: 30_000_000,
            elasticity_multiplier: 2,
        }
    }
}

/// Block produced event sent to proof coordinator
#[derive(Debug, Clone)]
pub struct BlockProduced {
    pub block_number: BlockNumber,
    pub block_hash: H256,
    pub parent_state_root: H256,
    pub state_root: H256,
    pub tx_count: usize,
}

/// Block producer - creates new blocks at regular intervals
pub struct BlockProducer {
    config: BlockProducerConfig,
    blockchain: Arc<Blockchain>,
    store: Arc<Store>,
    block_tx: mpsc::Sender<BlockProduced>,
    finalizer_handle: BlockFinalizerHandle,
    finalized_rx: mpsc::Receiver<BlockFinalized>,
}

impl BlockProducer {
    /// Create a new block producer
    pub fn new(
        config: BlockProducerConfig,
        blockchain: Arc<Blockchain>,
        store: Arc<Store>,
        block_tx: mpsc::Sender<BlockProduced>,
        finalizer_handle: BlockFinalizerHandle,
        finalized_rx: mpsc::Receiver<BlockFinalized>,
    ) -> Self {
        info!(
            "Block producer initialized: {}ms interval, gas_limit: {}",
            config.block_time_ms, config.gas_limit
        );
        info!("Block producer will wait for UC before producing next block");

        Self {
            config,
            blockchain,
            store,
            block_tx,
            finalizer_handle,
            finalized_rx,
        }
    }

    /// Start block production loop
    /// SYNCHRONOUS: Wait for transactions → Produce block → Wait for UC → Repeat
    pub async fn run(mut self) -> Result<(), BlockProducerError> {
        info!("Starting synchronous block producer (UC-gated)");
        info!("Block production sequence: wait for txs → produce → prove → submit → wait for UC → repeat");
        info!("T1 timeout: {}ms (time window to collect transactions)", self.config.block_time_ms);
        info!("⏳ Waiting for transactions before producing first block...");

        'outer: loop {
            // Step 1: Wait for FIRST transaction (check mempool without producing)
            loop {
                // Check if there are any pending transactions in mempool
                match self.blockchain.mempool.status() {
                    Ok(count) if count > 0 => {
                        // Found first transaction, start T1 timeout window
                        info!("First transaction detected ({} tx in mempool), starting T1 timeout window ({}ms)",
                              count, self.config.block_time_ms);
                        break;
                    }
                    Ok(_) => {
                        // No transactions yet, wait and retry
                        debug!("No transactions in mempool, waiting 100ms before retry");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => {
                        error!("❌ Failed to check mempool: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }

            // Step 2: T1 timeout window - collect more transactions
            info!("⏳ Collecting transactions for {}ms (T1 timeout window)...", self.config.block_time_ms);
            tokio::time::sleep(Duration::from_millis(self.config.block_time_ms)).await;

            // Step 3: T1 expired, produce block with all collected transactions
            let block_info = loop {
                match self.produce_block().await {
                    Ok(block_info) => {
                        // Successfully produced block with transactions
                        break block_info;
                    }
                    Err(BlockProducerError::NoTransactions) => {
                        // This can happen if transactions became invalid due to:
                        // 1. Wrong nonce after previous block
                        // 2. Insufficient fees (base_fee increased)
                        // 3. ethrex issue #680 (mempool doesn't validate against current state)
                        error!("⚠️  No valid transactions after T1 timeout!");
                        error!("   Detected {} txs in mempool, but couldn't include any",
                               self.blockchain.mempool.status().unwrap_or(0));
                        error!("   Likely cause: transactions filtered out by base_fee or invalid nonce");
                        error!("   → Clearing mempool and waiting for new transactions");

                        // Clear the mempool to remove invalid transactions
                        // This prevents infinite loop with stale/invalid txs
                        match self.blockchain.mempool.content() {
                            Ok(txs) => {
                                let count = txs.len();
                                for tx in txs {
                                    let _ = self.blockchain.mempool.remove_transaction(&tx.hash());
                                }
                                error!("   Removed {} invalid transactions from mempool", count);
                            }
                            Err(e) => {
                                error!("   Failed to clear mempool: {}", e);
                            }
                        }

                        // Break to outer loop to wait for new transactions
                        continue 'outer;
                    }
                    Err(e) => {
                        error!("❌ Failed to produce block: {}", e);
                        error!("   Error type: {:?}", e);

                        // Check if this is a state-related error
                        let error_msg = format!("{}", e);
                        if error_msg.contains("state root") || error_msg.contains("DB error") {
                            error!("   This appears to be a STATE ERROR - blockchain state may be corrupted");
                            error!("   Latest block in storage: {}", self.store.get_latest_block_number().await.unwrap_or(0));
                            error!("   This error may persist on restart");
                        }

                        // Wait before retrying on other errors
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            };

            info!(
                "✓ Block {} produced with {} transaction(s) (hash: {:?})",
                block_info.block_number,
                block_info.tx_count,
                block_info.block_hash,
            );

            // Step 2: Notify proof coordinator (will generate proof and submit to BFT Core)
            if let Err(e) = self.block_tx.send(block_info.clone()).await {
                error!("Failed to send block to proof coordinator: {}", e);
                continue;
            }

            // Step 3: Wait for UC before producing next block
            info!("⏳ Waiting for UC for block {} before producing next block...", block_info.block_number);

            let finalized_block_num = match self.finalized_rx.recv().await {
                Some(finalized) => {
                    if finalized.block_number == block_info.block_number {
                        info!("✓ UC received for block {}, ready to produce next block", finalized.block_number);
                    } else {
                        warn!(
                            "UC received for block {} but expected {}, continuing anyway",
                            finalized.block_number, block_info.block_number
                        );
                    }
                    finalized.block_number
                }
                None => {
                    error!("Finalization channel closed, stopping block producer");
                    return Ok(());
                }
            };

            // Step 4: Continue to next block production cycle
            info!("✓ Block {} finalized, continuing to next block production cycle", finalized_block_num);
        }
    }

    /// Produce a single block
    async fn produce_block(&self) -> Result<BlockProduced, BlockProducerError> {
        // Get parent block
        let latest_block_number = self.store.get_latest_block_number().await?;

        debug!("Attempting to produce block {} (building on parent block {})",
               latest_block_number + 1, latest_block_number);

        let parent_hash = self
            .store
            .get_canonical_block_hash(latest_block_number)
            .await?
            .ok_or(BlockProducerError::NoLatestBlock)?;

        let parent_header = self
            .store
            .get_block_header_by_hash(parent_hash)?
            .ok_or(BlockProducerError::NoLatestBlock)?;

        let parent_state_root = parent_header.state_root;

        debug!(
            "Parent block {}: hash={:?}, state_root={:?}",
            latest_block_number, parent_hash, parent_state_root
        );

        // Calculate timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BlockProducerError::StorageError(e.to_string()))?
            .as_secs();

        // Build payload args
        let payload_args = BuildPayloadArgs {
            parent: parent_hash,
            timestamp,
            fee_recipient: self.config.coinbase_address,
            random: H256::zero(), // Can be from beacon chain if needed
            withdrawals: None,    // No withdrawals for L2
            beacon_root: Some(H256::zero()),    // Set to zero for L2 (EIP-4788 requirement)
            version: 1,
            elasticity_multiplier: self.config.elasticity_multiplier,
            gas_ceil: self.config.gas_limit,
        };

        // Create empty payload
        // create_payload signature: (args: &BuildPayloadArgs, store: &Store, extra_data: Bytes)
        let extra_data = ethrex_common::Bytes::new(); // Empty extra data
        let mut payload = create_payload(&payload_args, &self.store, extra_data)?;

        // Set gas limit
        payload.header.gas_limit = self.config.gas_limit;

        // Build payload (fill with transactions from mempool)
        let build_result = self.blockchain.build_payload(payload)?;

        // Get block info from the built payload
        let block_hash = build_result.payload.hash();
        let block_number = build_result.payload.header.number;
        let state_root = build_result.payload.header.state_root;
        let tx_count = build_result.payload.body.transactions.len();

        // Check if block has transactions - we only produce blocks with transactions
        if tx_count == 0 {
            debug!("Block {} has no transactions, skipping block production", block_number);
            return Err(BlockProducerError::NoTransactions);
        }

        info!("Block {} includes {} transaction(s) from mempool", block_number, tx_count);

        // TODO: Validate the block - validate_block API changed
        // validate_block signature has changed, needs additional parameters
        // validate_block(&build_result.payload, &self.store)?;

        debug!("Storing block {} with hash {:?}", block_number, block_hash);

        // Store block AND mark as canonical (needed for proof generation)
        self.store.add_block(build_result.payload.clone()).await?;

        // Mark block as canonical so proof coordinator can read it
        // Note: This makes the block readable but we still track UC-certification separately
        self.store
            .forkchoice_update(vec![], block_number, block_hash, None, None)
            .await?;

        // CRITICAL: Clear processed transactions from mempool
        // After block production, remove all transactions that were included
        // This prevents them from being considered for the next block
        for tx in &build_result.payload.body.transactions {
            let tx_hash = tx.hash();
            if let Err(e) = self.blockchain.mempool.remove_transaction(&tx_hash) {
                debug!("Failed to remove tx {} from mempool: {}", tx_hash, e);
            }
        }
        debug!("Removed {} transactions from mempool after block production",
               build_result.payload.body.transactions.len());

        info!("========================================");
        info!("🔨 BLOCK PRODUCED");
        info!("========================================");
        info!("Block number:        {}", block_number);
        info!("Block hash:          {:?}", block_hash);
        info!("State root:          {:?}", state_root);
        info!("Parent state root:   {:?}", parent_state_root);
        info!("Gas used:            {}", build_result.payload.header.gas_used);
        info!("Transactions:        {}", tx_count);
        info!("Status:              PENDING UC");
        info!("========================================");

        // Notify finalizer that block is pending UC
        if let Err(e) = self.finalizer_handle
            .notify_block_produced(PendingBlock {
                block_number,
                block_hash,
                state_root,
                parent_state_root,
            })
            .await
        {
            error!("Failed to notify finalizer of block {}: {}", block_number, e);
        }

        Ok(BlockProduced {
            block_number,
            block_hash,
            parent_state_root,
            state_root,
            tx_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = BlockProducerConfig::default();
        assert_eq!(config.block_time_ms, 1000);
        assert_eq!(config.gas_limit, 30_000_000);
    }
}
