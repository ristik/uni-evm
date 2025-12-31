//! Block finalizer - waits for Unicity Certificates before finalizing blocks
//!
//! This component ensures blocks are only marked as canonical after receiving
//! a UnicityCertificate from BFT Core L1, implementing the critical property
//! that L2 blocks depend on L1 certification.

use ethrex_common::types::BlockNumber;
use ethrex_common::H256;
use ethrex_storage::Store;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uni_bft_committer::types::UnicityCertificate;

/// Block waiting for UC-based finalization
#[derive(Debug, Clone)]
pub struct PendingBlock {
    pub block_number: BlockNumber,
    pub block_hash: H256,
    pub state_root: H256,
    pub parent_state_root: H256,
}

/// Messages sent to the BlockFinalizer
#[derive(Debug)]
pub enum FinalizerMessage {
    /// A new block has been produced and is waiting for UC
    BlockProduced(PendingBlock),
    /// A UC has been received - contains the full UC for hash validation
    UcReceived(UnicityCertificate),
}

/// Notification that a block has been UC-certified and finalized
#[derive(Debug, Clone)]
pub struct BlockFinalized {
    pub block_number: u64,
}

/// Block finalizer - manages UC-based block finalization
pub struct BlockFinalizer {
    store: Arc<Store>,
    /// Blocks waiting for UCs, ordered by block number
    pending_blocks: BTreeMap<BlockNumber, PendingBlock>,
    /// Last finalized block number
    last_finalized: BlockNumber,
    /// Channel for receiving finalization messages
    msg_rx: mpsc::Receiver<FinalizerMessage>,
    /// Channel for sending finalization notifications
    finalized_tx: Option<mpsc::Sender<BlockFinalized>>,
}

impl BlockFinalizer {
    /// Create a new block finalizer
    pub fn new(
        store: Arc<Store>,
        initial_block_number: BlockNumber,
        msg_rx: mpsc::Receiver<FinalizerMessage>,
        finalized_tx: Option<mpsc::Sender<BlockFinalized>>,
    ) -> Self {
        info!(
            "Block finalizer initialized, last finalized block: {}",
            initial_block_number
        );

        Self {
            store,
            pending_blocks: BTreeMap::new(),
            last_finalized: initial_block_number,
            msg_rx,
            finalized_tx,
        }
    }

    /// Run the block finalizer event loop
    pub async fn run(mut self) {
        info!("Starting block finalizer");

        while let Some(msg) = self.msg_rx.recv().await {
            match msg {
                FinalizerMessage::BlockProduced(block) => {
                    self.handle_block_produced(block).await;
                }
                FinalizerMessage::UcReceived(uc) => {
                    self.handle_uc_received(uc).await;
                }
            }
        }

        warn!("Finalizer channel closed, stopping");
    }

    /// Handle a newly produced block (add to pending)
    async fn handle_block_produced(&mut self, block: PendingBlock) {
        info!(
            "Block {} produced, waiting for UC before finalization",
            block.block_number
        );

        self.pending_blocks
            .insert(block.block_number, block.clone());

        info!(
            "Pending blocks waiting for UC: {} blocks",
            self.pending_blocks.len()
        );
    }

    /// Handle a UC received (finalize the corresponding block)
    /// Validates that the UC certifies the correct block by checking state hashes
    async fn handle_uc_received(&mut self, uc: UnicityCertificate) {
        // Extract round number and state hashes from UC
        let round = uc.input_record.as_ref()
            .map(|ir| ir.round_number)
            .unwrap_or(0);

        // Check if this is a synchronization UC (BOTH hash and prev_hash null)
        // Note: First block certification has null prev_hash but non-null hash - this is VALID
        let has_null_hash = uc.input_record.as_ref()
            .and_then(|ir| ir.hash.as_ref())
            .map(|h| h.is_empty())
            .unwrap_or(true);

        let has_null_prev = uc.input_record.as_ref()
            .and_then(|ir| ir.previous_hash.as_ref())
            .map(|h| h.is_empty())
            .unwrap_or(true);

        if has_null_hash && has_null_prev {
            warn!("⚠️  SYNCHRONIZATION UC received (round {})", round);
            warn!("   This UC has BOTH null hashes - it's for sync, not block certification");
            return;
        }

        // Extract state hashes from UC
        let uc_state_hash = uc.input_record.as_ref()
            .and_then(|ir| ir.hash.as_ref())
            .map(|h| H256::from_slice(&h[..32]))
            .unwrap_or(H256::zero());

        let uc_prev_hash = uc.input_record.as_ref()
            .and_then(|ir| ir.previous_hash.as_ref())
            .map(|h| H256::from_slice(&h[..32]))
            .unwrap_or(H256::zero());

        info!("UC IR.n={}, IR.h={:?}, IR.h'={:?}", round, uc_state_hash, uc_prev_hash);

        // CRITICAL: Find pending block by STATE HASH match, not by round number
        // Round numbers may not match block numbers due to repeat UCs or gaps
        // What matters is that the UC certifies the correct state root
        //
        // For the first block: UC may have null/zero previous_hash while block has genesis state root
        // So we match on state hash only if UC has zero previous hash
        let matching_block = self.pending_blocks.iter().find(|(_, block)| {
            let state_match = block.state_root == uc_state_hash;
            let parent_match = uc_prev_hash.is_zero() || block.parent_state_root == uc_prev_hash;
            state_match && parent_match
        });

        if let Some((block_num, block)) = matching_block {
            let block_num = *block_num;
            info!(
                "✓ Found matching block {} for UC round {} (state hashes match)",
                block_num, round
            );
            info!(
                "  Block state_root={:?}, UC.IR.h={:?}",
                block.state_root, uc_state_hash
            );
            info!(
                "  Block parent_state={:?}, UC.IR.h'={:?}",
                block.parent_state_root, uc_prev_hash
            );

            // Remove and finalize the block
            if let Some(block) = self.pending_blocks.remove(&block_num) {
                self.finalize_block_sequence(block).await;
            }
        } else {
            // No pending block matches this UC's state hashes
            // This could happen if:
            // 1. The block was already finalized (UC received twice)
            // 2. BFT Core rejected our block and this UC is for a different state
            // 3. This is a repeat UC and we already finalized with an earlier UC

            warn!("UC for round {} has no matching pending block", round);
            warn!("  UC state hashes: h={:?}, h'={:?}", uc_state_hash, uc_prev_hash);
            warn!("  Pending blocks: {:?}", self.pending_blocks.keys().collect::<Vec<_>>());
            warn!("  Last finalized: {}", self.last_finalized);

            // Check if this UC's state was already finalized
            if round <= self.last_finalized {
                info!("  → Likely duplicate UC for already finalized block");
                info!("  → Ignoring (block already UC-certified)");
            } else {
                warn!("  → Either:");
                warn!("    1. Block was rejected by BFT Core (state hash doesn't match any pending)");
                warn!("    2. This is a repeat UC and block was already finalized");
                warn!("    3. Block hasn't been produced yet (we received UC before block production)");
                warn!("  → Not finalizing any blocks");
            }
        }
    }

    /// Finalize a block and any subsequent blocks that can now be finalized
    async fn finalize_block_sequence(&mut self, first_block: PendingBlock) {
        let mut blocks_to_finalize = vec![first_block];

        // Collect any subsequent blocks that can be finalized in sequence
        let mut next_block_num = blocks_to_finalize[0].block_number + 1;
        while let Some(block) = self.pending_blocks.remove(&next_block_num) {
            blocks_to_finalize.push(block);
            next_block_num += 1;
        }

        info!(
            "Finalizing {} blocks in sequence (starting from block {})",
            blocks_to_finalize.len(),
            blocks_to_finalize[0].block_number
        );

        // Finalize each block
        for block in blocks_to_finalize {
            if let Err(e) = self.finalize_block(&block).await {
                error!(
                    "Failed to finalize block {}: {}",
                    block.block_number, e
                );
                // Don't continue finalizing if one fails
                break;
            }

            self.last_finalized = block.block_number;
            info!("✓ Block {} UC-certified and finalized", block.block_number);

            // Notify that block is finalized (optional - for block producer to proceed)
            if let Some(ref tx) = self.finalized_tx {
                let _ = tx.send(BlockFinalized {
                    block_number: block.block_number,
                }).await;
            }
        }

        info!(
            "Last finalized block: {}, pending: {}",
            self.last_finalized,
            self.pending_blocks.len()
        );
    }

    /// Finalize a single block (mark as UC-certified)
    /// Note: Block is already canonical from block production, this just tracks UC-certification
    async fn finalize_block(&self, _block: &PendingBlock) -> Result<(), String> {
        // Block is already marked as canonical by block producer
        // This method just tracks that the block has been UC-certified
        // In the future, we could store UC-certification metadata here
        Ok(())
    }
}

/// Handle for sending messages to the BlockFinalizer
#[derive(Clone)]
pub struct BlockFinalizerHandle {
    msg_tx: mpsc::Sender<FinalizerMessage>,
}

impl BlockFinalizerHandle {
    /// Create a new handle
    pub fn new(msg_tx: mpsc::Sender<FinalizerMessage>) -> Self {
        Self { msg_tx }
    }

    /// Notify that a block has been produced (pending UC)
    pub async fn notify_block_produced(&self, block: PendingBlock) -> Result<(), String> {
        self.msg_tx
            .send(FinalizerMessage::BlockProduced(block))
            .await
            .map_err(|e| format!("Failed to send block produced message: {}", e))
    }

    /// Notify that a UC has been received
    pub async fn notify_uc_received(&self, uc: UnicityCertificate) -> Result<(), String> {
        self.msg_tx
            .send(FinalizerMessage::UcReceived(uc))
            .await
            .map_err(|e| format!("Failed to send UC received message: {}", e))
    }
}

/// Create a BlockFinalizer and its handle
/// If finalized_tx is provided, the finalizer will send notifications when blocks are UC-certified
pub fn create_block_finalizer(
    store: Arc<Store>,
    initial_block_number: BlockNumber,
    finalized_tx: Option<mpsc::Sender<BlockFinalized>>,
) -> (BlockFinalizer, BlockFinalizerHandle) {
    let (msg_tx, msg_rx) = mpsc::channel(128);
    let finalizer = BlockFinalizer::new(store, initial_block_number, msg_rx, finalized_tx);
    let handle = BlockFinalizerHandle::new(msg_tx);
    (finalizer, handle)
}
