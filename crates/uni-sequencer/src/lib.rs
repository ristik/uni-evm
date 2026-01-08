//! Uni-EVM Sequencer
//!
//! Simplified single-node sequencer for uni-evm L2.
//! Unlike ethrex which batches blocks, uni-evm processes and proves each block individually.

pub mod block_producer;
pub mod proof_coordinator;
pub mod block_finalizer;

#[cfg(feature = "sp1")]
pub mod sp1_prover;

pub use block_producer::{BlockProducer, BlockProducerConfig, BlockProduced};
pub use proof_coordinator::{ProofCoordinator, ProofCoordinatorConfig, ProverBackend};
pub use block_finalizer::{
    BlockFinalizer, BlockFinalizerHandle, BlockFinalized, PendingBlock, create_block_finalizer,
};
