use crate::input::UniEvmProgramInput;
use crate::output::UniEvmProgramOutput;
use guest_program::execution::{stateless_validation_l1, StatelessExecutionError};

/// Execute uni-evm block validation and return minimal output
///
/// This wraps ethrex's stateless_validation_l1 which performs full block validation:
/// - Validates block header against chain rules
/// - Executes all transactions in the EVM
/// - Validates gas used, receipts root, requests hash
/// - Applies account updates to the state trie
/// - Validates final state trie matches block's state_root
///
/// Unlike ethrex's full ProgramOutput (which includes L2-specific fields like
/// l1_out_messages, blob_versioned_hash, etc.), this only extracts the two
/// state roots needed for BFT-Core verification.
///
/// # Arguments
/// * `input` - Program input containing blocks and execution witness
///
/// # Returns
/// * `UniEvmProgramOutput` - Contains only prev_state_root and new_state_root (64 bytes)
///
/// # Errors
/// Returns error if block validation fails (invalid transactions, state mismatch, etc.)
pub fn uni_evm_execution(
    input: UniEvmProgramInput,
) -> Result<UniEvmProgramOutput, StatelessExecutionError> {
    // Extract the first block number for validation
    let first_block_number = input
        .blocks
        .first()
        .ok_or_else(|| {
            StatelessExecutionError::EmptyBatchError
        })?
        .header
        .number;

    // Call ethrex's stateless validation with L1-specific logic (no L2 messages)
    let ethrex_output = stateless_validation_l1(
        input.blocks.clone(),
        input.execution_witness,
        input.elasticity_multiplier,
        first_block_number,
    )?;

    // Extract only the state roots needed for BFT-Core
    // Note: ethrex uses "initial_state_hash" and "final_state_hash" terminology,
    // but these map directly to prev_state_root and new_state_root
    Ok(UniEvmProgramOutput::new(
        ethrex_output.initial_state_hash,
        ethrex_output.final_state_hash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{types::Block, H256};
    use ethrex_common::types::block_execution_witness::ExecutionWitness;

    #[test]
    fn test_empty_batch_error() {
        let input = UniEvmProgramInput {
            blocks: vec![],
            execution_witness: ExecutionWitness::default(),
            elasticity_multiplier: 2,
            fee_configs: None,
            blob_commitment: [0; 48],
            blob_proof: [0; 48],
        };

        let result = uni_evm_execution(input);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StatelessExecutionError::EmptyBatchError
        ));
    }

    // Note: Full integration tests with actual block execution would require
    // a complete blockchain state setup. Those tests are better suited for
    // the integration test suite with SP1 proving enabled.
}
