//! Uni-EVM SP1 Guest Program
//!
//! This program runs inside the SP1 zkVM and proves the execution of uni-evm blocks.
//!
//! ## Flow
//!
//! 1. Read `ProgramInput` from zkVM stdin (rkyv serialized)
//! 2. Execute stateless block validation using ethrex's logic
//! 3. Extract prev_state_root and new_state_root
//! 4. Commit 64-byte output to zkVM public values
//!
//! ## Public Values
//!
//! The output is exactly 64 bytes: [prev_state_root (32) || new_state_root (32)]
//! This format matches BFT-Core's verification expectations.
//!
//! ## Note on Dependencies
//!
//! This program reuses ethrex's execution logic (stateless_validation_l1) but
//! produces a minimal output. This avoids code duplication while meeting
//! BFT-Core's requirements.

#![no_main]

use guest_program::input::ProgramInput;
use rkyv::rancor::Error;

// SP1 zkVM entry point macro
sp1_zkvm::entrypoint!(main);

/// zkVM entry point
///
/// This function is called when the zkVM starts executing the program.
/// It performs the following steps:
///
/// 1. Read serialized input from zkVM stdin
/// 2. Deserialize to ProgramInput using rkyv
/// 3. Execute uni-evm block validation
/// 4. Encode output to 64 bytes
/// 5. Commit to zkVM public values
///
/// # Panics
///
/// Panics if:
/// - Input deserialization fails
/// - Block execution fails (invalid block, state mismatch, etc.)
/// - Output encoding produces incorrect length
pub fn main() {
    // 1. Read input bytes from zkVM stdin
    let input_bytes = sp1_zkvm::io::read_vec();

    // Debug: Print input size
    println!("Received {} bytes from stdin", input_bytes.len());
    if input_bytes.len() > 0 {
        println!("First 16 bytes: {:02x?}", &input_bytes[..input_bytes.len().min(16)]);
    }

    // 2. Deserialize using rkyv - same as ethrex
    println!("Attempting rkyv deserialization...");
    let input = rkyv::from_bytes::<ProgramInput, Error>(&input_bytes).unwrap();
    println!("✓ Successfully deserialized ProgramInput with rkyv!");

    // 3. Execute stateless block validation
    // This reuses ethrex's execution logic which:
    // - Validates block headers against chain rules
    // - Executes all transactions in the EVM
    // - Validates gas usage, receipts, requests
    // - Updates state trie and validates final state root
    //
    // Unlike ethrex's full guest program which uses stateless_validation_l2
    // (with L2 messages, blobs, etc.), we use stateless_validation_l1 which
    // is simpler and matches uni-evm's requirements
    let output = execute_uni_evm_blocks(input).expect("Block execution failed");

    // 4. Encode output to exactly 64 bytes
    let output_bytes = output.encode();

    // 5. Commit to zkVM public values
    // These bytes will be accessible in the proof and verified by BFT-Core
    sp1_zkvm::io::commit_slice(&output_bytes);
}

/// Execute uni-evm block validation
///
/// This wraps ethrex's stateless_validation_l1 and extracts minimal output
fn execute_uni_evm_blocks(
    input: guest_program::input::ProgramInput,
) -> Result<UniEvmProgramOutput, guest_program::execution::StatelessExecutionError> {
    // Extract first block number
    let first_block_number = input
        .blocks
        .first()
        .ok_or_else(|| guest_program::execution::StatelessExecutionError::EmptyBatchError)?
        .header
        .number;

    // Execute stateless validation (no L2 messages, just pure EVM execution)
    let ethrex_output = guest_program::execution::stateless_validation_l1(
        input.blocks.clone(),
        input.execution_witness,
        input.elasticity_multiplier,
        first_block_number,
    )?;

    // Extract only the two state roots
    Ok(UniEvmProgramOutput {
        prev_state_root: ethrex_output.initial_state_hash,
        new_state_root: ethrex_output.final_state_hash,
    })
}

/// Minimal output structure (same as in parent crate)
///
/// This is duplicated here to avoid complex dependency management in the guest program.
/// The guest program must be self-contained and compile to RISC-V.
struct UniEvmProgramOutput {
    prev_state_root: ethrex_common::H256,
    new_state_root: ethrex_common::H256,
}

impl UniEvmProgramOutput {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(64);
        encoded.extend_from_slice(&self.prev_state_root.to_fixed_bytes());
        encoded.extend_from_slice(&self.new_state_root.to_fixed_bytes());

        // Critical: Must be exactly 64 bytes for BFT-Core
        assert_eq!(
            encoded.len(),
            64,
            "Output must be exactly 64 bytes, got {}",
            encoded.len()
        );

        encoded
    }
}
