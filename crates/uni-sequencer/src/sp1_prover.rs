//! SP1 Proving Module for Uni-EVM
//!
//! This module provides SP1 zkVM proving functionality for uni-evm blocks.
//! It uses the custom uni-evm guest program which outputs only the minimal
//! 64-byte public values needed for BFT-Core verification.

#[cfg(feature = "sp1")]
use sp1_prover::components::CpuProverComponents;
#[cfg(feature = "sp1")]
use sp1_sdk::{CpuProver, Prover, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use guest_program::input::ProgramInput;
use rkyv::rancor::Error as RkyvError;
use std::sync::OnceLock;

/// Error type for SP1 proving operations
#[derive(Debug, thiserror::Error)]
pub enum Sp1ProverError {
    #[error("Failed to serialize input: {0}")]
    SerializationError(String),

    #[error("Failed to generate proof: {0}")]
    ProvingError(String),

    #[error("Invalid public values: expected 64 bytes, got {0}")]
    InvalidPublicValues(usize),

    #[error("ELF binary is empty. Rebuild with --features sp1")]
    EmptyElf,
}

#[cfg(feature = "sp1")]
/// SP1 Prover setup (client + proving/verifying keys)
///
/// This is cached using OnceLock to avoid repeated setup overhead.
pub struct Sp1ProverSetup {
    pub client: Box<dyn Prover<CpuProverComponents>>,
    pub pk: SP1ProvingKey,
    pub vk: SP1VerifyingKey,
}

#[cfg(feature = "sp1")]
/// Global prover setup cache
static PROVER_SETUP: OnceLock<Sp1ProverSetup> = OnceLock::new();

#[cfg(feature = "sp1")]
/// Initialize the SP1 prover from ELF binary
fn init_prover(elf: &[u8]) -> Sp1ProverSetup {
    let client = CpuProver::new();
    let (pk, vk) = client.setup(elf);

    Sp1ProverSetup {
        client: Box::new(client),
        pk,
        vk,
    }
}

#[cfg(feature = "sp1")]
/// Generate an SP1 proof for uni-evm block execution
///
/// # Arguments
/// * `input` - Program input containing blocks and execution witness
/// * `elf` - RISC-V ELF binary of the uni-evm guest program
///
/// # Returns
/// * `SP1ProofWithPublicValues` - Proof with 64-byte public values
pub fn prove_uni_evm(
    input: ProgramInput,
    elf: &[u8],
) -> Result<SP1ProofWithPublicValues, Sp1ProverError> {
    // NOTE: This function is no longer used since we switched to ethrex's SP1 backend
    // All proving now happens via ethrex_prover_lib::backend::sp1::prove()
    // See proof_coordinator.rs for the actual implementation

    let _ = (input, elf); // Suppress unused warnings

    Err(Sp1ProverError::ProvingError(
        "This function is deprecated. Use ethrex_prover_lib::backend::sp1::prove() instead.".to_string()
    ))
}

#[cfg(test)]
#[cfg(feature = "sp1")]
mod tests {
    use super::*;
    use ethrex_common::types::{Block, ExecutionWitness};

    #[test]
    fn test_empty_elf_error() {
        let input = ProgramInput {
            blocks: vec![],
            execution_witness: ExecutionWitness::default(),
            elasticity_multiplier: 2,
            fee_configs: None,
            blob_commitment: [0; 48],
            blob_proof: [0; 48],
        };

        let result = prove_uni_evm(input, &[]);
        assert!(matches!(result, Err(Sp1ProverError::EmptyElf)));
    }
}
