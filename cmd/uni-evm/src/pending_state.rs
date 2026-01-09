//! Pending state simulation for eth_estimateGas and eth_call
//!
//! When multiple transactions with consecutive nonces are submitted quickly,
//! eth_estimateGas needs to account for pending transactions to correctly
//! estimate gas for the second and subsequent transactions.
//!
//! This module provides utilities to apply pending transactions before simulation.

use ethrex_blockchain::{Blockchain, vm::StoreVmDatabase};
use ethrex_common::{Address, types::{BlockHeader, GenericTransaction, Transaction}};
use ethrex_rpc::utils::RpcErr;
use ethrex_storage::Store;
use ethrex_vm::ExecutionResult;
use std::sync::Arc;
use tracing::{debug, warn};

/// Apply all pending transactions from a sender before simulating a new transaction
///
/// This ensures that gas estimation works correctly when multiple transactions
/// with consecutive nonces are submitted in quick succession.
///
/// ## Algorithm
///
/// 1. Get all pending transactions from mempool
/// 2. Filter to sender's transactions only
/// 3. Sort by nonce
/// 4. Filter to transactions with nonce < target_transaction.nonce
/// 5. Apply each transaction in sequence to create pending state
/// 6. Simulate target transaction against the pending state
///
/// ## Example
///
/// User submits:
/// - TX1 (nonce 0) → Goes to mempool
/// - TX2 (nonce 1) → Needs gas estimation
///
/// Without this fix:
/// - estimateGas(TX2) simulates against committed state (nonce=0)
/// - Simulation fails: "nonce too high"
///
/// With this fix:
/// - estimateGas(TX2) first applies TX1 from mempool
/// - Then simulates TX2 against state where nonce=1
/// - Estimation succeeds
pub async fn simulate_with_pending_state(
    transaction: &GenericTransaction,
    block_header: &BlockHeader,
    storage: Store,
    blockchain: Arc<Blockchain>,
) -> Result<ExecutionResult, RpcErr> {
    let sender = transaction.from;

    // Get pending transactions from mempool
    let pending_txs = match blockchain.mempool.content() {
        Ok(txs) => txs,
        Err(e) => {
            warn!("Failed to get mempool content for pending state simulation: {}", e);
            // Fall back to direct simulation without pending state
            return simulate_tx_direct(transaction, block_header, storage, blockchain);
        }
    };

    // Filter to sender's transactions only
    let mut sender_pending_txs: Vec<_> = pending_txs
        .into_iter()
        .filter(|tx| {
            match tx.sender() {
                Ok(s) => s == sender,
                Err(_) => false,
            }
        })
        .collect();

    // If no pending transactions from this sender, use direct simulation
    if sender_pending_txs.is_empty() {
        debug!("No pending transactions from sender {:?}, using direct simulation", sender);
        return simulate_tx_direct(transaction, block_header, storage, blockchain);
    }

    // Sort by nonce (ascending)
    sender_pending_txs.sort_by_key(|tx| tx.nonce());

    // Determine the nonce we're estimating for
    let target_nonce = match transaction.nonce {
        Some(n) => n,
        None => {
            // If nonce not provided, get committed nonce + count of pending txs
            let committed_nonce = storage
                .get_nonce_by_account_address(block_header.number, sender)
                .await
                .unwrap_or(Some(0))
                .unwrap_or(0);

            committed_nonce + sender_pending_txs.len() as u64
        }
    };

    // Filter to transactions with nonce < target_nonce
    // These are the ones we need to apply before simulating
    let txs_to_apply: Vec<_> = sender_pending_txs
        .into_iter()
        .filter(|tx| tx.nonce() < target_nonce)
        .collect();

    if txs_to_apply.is_empty() {
        debug!(
            "No pending transactions to apply (target nonce={}), using direct simulation",
            target_nonce
        );
        return simulate_tx_direct(transaction, block_header, storage, blockchain);
    }

    debug!(
        "Applying {} pending transaction(s) from sender {:?} before simulating (target nonce={})",
        txs_to_apply.len(),
        sender,
        target_nonce
    );

    // Create VM with base state
    let mut vm_db = StoreVmDatabase::new(storage.clone(), block_header.clone())?;
    let mut vm = blockchain.new_evm(vm_db)?;

    // Apply each pending transaction in order
    for (idx, pending_tx) in txs_to_apply.iter().enumerate() {
        debug!(
            "  Applying pending tx {}/{}: nonce={}",
            idx + 1,
            txs_to_apply.len(),
            pending_tx.nonce()
        );

        // Execute the pending transaction
        let mut remaining_gas = block_header.gas_limit;
        match vm.execute_tx(pending_tx, block_header, &mut remaining_gas, transaction.from) {
            Ok(_result) => {
                // Successfully applied, continue
            }
            Err(e) => {
                warn!(
                    "Failed to apply pending tx (nonce={}): {}",
                    pending_tx.nonce(),
                    e
                );
                // If we can't apply a pending tx, fall back to direct simulation
                // This can happen if the pending tx is invalid
                return simulate_tx_direct(transaction, block_header, storage, blockchain);
            }
        }
    }

    // Now simulate the target transaction against the pending state
    debug!("Simulating target transaction (nonce={}) against pending state", target_nonce);

    match vm.simulate_tx_from_generic(transaction, block_header)? {
        ExecutionResult::Revert {
            gas_used: _,
            output,
        } => Err(RpcErr::Revert {
            data: format!("0x{output:#x}"),
        }),
        ExecutionResult::Halt { reason, gas_used } => Err(RpcErr::Halt { reason, gas_used }),
        success => Ok(success),
    }
}

/// Direct simulation without applying pending state
/// This is the original ethrex behavior
fn simulate_tx_direct(
    transaction: &GenericTransaction,
    block_header: &BlockHeader,
    storage: Store,
    blockchain: Arc<Blockchain>,
) -> Result<ExecutionResult, RpcErr> {
    let vm_db = StoreVmDatabase::new(storage, block_header.clone())?;
    let mut vm = blockchain.new_evm(vm_db)?;

    match vm.simulate_tx_from_generic(transaction, block_header)? {
        ExecutionResult::Revert {
            gas_used: _,
            output,
        } => Err(RpcErr::Revert {
            data: format!("0x{output:#x}"),
        }),
        ExecutionResult::Halt { reason, gas_used } => Err(RpcErr::Halt { reason, gas_used }),
        success => Ok(success),
    }
}
