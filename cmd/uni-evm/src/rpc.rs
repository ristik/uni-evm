//! Simplified RPC server for uni-evm
//!
//! Provides essential eth_* JSON-RPC endpoints without P2P dependencies.
//! Based on ethrex RPC but simplified for single-node operation.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::post,
};
use bytes::Bytes;
use ethrex_blockchain::Blockchain;
use ethrex_common::types::{GenericTransaction, Fork};
use ethrex_rpc::{
    RpcApiContext, GasTipEstimator, NodeData, RpcRequestWrapper,
    types::block_identifier::BlockIdentifier,
    utils::{RpcErr, RpcRequestId, RpcRequest},
};
use ethrex_storage::Store;
use ethrex_p2p::types::{Node, NodeRecord};
use serde_json::Value;
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}};
use tokio::{
    net::TcpListener,
    sync::Mutex as TokioMutex,
};
use tower_http::cors::CorsLayer;
use tracing::info;

// Constants for gas estimation (from ethrex rpc/eth/transaction.rs)
const TRANSACTION_GAS: u64 = 21_000; // Per transaction not creating a contract
const POST_OSAKA_GAS_LIMIT_CAP: u64 = u64::MAX;

/// Get maximum allowed gas limit for estimation
/// Based on ethrex_vm::backends::levm::get_max_allowed_gas_limit
fn get_max_allowed_gas_limit(block_gas_limit: u64, fork: Fork) -> u64 {
    if fork >= Fork::Osaka {
        POST_OSAKA_GAS_LIMIT_CAP
    } else {
        block_gas_limit - 1
    }
}

/// Recalculate gas limit based on account balance
/// Based on ethrex rpc/eth/transaction.rs recap_with_account_balances
async fn recap_with_account_balances(
    highest_gas_limit: u64,
    transaction: &GenericTransaction,
    storage: &Store,
    block_number: u64,
) -> Result<u64, RpcErr> {
    let account_info = storage
        .get_account_info(block_number, transaction.from)
        .await?;

    if let Some(info) = account_info {
        let balance = info.balance;
        let gas_price = if transaction.gas_price != 0 {
            transaction.gas_price
        } else {
            transaction
                .max_fee_per_gas
                .unwrap_or(transaction.gas_price)
        };

        // Calculate max gas based on balance
        use ethrex_common::U256;
        let available_funds = balance.saturating_sub(transaction.value);
        let gas_price_u256 = U256::from(gas_price);

        if gas_price > 0 {
            let max_gas_from_balance = available_funds.checked_div(gas_price_u256).unwrap_or(U256::zero());
            Ok(highest_gas_limit.min(max_gas_from_balance.as_u64()))
        } else {
            Ok(highest_gas_limit)
        }
    } else {
        // Account doesn't exist, return original limit
        Ok(highest_gas_limit)
    }
}

/// Start the simplified JSON-RPC server for uni-evm
pub async fn start_rpc_server(
    addr: SocketAddr,
    storage: Store,
    blockchain: Arc<Blockchain>,
    gas_ceil: u64,
) -> Result<(), RpcErr> {
    info!("Starting uni-evm RPC server at {}", addr);

    // Create dummy P2P data (not used in single-node mode)
    use std::net::IpAddr;
    use ethrex_common::H512;

    let dummy_node = Node::new(
        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        30303,  // udp_port
        30303,  // tcp_port
        H512::zero(),  // public_key
    );
    let dummy_node_record = NodeRecord {
        signature: H512::zero(),
        seq: 0,
        pairs: vec![],
    };

    // Initialize active filters for filter endpoints
    let active_filters = Arc::new(Mutex::new(HashMap::new()));

    // Start block executor (required for eth_sendRawTransaction)
    let block_worker_channel = ethrex_rpc::start_block_executor(blockchain.clone());

    // Create RpcApiContext
    let rpc_context = RpcApiContext {
        storage,
        blockchain,
        active_filters: active_filters.clone(),
        syncer: None, // No P2P sync in single-node mode
        peer_handler: None, // No P2P in single-node mode
        node_data: NodeData {
            jwt_secret: Bytes::new(), // Not used without engine API
            local_p2p_node: dummy_node,
            local_node_record: dummy_node_record,
            client_version: format!("uni-evm/{}", env!("CARGO_PKG_VERSION")),
            extra_data: Bytes::from("uni-evm"),
        },
        gas_tip_estimator: Arc::new(TokioMutex::new(GasTipEstimator::new())),
        log_filter_handler: None,
        gas_ceil,
        block_worker_channel,
    };

    // Periodically clean up active filters
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
        let filters = active_filters.clone();
        loop {
            interval.tick().await;
            ethrex_rpc::clean_outdated_filters(filters.clone(), std::time::Duration::from_secs(5 * 60));
        }
    });

    // Create router with CORS enabled
    let cors = CorsLayer::permissive(); // Allow all origins for development

    let router = Router::new()
        .route("/", post(handle_http_request))
        .layer(cors)
        .with_state(rpc_context);

    // Bind and serve
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| RpcErr::Internal(format!("Failed to bind RPC server: {}", e)))?;

    info!("RPC server listening on {}", addr);
    info!("Supported methods: all standard eth_* and net_* endpoints");
    info!("Engine API and Admin methods are not supported (single-node mode)");

    // Serve forever (until shutdown)
    axum::serve(listener, router)
        .with_graceful_shutdown(ethrex_rpc::shutdown_signal())
        .await
        .map_err(|e| RpcErr::Internal(format!("RPC server error: {}", e)))?;

    Ok(())
}

/// Handle incoming HTTP JSON-RPC requests
async fn handle_http_request(
    State(context): State<RpcApiContext>,
    body: String,
) -> Result<Json<Value>, StatusCode> {
    // Parse request wrapper (handles both single and batch requests)
    let res = match serde_json::from_str::<RpcRequestWrapper>(&body) {
        Ok(RpcRequestWrapper::Single(request)) => {
            // Intercept eth_estimateGas and eth_call to use pending state
            let res = match request.method.as_str() {
                "eth_estimateGas" => handle_estimate_gas(&request, context).await,
                "eth_call" => handle_call(&request, context).await,
                _ => ethrex_rpc::map_http_requests(&request, context).await,
            };
            ethrex_rpc::rpc_response(request.id, res).map_err(|_| StatusCode::BAD_REQUEST)?
        }
        Ok(RpcRequestWrapper::Multiple(requests)) => {
            // Handle batch requests
            let mut responses = Vec::new();
            for req in requests {
                let res = match req.method.as_str() {
                    "eth_estimateGas" => handle_estimate_gas(&req, context.clone()).await,
                    "eth_call" => handle_call(&req, context.clone()).await,
                    _ => ethrex_rpc::map_http_requests(&req, context.clone()).await,
                };
                responses.push(
                    ethrex_rpc::rpc_response(req.id, res).map_err(|_| StatusCode::BAD_REQUEST)?,
                );
            }
            serde_json::to_value(responses).map_err(|_| StatusCode::BAD_REQUEST)?
        }
        Err(_) => ethrex_rpc::rpc_response(
            RpcRequestId::String("".to_string()),
            Err(RpcErr::BadParams("Invalid request body".to_string())),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?,
    };
    Ok(Json(res))
}

/// Custom handler for eth_estimateGas with pending state support
///
/// This implementation applies pending transactions from the same sender
/// before estimating gas, allowing consecutive transactions to be estimated correctly.
async fn handle_estimate_gas(
    req: &RpcRequest,
    context: RpcApiContext,
) -> Result<Value, RpcErr> {
    use crate::pending_state::simulate_with_pending_state;
    use ethrex_common::types::TxKind;

    // Parse parameters (copied from ethrex EstimateGasRequest::parse)
    let params = req.params
        .as_ref()
        .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;

    if params.is_empty() {
        return Err(RpcErr::BadParams("No params provided".to_owned()));
    }

    if params.len() > 2 {
        return Err(RpcErr::BadParams(format!(
            "Expected one or two params and {} were provided",
            params.len()
        )));
    }

    let transaction: GenericTransaction =
        serde_json::from_value(params[0].clone())?;

    let block = match params.get(1) {
        Some(value) => Some(BlockIdentifier::parse(value.clone(), 1)?),
        None => None,
    };

    // Get block header (copied from ethrex EstimateGasRequest::handle)
    let storage = &context.storage;
    let blockchain = &context.blockchain;
    let block = block.unwrap_or_default();
    let chain_config = storage.get_chain_config();

    let block_header = match block.resolve_block_header(storage).await? {
        Some(header) => header,
        _ => return Ok(Value::Null),
    };

    let current_fork = chain_config.fork(block_header.timestamp);

    // Fill in nonce if not provided
    let transaction = match transaction.nonce {
        Some(_nonce) => transaction,
        None => {
            let transaction_nonce = storage
                .get_nonce_by_account_address(block_header.number, transaction.from)
                .await?;

            let mut cloned_transaction = transaction;
            cloned_transaction.nonce = transaction_nonce;
            cloned_transaction
        }
    };

    // If the transaction is a plain value transfer, short circuit estimation
    if let TxKind::Call(address) = transaction.to {
        let account_info = storage
            .get_account_info(block_header.number, address)
            .await?;
        let code = account_info.map(|info| storage.get_account_code(info.code_hash));
        if code.is_none() {
            let mut value_transfer_transaction = transaction.clone();
            value_transfer_transaction.gas = Some(TRANSACTION_GAS);

            // Use pending state simulation
            let result = simulate_with_pending_state(
                &value_transfer_transaction,
                &block_header,
                storage.clone(),
                blockchain.clone(),
            ).await?;

            if matches!(result, ethrex_vm::ExecutionResult::Success { .. }) {
                return serde_json::to_value(format!("{TRANSACTION_GAS:#x}"))
                    .map_err(|error| RpcErr::Internal(error.to_string()));
            }
        }
    }

    // Prepare binary search
    let highest_gas_limit = get_max_allowed_gas_limit(block_header.gas_limit, current_fork);
    let mut highest_gas_limit = match transaction.gas {
        Some(gas) => gas.min(highest_gas_limit),
        None => highest_gas_limit,
    };

    if transaction.gas_price != 0 {
        highest_gas_limit = recap_with_account_balances(
            highest_gas_limit,
            &transaction,
            storage,
            block_header.number,
        )
        .await?;
    }

    // Check whether the execution is possible
    let mut transaction = transaction;
    transaction.gas = Some(highest_gas_limit);

    // Use pending state simulation
    let result = simulate_with_pending_state(
        &transaction,
        &block_header,
        storage.clone(),
        blockchain.clone(),
    ).await?;

    match result {
        ethrex_vm::ExecutionResult::Success { gas_used, .. }
        | ethrex_vm::ExecutionResult::Revert { gas_used, .. } => {
            // Avoid estimating again if the transaction is expected to fail
            if matches!(result, ethrex_vm::ExecutionResult::Revert { .. }) {
                return serde_json::to_value(format!("{:#x}", gas_used))
                    .map_err(|error| RpcErr::Internal(error.to_string()));
            }

            // Binary search for the minimum gas that allows the transaction to succeed
            let mut lowest_gas_limit = TRANSACTION_GAS.saturating_sub(1);

            while lowest_gas_limit < highest_gas_limit {
                let mid = (highest_gas_limit + lowest_gas_limit) / 2;
                transaction.gas = Some(mid);

                // Use pending state simulation
                let execution_result = simulate_with_pending_state(
                    &transaction,
                    &block_header,
                    storage.clone(),
                    blockchain.clone(),
                ).await;

                match execution_result {
                    Ok(ethrex_vm::ExecutionResult::Success { .. }) => {
                        highest_gas_limit = mid;
                    }
                    _ => {
                        lowest_gas_limit = mid + 1;
                    }
                }
            }

            serde_json::to_value(format!("{:#x}", highest_gas_limit))
                .map_err(|error| RpcErr::Internal(error.to_string()))
        }
        ethrex_vm::ExecutionResult::Halt { .. } => Err(RpcErr::Internal(
            "Transaction execution halted".to_string(),
        )),
    }
}

/// Custom handler for eth_call with pending state support
///
/// This implementation applies pending transactions from the same sender
/// before executing the call, ensuring correct simulation of consecutive calls.
async fn handle_call(
    req: &RpcRequest,
    context: RpcApiContext,
) -> Result<Value, RpcErr> {
    use crate::pending_state::simulate_with_pending_state;
    use tracing::debug;

    // Parse parameters (copied from ethrex CallRequest::parse)
    let params = req.params
        .as_ref()
        .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;

    if params.is_empty() {
        return Err(RpcErr::BadParams("No params provided".to_owned()));
    }

    if params.len() > 2 {
        return Err(RpcErr::BadParams(format!(
            "Expected one or two params and {} were provided",
            params.len()
        )));
    }

    let transaction: GenericTransaction =
        serde_json::from_value(params[0].clone())?;

    let block = match params.get(1) {
        Some(value) => Some(BlockIdentifier::parse(value.clone(), 1)?),
        None => None,
    };

    // Get block header
    let storage = &context.storage;
    let blockchain = &context.blockchain;
    let block = block.unwrap_or_default();

    debug!("Requested call on block: {}", block);

    let header = match block.resolve_block_header(storage).await? {
        Some(header) => header,
        _ => return Ok(Value::Null),
    };

    // Use pending state simulation
    let result = simulate_with_pending_state(
        &transaction,
        &header,
        storage.clone(),
        blockchain.clone(),
    ).await?;

    serde_json::to_value(format!("0x{:#x}", result.output()))
        .map_err(|error| RpcErr::Internal(error.to_string()))
}
