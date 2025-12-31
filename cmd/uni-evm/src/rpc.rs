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
use ethrex_rpc::{
    RpcApiContext, GasTipEstimator, NodeData, RpcRequestWrapper,
    utils::{RpcErr, RpcRequestId},
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
            // Handle single request using ethrex's built-in request handler
            let res = ethrex_rpc::map_http_requests(&request, context).await;
            ethrex_rpc::rpc_response(request.id, res).map_err(|_| StatusCode::BAD_REQUEST)?
        }
        Ok(RpcRequestWrapper::Multiple(requests)) => {
            // Handle batch requests
            let mut responses = Vec::new();
            for req in requests {
                let res = ethrex_rpc::map_http_requests(&req, context.clone()).await;
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
