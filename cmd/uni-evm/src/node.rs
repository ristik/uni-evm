//! Uni-EVM node implementation

use crate::config::UniEvmConfig;
use crate::keys;
use anyhow::{Context, Result};
use ethrex_blockchain::{Blockchain, BlockchainOptions};
use ethrex_storage::{EngineType, Store};
use libp2p::{Multiaddr, PeerId};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};
use uni_bft_committer::{BftCommitter, BftCommitterConfig, BftCoreClient, UcStorage, UnicityCertificate};
use uni_bft_precompile::{init_precompile_trust_base, start_trust_base_updater, TrustBaseUpdateConfig};
use uni_sequencer::{
    BlockProducer, BlockProducerConfig, ProofCoordinator, ProofCoordinatorConfig,
    create_block_finalizer,
};
use uni_storage::UniStore;

/// Uni-EVM node
pub struct UniEvmNode {
    config: UniEvmConfig,
}

impl UniEvmNode {
    /// Create a new Uni-EVM node
    pub async fn new(config: UniEvmConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Run the node
    pub async fn run(self) -> Result<()> {
        info!("Starting Uni-EVM L2 node");
        info!(
            "Network: partition={}, shard={}, node_id={}",
            self.config.network.partition_id,
            self.config.network.shard_id,
            self.config.network.node_id
        );

        // 1. Initialize storage and genesis
        info!("Initializing storage...");
        let datadir = std::path::Path::new("./data/storage");

        // Load genesis
        info!("Loading genesis from {}...", self.config.network.genesis_file_path);
        let genesis_path = std::path::Path::new(&self.config.network.genesis_file_path);
        let genesis = ethrex_common::types::Genesis::try_from(genesis_path)
            .context("Failed to load genesis file")?;

        // Validate chain ID matches config
        if genesis.config.chain_id != self.config.network.chain_id {
            return Err(anyhow::anyhow!(
                "Genesis chain ID ({}) does not match config chain ID ({})",
                genesis.config.chain_id,
                self.config.network.chain_id
            ));
        }

        // Initialize store with genesis using RocksDB for persistence
        let engine_type = EngineType::RocksDB;
        let mut store = Store::new(datadir, engine_type)
            .context("Failed to create store")?;
        store.add_initial_state(genesis).await
            .context("Failed to add genesis state")?;

        info!("Genesis state initialized successfully");
        let store = Arc::new(store);

        // Initialize persistent UniStore for UCs and proofs
        let uni_store_path = std::path::Path::new("./data");
        let uni_store = Arc::new(UniStore::new(uni_store_path)
            .context("Failed to create UniStore")?);
        info!("UniStore initialized with persistent RocksDB backend");

        // 3. Initialize blockchain
        info!("Initializing blockchain...");
        let blockchain_opts = BlockchainOptions::default();
        let blockchain = Arc::new(
            Blockchain::new((*store).clone(), blockchain_opts)
        );

        // 4. Initialize Trust Base updater
        info!("Initializing Trust Base updater...");
        let tb_config = TrustBaseUpdateConfig {
            bft_core_endpoint: self.config.trust_base.bft_core_endpoint.clone(),
            filesystem_path: self.config.trust_base.filesystem_path.clone(),
            update_interval_secs: self.config.trust_base.update_interval_secs,
            request_timeout_secs: 10,
        };
        let (trust_base, _tb_handle) = start_trust_base_updater(tb_config).await;
        info!("Trust Base updater started");

        // Initialize the precompile with the trust base
        init_precompile_trust_base(trust_base.clone());
        info!("Unicity verification precompile initialized at 0x0100");

        // 5. Initialize Block Finalizer
        info!("Initializing Block Finalizer...");
        let latest_block_number = store.get_latest_block_number().await?;

        // Check if we have a last certified block from previous runs
        // This ensures we resume from the last UC-certified state
        let last_certified_block = uni_store.get_latest_certified_block()
            .unwrap_or(latest_block_number);

        info!(
            "Storage state on startup: latest_block={}, last_certified_block={}",
            latest_block_number, last_certified_block
        );

        // Debug: Check if we can read the latest block's state root
        if latest_block_number > 0 {
            match store.get_block_header(latest_block_number) {
                Ok(Some(header)) => {
                    info!(
                        "Block {} header found: number={}, state_root={:?}",
                        latest_block_number,
                        header.number,
                        header.state_root
                    );
                }
                Ok(None) => {
                    warn!("Block {} header not found in storage!", latest_block_number);
                }
                Err(e) => {
                    warn!("Failed to read block {} header: {}", latest_block_number, e);
                }
            }
        }

        // If there's a mismatch, we may need to handle it
        if last_certified_block != latest_block_number {
            warn!(
                "STATE MISMATCH: Latest block in storage: {}, last UC-certified block: {}",
                latest_block_number, last_certified_block
            );
            if latest_block_number > last_certified_block {
                warn!(
                    "Storage has {} uncertified blocks - these may need to be discarded",
                    latest_block_number - last_certified_block
                );
            }
        }

        // Create channel for block finalization notifications (finalizer -> block producer)
        let (finalized_tx, finalized_rx) = mpsc::channel(32);

        let (block_finalizer, finalizer_handle) = create_block_finalizer(
            store.clone(),
            last_certified_block,  // Use last certified block, not latest block
            Some(finalized_tx),
        );
        info!("Block finalizer ready, last finalized: {}", last_certified_block);

        // 6. Load signing key and auth key
        info!("Loading BFT Core configuration...");
        let signing_key = keys::load_signing_key(&self.config.bft_core.signing_key_path)
            .context("Failed to load signing key")?;
        let public_key = keys::get_public_key(&signing_key);
        info!("Loaded signing key, public key: {}", keys::format_public_key(&public_key));

        // Load auth key for libp2p peer ID derivation
        // This matches BFT Core's architecture where NodeID is derived from authKey
        info!("Loading auth key for libp2p peer ID derivation...");
        let auth_key = keys::load_signing_key(&self.config.bft_core.auth_key_path)
            .context("Failed to load auth key")?;
        let auth_pub = keys::get_public_key(&auth_key);
        info!("Loaded auth key, public key: {}", keys::format_public_key(&auth_pub));
        let auth_key_bytes = auth_key.secret_bytes().to_vec();

        // 7. Initialize BFT Core client with auth key for peer ID
        info!("Initializing BFT Core client...");
        let listen_addr: Multiaddr = self
            .config
            .bft_core
            .libp2p_listen_addr
            .parse()
            .context("Invalid libp2p listen address")?;

        let uc_storage = UcStorage::new();
        let mut bft_client = BftCoreClient::new(
            listen_addr,
            uc_storage,
            auth_key_bytes,  // authKey derives libp2p peer ID matching BFT node ID
        )?;
        let bft_handle = bft_client.handle();
        let bft_peer_id = bft_client.local_peer_id();

        let root_chain_peer = if let Some(peer_str) = self.config.bft_core.root_chain_peers.first() {
            keys::parse_peer_id(peer_str)
                .context(format!("Failed to parse root chain peer: {}", peer_str))?
        } else {
            warn!("No root chain peers configured");
            PeerId::random()
        };

        // Set up UC+TechnicalRecord callback BEFORE spawning client
        // This callback will handle both genesis UC and regular UCs
        // Note: BftCommitter will be created AFTER genesis UC is loaded, so we use Arc<Once> pattern
        info!("Setting up UC callback...");
        let uc_store = uni_store.clone();
        let finalizer_handle_for_uc = finalizer_handle.clone();
        // Will be set after committer is created
        let bft_committer_ref: Arc<Mutex<Option<Arc<Mutex<BftCommitter>>>>> = Arc::new(Mutex::new(None));
        let committer_for_uc = bft_committer_ref.clone();

        bft_client.set_uc_callback(move |uc, technical| {
            let round = uc.input_record.as_ref()
                .ok_or_else(|| anyhow::anyhow!("UC missing InputRecord"))?
                .round_number;

            info!("UC received for round {} with TechnicalRecord (next_round={})", round, technical.round);

            // Log UC hash values and shard ID for debugging
            let uc_shard_id = hex::encode(&uc.shard_tree_certificate.shard);
            if let Some(ref ir) = uc.input_record {
                let hash_str = ir.hash.as_ref()
                    .map(|h| if h.is_empty() { "NULL".to_string() } else { hex::encode(h) })
                    .unwrap_or_else(|| "NONE".to_string());
                let prev_hash_str = ir.previous_hash.as_ref()
                    .map(|h| if h.is_empty() { "NULL".to_string() } else { hex::encode(h) })
                    .unwrap_or_else(|| "NONE".to_string());
                info!("  UC.InputRecord.Hash:         {}", hash_str);
                info!("  UC.InputRecord.PreviousHash: {}", prev_hash_str);
                info!("  UC.InputRecord.Round:        {}", ir.round_number);
            }

            // CRITICAL: Validate this UC is for our partition (shard ID 0x80 = partition 8)
            // UCs for other shards should be ignored
            let expected_shard_id = vec![0x80u8];  // Empty bitstring for default shard
            if uc.shard_tree_certificate.shard != expected_shard_id {
                warn!("⚠️  UC is for different shard: {} (expected: 0x80)", uc_shard_id);
                warn!("   Ignoring UC not for our partition");
                return Ok(());
            }

            // CRITICAL: Check if this is a synchronization UC (null hashes)
            // BFT Core sends these when it rejects a certification request
            let has_null_hash = uc.input_record.as_ref()
                .and_then(|ir| ir.hash.as_ref())
                .map(|h| h.is_empty())
                .unwrap_or(true);

            let has_null_prev = uc.input_record.as_ref()
                .and_then(|ir| ir.previous_hash.as_ref())
                .map(|h| h.is_empty())
                .unwrap_or(true);

            if has_null_hash && has_null_prev {
                warn!("⚠️  SYNCHRONIZATION UC detected (round {}, next_round from TR: {})", round, technical.round);
                warn!("   Expected: Use round {} for next block (from TechnicalRecord)", technical.round);

                // Store sync UC as LUC to get timestamp/epoch for next certification request
                // But DON'T finalize any blocks
                if let Some(committer_arc) = committer_for_uc.try_lock().ok().and_then(|guard| guard.clone()) {
                    if let Ok(committer) = committer_arc.try_lock() {
                        // Clear any proposed block (it wasn't certified)
                        committer.round_state().clear_proposed_block();
                        // Store sync UC as LUC and update round state
                        committer.handle_uc_received(&uc, technical.round);
                        info!("✓ Stored sync UC as LUC (for timestamp/epoch)");
                        info!("  next_expected_round={}", technical.round);
                        if let Some(seal) = uc.unicity_seal.as_ref() {
                            info!("  timestamp={}", seal.timestamp);
                            info!("  epoch={}", seal.epoch);
                        }
                    }
                }

                // Don't finalize blocks for sync UCs
                // Just update state and wait for actual block certification
                return Ok(());
            }

            // Try to get committer (may not be available for genesis UC)
            let committer_opt = committer_for_uc.try_lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock committer ref"))?
                .clone();

            if let Some(committer_arc) = committer_opt {
                // VALIDATE UC via committer before processing
                let validation = {
                    let committer = committer_arc.try_lock()
                        .map_err(|_| anyhow::anyhow!("Failed to lock committer"))?;
                    committer.validate_uc(&uc)
                };

                info!("UC validation result: {:?}", validation);

                // Handle based on validation
                let should_finalize = match validation {
                    uni_bft_committer::types::UcValidation::Duplicate => {
                        info!("Duplicate UC for round {} - already processed", round);
                        return Ok(());
                    }

                    uni_bft_committer::types::UcValidation::Repeat => {
                        warn!("Repeat UC for round {} - root chain timeout, block not accepted", round);
                        // CRITICAL: Update LUC with new TechnicalRecord for correct next_round
                        info!("Updating LUC with repeat UC (contains updated next_round from TechnicalRecord)");
                        {
                            let committer = committer_arc.try_lock()?;
                            committer.round_state().clear_proposed_block();
                            info!("Cleared proposed block due to timeout");
                        }
                        false  // Don't finalize blocks, but DO update LUC below
                    }

                    uni_bft_committer::types::UcValidation::RoundMismatch { uc_round, proposed_round } => {
                        error!("UC round {} doesn't match proposed {}", uc_round, proposed_round);
                        // CRITICAL: Update LUC even on mismatch to get latest TechnicalRecord
                        info!("Updating LUC with mismatched UC (contains updated next_round from TechnicalRecord)");
                        {
                            let committer = committer_arc.try_lock()?;
                            committer.round_state().clear_proposed_block();
                            error!("Cleared proposed block due to mismatch - will resync");
                        }
                        false  // Don't finalize, but DO update LUC below
                    }

                    uni_bft_committer::types::UcValidation::NoProposedBlock => {
                        info!("UC received with no proposed block - sync or initialization UC");
                        info!("Updating LUC with sync UC (contains TechnicalRecord for synchronization)");
                        // This is normal during sync or when block hasn't been proposed yet
                        false  // Don't finalize, but DO update LUC below
                    }

                    uni_bft_committer::types::UcValidation::Valid => {
                        info!("UC validation PASSED for round {}", round);
                        true  // Proceed to finalization
                    }
                };

                // Update LUC
                {
                    let committer = committer_arc.try_lock()?;
                    let next_round = technical.round;
                    committer.handle_uc_received(&uc, next_round);

                    // For Valid UCs, clear proposed block after updating LUC
                    // (already cleared for other cases above)
                    if should_finalize {
                        committer.round_state().clear_proposed_block();
                    }
                }

                // NOTIFY finalizer (only if valid and matches proposed block)
                if should_finalize {
                    let finalizer = finalizer_handle_for_uc.clone();
                    let uc_clone = uc.clone();
                    tokio::spawn(async move {
                        if let Err(e) = finalizer.notify_uc_received(uc_clone).await {
                            tracing::error!("Failed to notify finalizer: {}", e);
                        }
                    });
                }
            } else {
                // No committer yet - this is genesis UC during initialization
                info!("Genesis UC received during initialization (no committer yet)");
            }

            // STORE UC (always)
            uc_store.store_unicity_certificate(round, uc.clone())
                .map_err(|e| anyhow::anyhow!("Failed to store UC: {}", e))?;
            info!("Stored UC for round {}", round);

            Ok(())
        });

        // Dial root chain peers
        for addr_str in &self.config.bft_core.root_chain_addrs {
            let addr: Multiaddr = addr_str.parse()
                .context(format!("Invalid root chain address: {}", addr_str))?;
            bft_client.dial(addr)?;
        }

        // Spawn BFT Core client in background
        tokio::spawn(async move {
            bft_client.run().await;
        });

        // Wait for connections to establish
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Load last UC from storage for committer initialization
        // On restart, we should use the last UC, not genesis
        info!("Loading last UC from storage for initialization...");
        let last_uc: Option<UnicityCertificate> = if last_certified_block > 0 {
            // Restart scenario: use last certified block's UC
            info!("✓ Found last certified block {} - loading its UC", last_certified_block);
            match uni_store.get_unicity_certificate(last_certified_block) {
                Ok(uc) => {
                    let state = uc.input_record
                        .as_ref()
                        .and_then(|ir| ir.hash.as_ref())
                        .map(|h| hex::encode(&h[..32.min(h.len())]))
                        .unwrap_or_else(|| "none".to_string());
                    info!("  Last UC round: {}, state hash: {}", last_certified_block, state);
                    Some(uc)
                }
                Err(e) => {
                    warn!("Failed to load UC for block {}: {}", last_certified_block, e);
                    warn!("Will sync from BFT Core instead");
                    None
                }
            }
        } else if uni_store.has_unicity_certificate(0) {
            // Genesis UC exists, use it
            info!("✓ Genesis UC (round 0) found in storage");
            let uc = uni_store.get_unicity_certificate(0)
                .context("Failed to read genesis UC from storage")?;
            let genesis_state = uc.input_record
                .as_ref()
                .and_then(|ir| ir.hash.as_ref())
                .map(|h| hex::encode(&h[..32.min(h.len())]))
                .unwrap_or_else(|| "none".to_string());
            info!("  Genesis state hash: {}", genesis_state);
            Some(uc)
        } else {
            info!("No UC in storage - first run, will subscribe to UC feed");
            None
        };

        // Initialize BFT Committer with genesis UC
        info!("Initializing BFT Committer with genesis UC...");
        let committer_config = BftCommitterConfig {
            partition_id: self.config.network.partition_id,
            shard_id: vec![self.config.network.shard_id as u8],
            node_id: self.config.network.node_id.clone(),  // Use BFT node ID from config, NOT libp2p peer ID
            signing_key,
            root_chain_peer,
        };

        let bft_committer = Arc::new(Mutex::new(BftCommitter::new(
            committer_config,
            bft_handle.clone(),
            last_uc,  // Pass last UC for round state initialization (not just genesis)
        )));

        // Store committer reference for UC callback
        *bft_committer_ref.lock().await = Some(bft_committer.clone());

        info!("Sending handshake to BFT Core to subscribe to UC feed...");
        info!("  Partition ID: {}", self.config.network.partition_id);
        info!("  BFT Node ID:  {}", self.config.network.node_id);
        info!("  libp2p Peer:  {}", bft_peer_id);
        info!("  Root Peer:    {}", root_chain_peer);

        bft_handle
            .send_handshake(
                root_chain_peer,
                self.config.network.partition_id,
                self.config.network.node_id.clone(),  // Use BFT node ID, not libp2p peer ID
            )
            .await
            .context("Failed to send handshake to BFT Core")?;

        info!("✓ Handshake sent - waiting for UC feed subscription...");

        // Wait for first UC from subscription to arrive
        // BFT Core should send latest UC (e.g., round 481) + TechnicalRecord
        info!("Waiting for first UC from BFT Core (up to 5 seconds)...");
        let timeout = tokio::time::Duration::from_secs(5);
        let start = tokio::time::Instant::now();
        let mut luc_received = false;

        while start.elapsed() < timeout {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Check if we have a last UC with VALID (non-null) state hash
            if let Some(committer_arc) = bft_committer_ref.lock().await.as_ref() {
                if let Ok(committer) = committer_arc.try_lock() {
                    if let Some(uc) = committer.round_state().get_last_uc() {
                        // Verify UC has non-null state hash (not a sync UC)
                        let has_valid_hash = uc.input_record.as_ref()
                            .and_then(|ir| ir.hash.as_ref())
                            .map(|h| !h.is_empty())
                            .unwrap_or(false);

                        if has_valid_hash {
                            luc_received = true;
                            break;
                        }
                    }
                }
            }
        }

        if luc_received {
            // Get UC details for logging
            let (uc_round, next_round) = if let Some(committer_arc) = bft_committer_ref.lock().await.as_ref() {
                if let Ok(committer) = committer_arc.try_lock() {
                    let uc = committer.round_state().get_last_uc();
                    let uc_round = uc.as_ref()
                        .and_then(|u| u.input_record.as_ref())
                        .map(|ir| ir.round_number)
                        .unwrap_or(0);
                    let next_round = committer.round_state().get_next_expected_round();
                    (uc_round, next_round)
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };
            info!("Received UC from BFT Core: round {}, next expected round {}", uc_round, next_round);
        } else {
            warn!("No UC received from handshake within timeout");
        }

        // Certify genesis state (block 0) before producing first transaction block
        // This ensures we have a valid LUC with the genesis state root certified by BFT Core
        info!("========================================");
        info!("📝 CERTIFYING GENESIS STATE");
        info!("========================================");

        // Get genesis state root from block 0
        let genesis_state_root = match store.get_block_header(0) {
            Ok(Some(header)) => {
                info!("Genesis block 0 state_root: {:?}", header.state_root);
                header.state_root
            }
            Ok(None) => {
                warn!("Genesis block 0 header not found, using zero state root");
                ethrex_common::H256::zero()
            }
            Err(e) => {
                warn!("Failed to read genesis block header: {}, using zero state root", e);
                ethrex_common::H256::zero()
            }
        };

        // Send certification request for genesis state
        info!("Submitting genesis state certification request...");
        let committer_opt = bft_committer_ref.lock().await.clone();
        if let Some(committer_arc) = committer_opt {
            // Submit genesis state for certification
            // Block hash is zero for genesis (no actual block with transactions)
            let submit_result = {
                let mut committer = committer_arc.lock().await;
                committer.commit_block(
                    0,  // block number (genesis)
                    ethrex_common::H256::zero(),  // block hash (zero for genesis)
                    ethrex_common::H256::zero(),  // previous state (zero for genesis)
                    genesis_state_root,  // genesis state root to certify
                    vec![0xDE, 0xAD, 0xBE, 0xEF],  // dummy proof for exec mode
                ).await
            }; // Drop committer lock here before waiting

            match submit_result {
                Ok(_) => {
                    info!("✓ Genesis state certification request submitted");

                    // Wait for genesis UC (with timeout)
                    let genesis_timeout = tokio::time::Duration::from_secs(10);
                    let start = tokio::time::Instant::now();
                    let mut genesis_certified = false;

                    while start.elapsed() < genesis_timeout {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                        // Re-acquire lock to check LUC (released after check)
                        // Extract only the data we need to avoid cloning
                        let (uc_state, uc_round) = {
                            let committer = committer_arc.lock().await;
                            if let Some(uc) = committer.round_state().get_last_uc() {
                                let state = uc.input_record.as_ref()
                                    .and_then(|ir| ir.hash.as_ref())
                                    .map(|h| ethrex_common::H256::from_slice(&h[..32]))
                                    .unwrap_or(ethrex_common::H256::zero());
                                let round = uc.input_record.as_ref()
                                    .map(|ir| ir.round_number)
                                    .unwrap_or(0);
                                (Some(state), round)
                            } else {
                                (None, 0)
                            }
                        };

                        if let Some(state) = uc_state {
                            if state == genesis_state_root {
                                genesis_certified = true;
                                info!("✓ Genesis state certified (UC round {})", uc_round);
                                break;
                            }
                        }
                    }

                    if !genesis_certified {
                        warn!("⚠️  Genesis certification timeout - continuing anyway");
                        warn!("   First block will establish the certified chain");
                    }
                }
                Err(e) => {
                    warn!("Failed to submit genesis certification: {}", e);
                    warn!("Continuing - first block will establish the chain");
                }
            }
        }

        // This maintains UC feed subscription even if BFT Core cannot dial back
        info!("========================================");
        info!("🔄 STARTING PERIODIC HANDSHAKE TASK");
        info!("========================================");
        let bft_handle_for_heartbeat = bft_handle.clone();
        let root_chain_peer_for_heartbeat = root_chain_peer;
        let partition_id_for_heartbeat = self.config.network.partition_id;
        let node_id_for_heartbeat = self.config.network.node_id.clone();  // Use BFT node ID
        let handshake_interval_secs = 30*60;

        info!("Handshake will be re-sent every {} seconds", handshake_interval_secs);
        info!("This ensures UC feed subscription remains active");

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(handshake_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first tick (we just sent handshake above)
            interval.tick().await;

            loop {
                interval.tick().await;

                info!("📡 Periodic handshake: Re-subscribing to UC feed");

                if let Err(e) = bft_handle_for_heartbeat.send_handshake(
                    root_chain_peer_for_heartbeat,
                    partition_id_for_heartbeat,
                    node_id_for_heartbeat.clone(),
                ).await {
                    warn!("Failed to send periodic handshake: {}", e);
                } else {
                    // info!("✓ Periodic handshake sent successfully");
                }
            }
        });

        // Create channel for block production -> proof coordination
        let (block_tx, block_rx) = mpsc::channel(32);

        // 7. Initialize Block Producer
        info!("Initializing Block Producer...");
        let block_producer_config = BlockProducerConfig {
            block_time_ms: self.config.sequencer.block_time_ms,
            coinbase_address: ethrex_common::Address::zero(), // TODO: configure
            gas_limit: self.config.sequencer.gas_limit,
            elasticity_multiplier: 2,
        };

        let block_producer = BlockProducer::new(
            block_producer_config,
            blockchain.clone(),
            store.clone(),
            block_tx,
            finalizer_handle.clone(),
            finalized_rx,
        );

        // 8. Initialize Proof Coordinator
        info!("Initializing Proof Coordinator...");
        let proof_coordinator_config = ProofCoordinatorConfig {
            proof_format: self
                .config
                .prover
                .get_proof_format()
                .context("Failed to parse proof_format from config")?,
            prover_backend: self
                .config
                .prover
                .get_backend()
                .context("Failed to parse prover_type from config")?,
            elasticity_multiplier: 2, // Standard EIP-1559 value
        };

        let proof_coordinator = ProofCoordinator::new(
            proof_coordinator_config,
            store.clone(),
            uni_store.clone(),
            bft_committer.clone(),
            block_rx,
            blockchain.clone(),
        );

        // 9. Spawn components
        info!("Starting sequencer components...");

        // Spawn block finalizer (must run before block producer)
        tokio::spawn(async move {
            block_finalizer.run().await;
        });

        // Spawn block producer
        tokio::spawn(async move {
            if let Err(e) = block_producer.run().await {
                tracing::error!("Block producer error: {}", e);
            }
        });

        // Spawn proof coordinator
        tokio::spawn(async move {
            if let Err(e) = proof_coordinator.run().await {
                tracing::error!("Proof coordinator error: {}", e);
            }
        });

        // 10. Start RPC server
        info!("Starting RPC server...");
        let rpc_store = store.clone();
        let rpc_blockchain = blockchain.clone();
        let rpc_addr = format!("{}:{}", self.config.rpc.http_addr, self.config.rpc.http_port);
        let rpc_socket_addr = rpc_addr.parse().context("Invalid RPC address")?;
        let gas_ceil = self.config.sequencer.gas_limit; // Use sequencer gas limit as gas ceiling

        tokio::spawn(async move {
            if let Err(e) = crate::rpc::start_rpc_server(
                rpc_socket_addr,
                (*rpc_store).clone(),
                rpc_blockchain,
                gas_ceil,
            ).await {
                tracing::error!("RPC server error: {}", e);
            }
        });

        info!("Block production: {}ms interval", self.config.sequencer.block_time_ms);
        info!("Gas limit: {}", self.config.sequencer.gas_limit);
        info!("RPC server: http://{}", rpc_addr);

        // Keep running until Ctrl+C
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        Ok(())
    }
}
