//! Trust Base updater - fetches updated trust base from BFT Core

use crate::trust_base::{TrustBaseEntry, UnicityTrustBase, ValidatorInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum TrustBaseUpdateError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),
    #[error("Fetch error: {0}")]
    FetchError(String),
}

/// Root node information from BFT Core trust base JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BftRootNode {
    pub node_id: String,
    pub sig_key: String, // Hex-encoded public key with 0x prefix
    pub stake: u64,
}

/// BFT Core trust base JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BftCoreTrustBase {
    pub version: u8,
    pub network_id: u32,
    pub epoch: u64,
    pub epoch_start_round: u64,
    pub root_nodes: Vec<BftRootNode>,
    pub quorum_threshold: u64,
    pub state_hash: String,
    pub change_record_hash: String,
    pub previous_entry_hash: String,
    #[serde(default)]
    pub signatures: HashMap<String, String>,
}

impl BftCoreTrustBase {
    /// Convert BFT Core trust base to internal format
    pub fn to_trust_base_entry(&self) -> Result<TrustBaseEntry, TrustBaseUpdateError> {
        let mut validators = Vec::new();

        for node in &self.root_nodes {
            // Parse hex public key (remove 0x prefix if present)
            let key_hex = node.sig_key.strip_prefix("0x").unwrap_or(&node.sig_key);
            let public_key = hex::decode(key_hex).map_err(|e| {
                TrustBaseUpdateError::InvalidPublicKey(format!("Failed to decode {}: {}", key_hex, e))
            })?;

            validators.push(ValidatorInfo {
                node_id: node.node_id.clone(),
                public_key,
                stake: node.stake,
            });
        }

        Ok(TrustBaseEntry {
            network_id: self.network_id.to_string(),
            epoch: self.epoch,
            epoch_start_round: self.epoch_start_round,
            validators,
            quorum_threshold: self.quorum_threshold,
            state_hash: hex::decode(self.state_hash.strip_prefix("0x").unwrap_or(&self.state_hash))
                .unwrap_or_default(),
            change_record_hash: hex::decode(
                self.change_record_hash
                    .strip_prefix("0x")
                    .unwrap_or(&self.change_record_hash),
            )
            .unwrap_or_default(),
            previous_entry_hash: hex::decode(
                self.previous_entry_hash
                    .strip_prefix("0x")
                    .unwrap_or(&self.previous_entry_hash),
            )
            .unwrap_or_default(),
        })
    }
}

/// Configuration for trust base updates
#[derive(Debug, Clone)]
pub struct TrustBaseUpdateConfig {
    /// BFT Core REST API endpoint (e.g., "http://localhost:8080")
    pub bft_core_endpoint: Option<String>,
    /// Path to trust-base.json file (fallback if REST fails)
    pub filesystem_path: Option<String>,
    /// Update interval in seconds
    pub update_interval_secs: u64,
    /// Timeout for HTTP requests in seconds
    pub request_timeout_secs: u64,
}

impl Default for TrustBaseUpdateConfig {
    fn default() -> Self {
        Self {
            bft_core_endpoint: None,
            filesystem_path: Some("./trust-base.json".to_string()),
            update_interval_secs: 60*60, // 1 hour
            request_timeout_secs: 10,
        }
    }
}

/// Trust base updater - periodically fetches updated trust base
pub struct TrustBaseUpdater {
    config: TrustBaseUpdateConfig,
    trust_base: Arc<RwLock<UnicityTrustBase>>,
    http_client: reqwest::Client,
}

impl TrustBaseUpdater {
    /// Create a new trust base updater
    pub fn new(config: TrustBaseUpdateConfig, trust_base: Arc<RwLock<UnicityTrustBase>>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            config,
            trust_base,
            http_client,
        }
    }

    /// Start the updater background task
    pub async fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                "Starting trust base updater (interval: {}s)",
                self.config.update_interval_secs
            );

            // Initial load
            if let Err(e) = self.update_trust_base().await {
                error!("Initial trust base load failed: {}", e);
            }

            // Periodic updates
            let mut interval =
                tokio::time::interval(Duration::from_secs(self.config.update_interval_secs));

            loop {
                interval.tick().await;

                if let Err(e) = self.update_trust_base().await {
                    error!("Failed to update trust base: {}", e);
                }
            }
        })
    }

    /// Update trust base from BFT Core or filesystem
    async fn update_trust_base(&self) -> Result<(), TrustBaseUpdateError> {
        // Try REST API first
        if let Some(ref endpoint) = self.config.bft_core_endpoint {
            match self.fetch_from_rest(endpoint).await {
                Ok(bft_tb) => {
                    self.apply_trust_base(bft_tb).await?;
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to fetch trust base from REST API: {}", e);
                }
            }
        }

        // Fallback to filesystem
        if let Some(ref path) = self.config.filesystem_path {
            match self.load_from_file(path).await {
                Ok(bft_tb) => {
                    self.apply_trust_base(bft_tb).await?;
                    return Ok(());
                }
                Err(e) => {
                    error!("Failed to load trust base from file: {}", e);
                    return Err(e);
                }
            }
        }

        warn!("No trust base source configured");
        Ok(())
    }

    /// Fetch trust base from BFT Core REST API
    async fn fetch_from_rest(&self, endpoint: &str) -> Result<BftCoreTrustBase, TrustBaseUpdateError> {
        let url = format!("{}/trustbases", endpoint.trim_end_matches('/'));
        info!("Fetching trust base from {}", url);

        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(TrustBaseUpdateError::FetchError(format!(
                "HTTP request failed with status: {}",
                status
            )));
        }

        let trust_base: BftCoreTrustBase = response.json().await?;
        info!(
            "Fetched trust base: epoch={}, validators={}",
            trust_base.epoch,
            trust_base.root_nodes.len()
        );

        Ok(trust_base)
    }

    /// Load trust base from filesystem
    async fn load_from_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<BftCoreTrustBase, TrustBaseUpdateError> {
        let path = path.as_ref();
        info!("Loading trust base from file: {}", path.display());

        let contents = tokio::fs::read_to_string(path).await?;
        let trust_base: BftCoreTrustBase = serde_json::from_str(&contents)?;

        info!(
            "Loaded trust base: epoch={}, validators={}",
            trust_base.epoch,
            trust_base.root_nodes.len()
        );

        Ok(trust_base)
    }

    /// Apply BFT Core trust base to internal trust base
    async fn apply_trust_base(&self, bft_tb: BftCoreTrustBase) -> Result<(), TrustBaseUpdateError> {
        let entry = bft_tb.to_trust_base_entry()?;
        let epoch = entry.epoch;

        let mut trust_base = self.trust_base.write().await;

        // Check if we already have this epoch
        if trust_base.get_entry(epoch).is_some() {
            info!("Trust base epoch {} already exists, skipping", epoch);
            return Ok(());
        }

        // Add new entry
        trust_base.add_entry(entry);
        info!(
            "Added trust base epoch {} ({} validators, quorum: {})",
            epoch,
            bft_tb.root_nodes.len(),
            bft_tb.quorum_threshold
        );

        // Log validator info
        for node in &bft_tb.root_nodes {
            info!(
                "  Validator: {} (stake: {})",
                node.node_id, node.stake
            );
        }

        Ok(())
    }

    /// Manually trigger a trust base update (useful for on-demand updates)
    pub async fn trigger_update(&self) -> Result<(), TrustBaseUpdateError> {
        info!("Manually triggering trust base update");
        self.update_trust_base().await
    }
}

/// Helper function to create and start trust base updater
pub async fn start_trust_base_updater(
    config: TrustBaseUpdateConfig,
) -> (Arc<RwLock<UnicityTrustBase>>, tokio::task::JoinHandle<()>) {
    let trust_base = Arc::new(RwLock::new(UnicityTrustBase::new()));
    let updater = TrustBaseUpdater::new(config, trust_base.clone());
    let handle = updater.start().await;

    (trust_base, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bft_trust_base_conversion() {
        let bft_tb = BftCoreTrustBase {
            version: 1,
            network_id: 3,
            epoch: 1,
            epoch_start_round: 1,
            root_nodes: vec![BftRootNode {
                node_id: "16Uiu2HAkyQRiA7pMgzgLj9GgaBJEJa8zmx9dzqUDa6WxQPJ82ghU".to_string(),
                sig_key: "0x039afb2acb65f5fbc272d8907f763d0a5d189aadc9b97afdcc5897ea4dd112e68b"
                    .to_string(),
                stake: 1,
            }],
            quorum_threshold: 1,
            state_hash: "".to_string(),
            change_record_hash: "".to_string(),
            previous_entry_hash: "".to_string(),
            signatures: HashMap::new(),
        };

        let entry = bft_tb.to_trust_base_entry().unwrap();
        assert_eq!(entry.epoch, 1);
        assert_eq!(entry.validators.len(), 1);
        assert_eq!(entry.validators[0].stake, 1);
        assert_eq!(entry.quorum_threshold, 1);
    }

    #[tokio::test]
    async fn test_load_from_file() {
        // Create temporary test file
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test-trust-base.json");

        let test_data = r#"{
            "version": 1,
            "networkId": 3,
            "epoch": 1,
            "epochStartRound": 1,
            "rootNodes": [{
                "nodeId": "test-node",
                "sigKey": "0x039afb2acb65f5fbc272d8907f763d0a5d189aadc9b97afdcc5897ea4dd112e68b",
                "stake": 100
            }],
            "quorumThreshold": 1,
            "stateHash": "",
            "changeRecordHash": "",
            "previousEntryHash": "",
            "signatures": {}
        }"#;

        tokio::fs::write(&file_path, test_data).await.unwrap();

        let config = TrustBaseUpdateConfig {
            filesystem_path: Some(file_path.to_str().unwrap().to_string()),
            ..Default::default()
        };

        let trust_base = Arc::new(RwLock::new(UnicityTrustBase::new()));
        let updater = TrustBaseUpdater::new(config, trust_base.clone());

        let result = updater
            .load_from_file(file_path.to_str().unwrap())
            .await;
        assert!(result.is_ok());

        let bft_tb = result.unwrap();
        assert_eq!(bft_tb.epoch, 1);
        assert_eq!(bft_tb.root_nodes.len(), 1);
    }
}
