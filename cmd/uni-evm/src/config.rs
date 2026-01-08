//! Uni-EVM configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uni_sequencer::ProverBackend;

/// Main configuration for Uni-EVM node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniEvmConfig {
    pub network: NetworkConfig,
    pub bft_core: BftCoreConfig,
    pub prover: ProverConfig,
    pub sequencer: SequencerConfig,
    pub rpc: RpcConfig,
    pub trust_base: TrustBaseConfig,
}

/// Network configuration (partition/shard identification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub partition_id: u32,
    pub shard_id: u32,
    pub node_id: String,
    pub chain_id: u64,
    pub genesis_file_path: String,
}

/// BFT Core L1 connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BftCoreConfig {
    /// List of BFT Core root chain peer IDs
    pub root_chain_peers: Vec<String>,
    /// Multiaddrs for dialing root chain peers
    pub root_chain_addrs: Vec<String>,
    /// libp2p listen address
    pub libp2p_listen_addr: String,
    /// Path to signing key (secp256k1, for signing certification requests)
    pub signing_key_path: String,
    /// Path to auth key (secp256k1, for deriving libp2p peer ID that matches BFT node ID)
    pub auth_key_path: String,
}

/// Prover configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// Prover type (sp1, risc0, etc.)
    pub prover_type: String,
    /// Proof format (compressed or groth16)
    pub proof_format: String,
    /// Optional remote prover endpoint
    pub prover_endpoint: Option<String>,
}

impl ProverConfig {
    /// Parse prover_type string to ProverBackend enum
    ///
    /// This maps the configuration string to our custom backend:
    /// - "exec" → ProverBackend::Exec (dummy proofs for testing)
    /// - "sp1" → ProverBackend::Sp1 (real SP1 ZK proofs)
    ///
    /// Returns an error if:
    /// - prover_type is unknown
    /// - prover_type is "sp1" but the sp1 feature is not enabled
    pub fn get_backend(&self) -> Result<ProverBackend> {
        match self.prover_type.to_lowercase().as_str() {
            "exec" => Ok(ProverBackend::Exec),

            #[cfg(feature = "sp1")]
            "sp1" => Ok(ProverBackend::Sp1),

            #[cfg(not(feature = "sp1"))]
            "sp1" => Err(anyhow::anyhow!(
                "SP1 backend not available. Rebuild with --features sp1"
            )),

            _ => Err(anyhow::anyhow!(
                "Unknown prover_type: '{}'. Valid options: exec, sp1",
                self.prover_type
            )),
        }
    }

    /// Get the proof format
    ///
    /// For BFT-Core integration, only "compressed" format is supported.
    /// Groth16 wrapping is not needed since BFT-Core verifies SP1 proofs directly.
    pub fn get_proof_format(&self) -> Result<ethrex_l2_common::prover::ProofFormat> {
        use ethrex_l2_common::prover::ProofFormat;

        match self.proof_format.to_lowercase().as_str() {
            "compressed" => Ok(ProofFormat::Compressed),
            "groth16" => Err(anyhow::anyhow!(
                "Groth16 format not supported. BFT-Core requires 'compressed' format"
            )),
            _ => Err(anyhow::anyhow!(
                "Unknown proof_format: '{}'. Must be 'compressed'",
                self.proof_format
            )),
        }
    }
}

/// Sequencer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Block production interval in milliseconds
    pub block_time_ms: u64,
    /// Maximum gas per block
    pub gas_limit: u64,
}

/// RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// HTTP RPC listen address
    pub http_addr: String,
    /// HTTP RPC port
    pub http_port: u16,
}

/// Trust Base configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBaseConfig {
    /// BFT Core REST API endpoint (e.g., "http://localhost:8080")
    pub bft_core_endpoint: Option<String>,
    /// Path to trust-base.json file (fallback if REST fails)
    pub filesystem_path: Option<String>,
    /// Update interval in seconds
    pub update_interval_secs: u64,
}

impl UniEvmConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Create default configuration
    pub fn default() -> Self {
        Self {
            network: NetworkConfig {
                partition_id: 1,
                shard_id: 1,
                node_id: "uni-evm-node-1".to_string(),
                chain_id: 1, // Default chain ID
                genesis_file_path: "./genesis.json".to_string(),
            },
            bft_core: BftCoreConfig {
                root_chain_peers: vec![],
                root_chain_addrs: vec![],
                libp2p_listen_addr: "/ip4/0.0.0.0/tcp/9000".to_string(),
                signing_key_path: "./keys/signing.key".to_string(),
                auth_key_path: "./keys/auth.key".to_string(),
            },
            prover: ProverConfig {
                prover_type: "sp1".to_string(),
                proof_format: "compressed".to_string(),
                prover_endpoint: None,
            },
            sequencer: SequencerConfig {
                block_time_ms: 1000,
                gas_limit: 30_000_000,
            },
            rpc: RpcConfig {
                http_addr: "127.0.0.1".to_string(),
                http_port: 8545,
            },
            trust_base: TrustBaseConfig {
                bft_core_endpoint: None, // Configure if BFT Core REST is available
                filesystem_path: Some("./trust-base.json".to_string()),
                update_interval_secs: 300, // 5 minutes
            },
        }
    }
}

// Add toml dependency
use toml;
