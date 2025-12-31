//! Uni-EVM L2 Blockchain
//!
//! A minimal, single-node L2 blockchain based on ethrex that submits
//! per-block ZK proofs to BFT Core L1.

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber;

mod config;
mod keys;
mod node;
mod rpc;

use config::UniEvmConfig;
use node::UniEvmNode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to configuration file (for run command)
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[derive(Parser, Debug)]
enum Command {
    /// Run the Uni-EVM node (default)
    Run,
    /// Generate a new signing key
    GenerateKey {
        /// Path to save the key (default: ./keys/signing.key)
        #[arg(short, long, default_value = "./keys/signing.key")]
        output: String,
    },
    /// Show public key from existing private key
    ShowPublicKey {
        /// Path to the private key file or hex-encoded key
        #[arg(short, long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments first
    let args = Args::parse();

    // Handle subcommands
    match args.command.unwrap_or(Command::Run) {
        Command::Run => run_node(&args.config).await,
        Command::GenerateKey { output } => generate_key(&output),
        Command::ShowPublicKey { key } => show_public_key(&key),
    }
}

/// Run the Uni-EVM node
async fn run_node(config_path: &str) -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    info!("Starting Uni-EVM L2 node");

    // Load configuration
    let config = UniEvmConfig::from_file(config_path)?;
    info!("Loaded configuration from {}", config_path);

    // Create and start node
    let node = UniEvmNode::new(config).await?;
    info!("Uni-EVM node initialized");

    // Run node
    node.run().await?;

    Ok(())
}

/// Generate a new signing key
fn generate_key(output: &str) -> Result<()> {
    use std::path::Path;

    println!("Generating new signing key...");
    println!();

    let path = Path::new(output);
    keys::generate_and_save_key(path)?;

    println!();
    println!("Next steps:");
    println!("1. Keep this key secure and never share the secret key");
    println!("2. Register the public key in BFT Core partition configuration");
    println!("3. Update config.toml with signing_key_path = \"{}\"", output);
    println!("4. Or set environment variable: export UNI_EVM_SIGNING_KEY=<secret_key_hex>");

    Ok(())
}

/// Show public key from a private key
fn show_public_key(key_input: &str) -> Result<()> {
    use std::path::Path;

    let secret_key = if Path::new(key_input).exists() {
        // Load from file
        println!("Loading key from file: {}", key_input);
        let _key_hex = std::fs::read_to_string(key_input)?;
        keys::load_signing_key(key_input)?
    } else {
        // Parse as hex
        println!("Parsing hex key...");
        let hex = key_input.trim().strip_prefix("0x").unwrap_or(key_input);
        let bytes = hex::decode(hex)?;
        secp256k1::SecretKey::from_slice(&bytes)?
    };

    let public_key = keys::get_public_key(&secret_key);

    println!();
    println!("Public Key: {}", keys::format_public_key(&public_key));
    println!();
    println!("Use this public key to register in BFT Core partition configuration");

    Ok(())
}
