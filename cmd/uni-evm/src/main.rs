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
    #[cfg(feature = "sp1")]
    /// Extract SP1 verification key for BFT-Core deployment
    ExtractVkey {
        /// Path to save the verification key (default: ./uni-evm-vkey.bin)
        #[arg(short, long, default_value = "./uni-evm-vkey.bin")]
        output: String,
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
        #[cfg(feature = "sp1")]
        Command::ExtractVkey { output } => extract_vkey(&output),
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

#[cfg(feature = "sp1")]
/// Extract SP1 verification key for BFT-Core deployment
///
/// This command extracts the verification key from the SP1 guest program ELF
/// and saves it in bincode format for deployment to BFT-Core nodes.
fn extract_vkey(output: &str) -> Result<()> {
    use sp1_sdk::{HashableKey, ProverClient};

    println!("Extracting SP1 verification key...");
    println!();

    // Get the ELF binary from the guest program
    let elf = uni_evm_guest::UNI_EVM_SP1_ELF;

    if elf.is_empty() {
        eprintln!("ERROR: SP1 ELF binary is empty");
        eprintln!();
        eprintln!("The uni-evm-guest program was not built with SP1 support.");
        eprintln!("To fix this:");
        eprintln!("  1. Ensure SP1 toolchain is installed: curl -L https://sp1.succinctlabs.com | bash && sp1up");
        eprintln!("  2. Rebuild with SP1 feature: cargo build --release --features sp1");
        eprintln!();
        std::process::exit(1);
    }

    println!("ELF size: {} bytes", elf.len());
    println!("Setting up SP1 prover...");

    // Initialize SP1 prover client and generate keys
    let client = ProverClient::from_env();
    let (_, vk) = client.setup(elf);

    println!("Verification key generated successfully");
    println!("VKey hash: {}", vk.vk.bytes32());

    // Serialize the verification key using bincode
    // This matches the format expected by BFT-Core's sp1-verifier-ffi
    let vk_bytes = bincode::serialize(&vk.vk)?;

    // Save to file
    std::fs::write(output, &vk_bytes)?;

    println!();
    println!("✓ Verification key saved to: {}", output);
    println!("  Size: {} bytes", vk_bytes.len());
    println!("  Hash: {}", vk.vk.bytes32());
    println!();
    println!("Next steps:");
    println!("  1. Copy {} to each BFT-Core validator node", output);
    println!("  2. Configure BFT-Core nodes:");
    println!("     --zk-verification-enabled=true");
    println!("     --zk-proof-type=sp1");
    println!(
        "     --zk-vkey-path=/path/to/{}",
        output.split('/').last().unwrap_or(output)
    );
    println!("  3. Restart BFT-Core nodes to load the verification key");
    println!("  4. Set uni-evm config.toml: prover_type = \"sp1\"");
    println!("  5. Restart uni-evm with SP1 proving enabled");
    println!();
    println!("IMPORTANT: All BFT-Core validators MUST use the exact same verification key!");

    Ok(())
}
