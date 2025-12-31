//! Helper binary to get libp2p peer ID from authKey file
//!
//! Usage: get-peer-id <auth-key-path>

use anyhow::{Context, Result};
use libp2p::{identity, PeerId};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <auth-key-path>", args[0]);
        eprintln!("Example: {} ./keys/auth.key", args[0]);
        std::process::exit(1);
    }

    let auth_key_path = &args[1];

    // Read auth key from file (hex-encoded secp256k1 private key)
    let auth_key_hex = std::fs::read_to_string(auth_key_path)
        .context("Failed to read auth key file")?
        .trim()
        .to_string();

    // Decode hex to bytes
    let auth_key_bytes = hex::decode(&auth_key_hex)
        .context("Failed to decode auth key hex")?;

    // Derive libp2p keypair from authKey (secp256k1)
    use libp2p::identity::secp256k1;
    let secret_key = secp256k1::SecretKey::try_from_bytes(auth_key_bytes)
        .context("Failed to create secp256k1 secret key from auth key bytes")?;
    let keypair = identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    // Get peer ID
    let peer_id = PeerId::from(keypair.public());

    // Print only the peer ID (for script usage)
    println!("{}", peer_id);

    Ok(())
}
