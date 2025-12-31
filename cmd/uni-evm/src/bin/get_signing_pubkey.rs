//! Helper binary to get secp256k1 public key from a signing key file
//!
//! Usage: get-signing-pubkey <signing-key-path>

use anyhow::Result;
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use std::fs;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <signing-key-path>", args[0]);
        eprintln!("Example: {} ./keys/signing.key", args[0]);
        std::process::exit(1);
    }

    let key_path = &args[1];

    // Read and parse secret key
    let key_hex = fs::read_to_string(key_path)?;
    let key_hex = key_hex.trim().strip_prefix("0x").unwrap_or(key_hex.trim());
    let bytes = hex::decode(key_hex)?;

    if bytes.len() != 32 {
        eprintln!("Error: Secret key must be exactly 32 bytes, got {}", bytes.len());
        std::process::exit(1);
    }

    let secret_key = SecretKey::from_slice(&bytes)?;

    // Derive public key
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Print in BFT Core format (0x + hex)
    println!("0x{}", hex::encode(public_key.serialize()));

    Ok(())
}
