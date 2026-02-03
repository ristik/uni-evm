//! Key management for BFT Core authentication
//!
//! Supports loading signing keys from:
//! - Environment variable: UNI_EVM_SIGNING_KEY
//! - File path specified in config

use anyhow::{Context, Result, anyhow};
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use std::fs;
use std::path::Path;
use tracing::info;

/// Load signing key with the following precedence:
/// 1. Environment variable UNI_EVM_SIGNING_KEY (hex-encoded)
/// 2. File at signing_key_path (hex-encoded)
///
/// Returns error if no key is found - keys are required for operation.
pub fn load_signing_key(signing_key_path: &str) -> Result<SecretKey> {
    // Try environment variable first
    if let Ok(key_hex) = std::env::var("UNI_EVM_SIGNING_KEY") {
        info!("Loading signing key from environment variable UNI_EVM_SIGNING_KEY");
        return parse_secret_key(&key_hex)
            .context("Failed to parse signing key from environment variable");
    }

    // Try file path
    let path = Path::new(signing_key_path);
    if path.exists() {
        info!("Loading signing key from file: {}", signing_key_path);
        let key_hex = fs::read_to_string(path)
            .context("Failed to read signing key file")?;
        return parse_secret_key(key_hex.trim())
            .context("Failed to parse signing key from file");
    }

    // No key found - fail
    Err(anyhow!(
        "No signing key found. Either:\n\
         1. Set UNI_EVM_SIGNING_KEY environment variable (hex-encoded), or\n\
         2. Create key file at: {}\n\
         \n\
         Generate keys using: uni-evm generate-key --output {}",
        signing_key_path, signing_key_path
    ))
}

/// Parse a hex-encoded secret key (with or without 0x prefix)
fn parse_secret_key(hex: &str) -> Result<SecretKey> {
    let hex = hex.trim().strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)
        .context("Invalid hex encoding for secret key")?;

    if bytes.len() != 32 {
        return Err(anyhow!("Secret key must be exactly 32 bytes, got {}", bytes.len()));
    }

    SecretKey::from_slice(&bytes)
        .map_err(|e| anyhow!("Invalid secret key: {}", e))
}

/// Save secret key to file (hex-encoded, without 0x prefix)
fn save_secret_key(key: &SecretKey, path: &Path) -> Result<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .context("Failed to create key directory")?;
    }

    let hex = hex::encode(key.secret_bytes());
    fs::write(path, hex)
        .context("Failed to write key file")?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // rw-------
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Get public key from secret key
pub fn get_public_key(secret_key: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, secret_key)
}

/// Format public key as hex (compressed, with 0x prefix)
pub fn format_public_key(public_key: &PublicKey) -> String {
    format!("0x{}", hex::encode(public_key.serialize()))
}

/// Parse libp2p peer ID from string
pub fn parse_peer_id(peer_id_str: &str) -> Result<libp2p::PeerId> {
    peer_id_str.parse()
        .map_err(|e| anyhow!("Invalid peer ID '{}': {}", peer_id_str, e))
}

/// Generate a new signing key and save to file
pub fn generate_and_save_key(path: &Path) -> Result<SecretKey> {
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    save_secret_key(&secret_key, path)?;

    let public_key = get_public_key(&secret_key);
    println!("Generated new signing key:");
    println!("  Secret key: {}", hex::encode(secret_key.secret_bytes()));
    println!("  Public key: {}", format_public_key(&public_key));
    println!("  Saved to: {}", path.display());

    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_secret_key_with_prefix() {
        let hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_secret_key(hex).unwrap();
        assert_eq!(hex::encode(key.secret_bytes()), hex.strip_prefix("0x").unwrap());
    }

    #[test]
    fn test_parse_secret_key_without_prefix() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_secret_key(hex).unwrap();
        assert_eq!(hex::encode(key.secret_bytes()), hex);
    }

    #[test]
    fn test_save_and_load_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");

        let original_key = SecretKey::new(&mut rand::thread_rng());
        save_secret_key(&original_key, &key_path).unwrap();

        let loaded_hex = fs::read_to_string(&key_path).unwrap();
        let loaded_key = parse_secret_key(&loaded_hex).unwrap();

        assert_eq!(original_key.secret_bytes(), loaded_key.secret_bytes());
    }

    #[test]
    fn test_public_key_derivation() {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = get_public_key(&secret_key);

        // Verify public key is compressed format (33 bytes)
        assert_eq!(public_key.serialize().len(), 33);

        // Verify format includes 0x prefix
        let formatted = format_public_key(&public_key);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 2 + 66); // 0x + 33 bytes * 2 hex chars
    }

    #[test]
    fn test_invalid_key_length() {
        let hex = "0123456789abcdef"; // Only 8 bytes
        let result = parse_secret_key(hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex() {
        let hex = "xyz"; // Invalid hex
        let result = parse_secret_key(hex);
        assert!(result.is_err());
    }
}
