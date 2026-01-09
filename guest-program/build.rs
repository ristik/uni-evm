//! Build script for uni-evm-guest
//!
//! When built with the `sp1` feature, this script:
//! 1. Compiles the SP1 guest program to RISC-V ELF
//! 2. Generates the verification key
//! 3. Saves both to `src/sp1/out/`
//!
//! Without the `sp1` feature, this is a no-op.

fn main() {
    // Only build the SP1 guest program if the sp1 feature is enabled
    #[cfg(feature = "sp1")]
    build_sp1_guest();

    // Tell cargo to rerun if these files change
    println!("cargo:rerun-if-changed=src/sp1/src/main.rs");
    println!("cargo:rerun-if-changed=src/sp1/Cargo.toml");
    println!("cargo:rerun-if-changed=src/execution.rs");
    println!("cargo:rerun-if-changed=src/output.rs");
}

#[cfg(feature = "sp1")]
fn build_sp1_guest() {
    use sp1_sdk::{HashableKey, ProverClient};

    println!("cargo:warning=Building SP1 guest program...");

    // Build the guest program using sp1-build
    // This compiles src/sp1/ to RISC-V and outputs to src/sp1/out/
    sp1_build::build_program_with_args(
        "./src/sp1",
        sp1_build::BuildArgs {
            output_directory: Some("./src/sp1/out".to_string()),
            elf_name: Some("uni-evm-sp1-elf".to_string()),
            ignore_rust_version: true, // Allow any Rust version
            features: vec![],
            tag: "v5.0.8".to_string(),
            ..Default::default()
        },
    );

    println!("cargo:warning=SP1 guest program built successfully");

    // Generate verification key
    println!("cargo:warning=Generating verification key...");

    // Read the ELF binary
    let elf_path = "./src/sp1/out/uni-evm-sp1-elf";
    let elf = match std::fs::read(elf_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to read ELF from {}: {}", elf_path, e);
            panic!("ELF file not found. SP1 build may have failed.");
        }
    };

    // Setup the prover to get the verification key
    let prover = ProverClient::from_env();
    let (_, vk) = prover.setup(&elf);

    // Serialize the verification key using bincode
    // This matches the format expected by BFT-Core's sp1-verifier-ffi
    let vk_bytes = match bincode::serialize(&vk.vk) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to serialize verification key: {}", e);
            panic!("Verification key serialization failed");
        }
    };

    // Save the verification key
    let vkey_path = "./src/sp1/out/uni-evm-vkey.bin";
    if let Err(e) = std::fs::write(vkey_path, &vk_bytes) {
        eprintln!("Failed to write verification key to {}: {}", vkey_path, e);
        panic!("Failed to save verification key");
    }

    println!("cargo:warning=Verification key generated successfully");
    println!(
        "cargo:warning=VKey hash: {} ({} bytes)",
        vk.vk.bytes32(),
        vk_bytes.len()
    );
    println!("cargo:warning=VKey saved to: {}", vkey_path);
    println!("cargo:warning=ELF size: {} bytes", elf.len());

    // Set environment variables for access in the crate
    println!("cargo:rustc-env=UNI_EVM_VKEY_PATH={}", vkey_path);
    println!("cargo:rustc-env=UNI_EVM_ELF_SIZE={}", elf.len());
}
