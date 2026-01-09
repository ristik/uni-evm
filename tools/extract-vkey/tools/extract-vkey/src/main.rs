use sp1_sdk::ProverClient;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Extracting verification key from ethrex's SP1 guest program...");
    
    // Read ethrex's SP1 ELF
    let elf_path = "../../ethrex/crates/l2/prover/src/guest_program/src/sp1/out/riscv32im-succinct-zkvm-elf";
    let elf_bytes = fs::read(elf_path)?;
    println!("Read ELF: {} bytes from {}", elf_bytes.len(), elf_path);
    
    // Setup SP1 prover and extract vkey
    let client = ProverClient::from_env();
    let (_, vk) = client.setup(&elf_bytes);
    
    println!("VKey hash: {}", vk.bytes32());
    
    // Serialize vkey with bincode (same format BFT-Core expects)
    let vkey_bytes = bincode::serialize(&vk)?;
    
    // Save to file
    let output_path = "../../ethrex-vkey.bin";
    fs::write(output_path, &vkey_bytes)?;
    
    println!("Saved verification key to: ethrex-vkey.bin");
    println!("VKey size: {} bytes", vkey_bytes.len());
    
    Ok(())
}
