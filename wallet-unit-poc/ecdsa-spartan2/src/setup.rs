use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    time::Instant,
};

use spartan2::{spartan::R1CSSNARK, traits::snark::R1CSSNARKTrait};
use tracing::info;

use crate::{ecdsa_circuit::ECDSACircuit, jwt_circuit::JWTCircuit, E};

pub fn save_keys(
    pk_path: &str,
    vk_path: &str,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = std::path::Path::new(pk_path).parent() {
        create_dir_all(parent)?;
    }
    if let Some(parent) = std::path::Path::new(vk_path).parent() {
        create_dir_all(parent)?;
    }

    let pk_bytes = bincode::serialize(pk)?;
    let mut pk_file = File::create(pk_path)?;
    pk_file.write_all(&pk_bytes)?;
    info!("Saved proving key to: {}", pk_path);

    let vk_bytes = bincode::serialize(vk)?;
    let mut vk_file = File::create(vk_path)?;
    vk_file.write_all(&vk_bytes)?;
    info!("Saved verifying key to: {}", vk_path);

    Ok(())
}

pub fn load_keys(
    pk_path: &str,
    vk_path: &str,
) -> Result<
    (
        <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
        <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    ),
    Box<dyn std::error::Error>,
> {
    let mut pk_file = File::open(pk_path)?;
    let mut pk_bytes = Vec::new();
    pk_file.read_to_end(&mut pk_bytes)?;
    let pk = bincode::deserialize(&pk_bytes)?;
    info!("Loaded proving key from: {}", pk_path);

    let mut vk_file = File::open(vk_path)?;
    let mut vk_bytes = Vec::new();
    vk_file.read_to_end(&mut vk_bytes)?;
    let vk = bincode::deserialize(&vk_bytes)?;
    info!("Loaded verifying key from: {}", vk_path);

    Ok((pk, vk))
}

pub fn setup_ecdsa_keys() {
    info!("=== ECDSA Setup: Generating and saving keys ===");
    let circuit = ECDSACircuit;

    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "ECDSA setup completed");

    let pk_path = "keys/ecdsa_proving.key";
    let vk_path = "keys/ecdsa_verifying.key";

    if let Err(e) = save_keys(pk_path, vk_path, &pk, &vk) {
        eprintln!("Failed to save keys: {}", e);
        std::process::exit(1);
    }

    info!("ECDSA keys generated and saved successfully!");
    info!("Proving key: {}", pk_path);
    info!("Verifying key: {}", vk_path);
}

pub fn setup_jwt_keys() {
    info!("=== JWT Setup: Generating and saving keys ===");
    let circuit = JWTCircuit;

    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(
        elapsed_ms = setup_ms,
        "JWT setup completed (~{:.1}s)",
        setup_ms as f64 / 1000.0
    );

    let pk_path = "keys/jwt_proving.key";
    let vk_path = "keys/jwt_verifying.key";

    if let Err(e) = save_keys(pk_path, vk_path, &pk, &vk) {
        eprintln!("Failed to save keys: {}", e);
        std::process::exit(1);
    }

    info!("JWT keys generated and saved successfully!");
    info!("Proving key: {}", pk_path);
    info!("Verifying key: {}", vk_path);
}
