use std::{
    fs::{create_dir_all, File},
    io::{BufReader, Cursor, Write},
    time::Instant,
};

use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use tracing::info;

use crate::E;
use memmap2::MmapOptions;

pub const PREPARE_PROVING_KEY: &str = "keys/prepare_proving.key";
pub const PREPARE_VERIFYING_KEY: &str = "keys/prepare_verifying.key";
pub const SHOW_PROVING_KEY: &str = "keys/show_proving.key";
pub const SHOW_VERIFYING_KEY: &str = "keys/show_verifying.key";

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

    info!("Saved ZK-Spartan proving key to: {}", pk_path);

    let vk_bytes = bincode::serialize(vk)?;
    let mut vk_file = File::create(vk_path)?;
    vk_file.write_all(&vk_bytes)?;
    info!("Saved ZK-Spartan verifying key to: {}", vk_path);

    Ok(())
}

#[allow(dead_code)]
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
    let pk_file = File::open(pk_path)?;
    let pk = bincode::deserialize_from(&mut BufReader::new(pk_file))?;

    info!("Loaded ZK-Spartan proving key from: {}", pk_path);

    let vk_file = File::open(vk_path)?;
    let vk = bincode::deserialize_from(&mut BufReader::new(vk_file))?;
    info!("Loaded ZK-Spartan verifying key from: {}", vk_path);

    Ok((pk, vk))
}

pub fn load_proving_key(
    pk_path: &str,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey, Box<dyn std::error::Error>> {
    let pk_file = File::open(pk_path)?;
    let pk_mmap = unsafe { MmapOptions::new().map(&pk_file)? };
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        bincode::deserialize_from(Cursor::new(&pk_mmap[..]))?;
    Ok(pk)
}

pub fn setup_circuit_keys<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: &str,
    vk_path: &str,
) {
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(
        elapsed_ms = setup_ms,
        "Setup completed (~{:.1}s)",
        setup_ms as f64 / 1000.0
    );

    if let Err(e) = save_keys(pk_path, vk_path, &pk, &vk) {
        eprintln!("Failed to save keys: {}", e);
        std::process::exit(1);
    }

    info!("Keys generated and saved successfully!");
    info!("Proving key: {}", pk_path);
    info!("Verifying key: {}", vk_path);
}
