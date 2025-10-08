use std::{
    fs::{create_dir_all, File},
    io::{BufReader, Cursor, Read, Write},
    path::Path,
    time::Instant,
};

use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use tracing::info;

use crate::{ecdsa_circuit::ECDSACircuit, jwt_circuit::JWTCircuit, E};
use memmap2::MmapOptions;

pub fn run_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(circuit: C) {
    // SETUP using ZK-Spartan
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "ZK-Spartan setup");

    // PREPARE
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prep_ms, "ZK-Spartan prep_prove");

    // PROVE
    let t0 = Instant::now();
    let proof =
        R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prove_ms, "ZK-Spartan prove");

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "ZK-Spartan verify");

    // Summary
    info!(
        "ZK-Spartan SUMMARY , setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
        setup_ms, prep_ms, prove_ms, verify_ms
    );
}

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

pub fn save_chunked_proving_key(
    base_dir: &str,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    chunk_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = Path::new(base_dir);

    // Ensure directories exist
    let pk_dir = base.join("proving_key");
    create_dir_all(&pk_dir)?;

    // --- Save proving key in chunks ---
    let pk_bytes = bincode::serialize(pk)?;
    let mut offset = 0;
    let mut chunk_idx = 0;

    while offset < pk_bytes.len() {
        let end = (offset + chunk_size).min(pk_bytes.len());
        let chunk = &pk_bytes[offset..end];

        let chunk_path = pk_dir.join(format!("chunk_{}.bin", chunk_idx));
        let mut chunk_file = File::create(&chunk_path)?;
        chunk_file.write_all(chunk)?;

        info!(
            "Saved proving key chunk {} ({} bytes) to: {}",
            chunk_idx,
            chunk.len(),
            chunk_path.display()
        );

        offset = end;
        chunk_idx += 1;
    }

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

pub fn load_proving_chunked_key(
    pk_dir: &str,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey, Box<dyn std::error::Error>> {
    let dir = Path::new(pk_dir);

    // Collect and sort chunk paths
    let mut chunks: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            if name.starts_with("chunk_") && name.ends_with(".bin") {
                Some((entry.path(), name))
            } else {
                None
            }
        })
        .collect();

    chunks.sort_by_key(|(_, name)| {
        name.trim_start_matches("chunk_")
            .trim_end_matches(".bin")
            .parse::<usize>()
            .unwrap_or(0)
    });

    // Build a single reader over all chunks
    let mut reader: Box<dyn Read> = Box::new(BufReader::new(File::open(&chunks[0].0)?));
    for (path, _) in chunks.into_iter().skip(1) {
        let next_reader = BufReader::new(File::open(path)?);
        reader = Box::new(reader.chain(next_reader));
    }

    // Deserialize directly from the chained reader
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        bincode::deserialize_from(&mut reader)?;

    Ok(pk)
}

pub fn setup_ecdsa_keys() {
    info!("=== ECDSA Setup (ZK-Spartan): Generating and saving keys ===");
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
    info!("=== JWT Setup (ZK-Spartan): Generating and saving keys ===");
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

pub fn setup_jwt_chunked_keys() {
    info!("=== Chunked JWT Setup (ZK-Spartan): Generating and saving keys ===");
    let circuit = JWTCircuit;

    let t0 = Instant::now();
    let (pk, _) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(
        elapsed_ms = setup_ms,
        "Chunked JWT setup completed (~{:.1}s)",
        setup_ms as f64 / 1000.0
    );

    let base_dir = "keys/chunked_jwt_keys";
    let chunk_size = 100 * 1024 * 1024; // 100 MB chunks

    if let Err(e) = save_chunked_proving_key(base_dir, &pk, chunk_size) {
        eprintln!("Failed to save chunked keys: {}", e);
        std::process::exit(1);
    }

    info!("Chunked JWT keys generated and saved successfully!");
    info!("Proving key chunks directory: {}/proving_key", base_dir);
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::time::Instant;

    use spartan2::traits::snark::R1CSSNARKTrait;
    use tracing::info;

    use crate::setup::load_keys;

    #[test]
    fn test_proving_ecdsa_from_keys() {
        setup_ecdsa_keys();

        info!("=== ECDSA Proving (ZK-Spartan): Using saved keys ===");
        let circuit = ECDSACircuit;

        // Load keys
        let pk_path = "keys/ecdsa_proving.key";
        let vk_path = "keys/ecdsa_verifying.key";

        let (pk, vk) = match load_keys(pk_path, vk_path) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("Failed to load keys: {}", e);
                eprintln!("Run 'cargo run --release -- setup-ecdsa' first to generate keys");
                std::process::exit(1);
            }
        };

        // PREPARE
        let t0 = Instant::now();
        let mut prep_snark = super::R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false)
            .expect("prep_prove failed");
        let prep_ms = t0.elapsed().as_millis();
        info!(elapsed_ms = prep_ms, "ECDSA prep_prove");

        // PROVE
        let t0 = Instant::now();
        let proof = super::R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false)
            .expect("prove failed");
        let prove_ms = t0.elapsed().as_millis();
        info!(elapsed_ms = prove_ms, "ECDSA prove");

        // VERIFY
        let t0 = Instant::now();
        proof.verify(&vk).expect("verify errored");
        let verify_ms = t0.elapsed().as_millis();
        info!(elapsed_ms = verify_ms, "ECDSA verify");

        let total_ms = prep_ms + prove_ms + verify_ms;
        info!("ECDSA Proving TOTAL: {} ms (without setup)", total_ms);
    }
}
