//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for either ECDSA or JWT circuits.
//!
//! Usage:
//!   RUST_LOG=info cargo run --release -- ecdsa
//!   RUST_LOG=info cargo run --release -- jwt
//!
//! To benchmark only the JWT circuit sum-check:
//!   RUST_LOG=info cargo run --release -- jwt_sum_check
//!
//! To benchmark only Spartan sum-check + Hyrax for ECDSA/JWT:
//!   RUST_LOG=info cargo run --release -- prove_jwt
//!   RUST_LOG=info cargo run --release -- prove_ecdsa

use crate::ecdsa_circuit::ECDSACircuit;
use crate::jwt_circuit::JWTCircuit;
use crate::setup::{load_keys, setup_ecdsa_keys, setup_jwt_keys};

use spartan2::{
    provider::T256HyraxEngine,
    spartan::R1CSSNARK,
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait, Engine},
};
use std::{env::args, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

mod ecdsa_circuit;
mod jwt_circuit;
mod setup;

fn run_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(circuit: C) {
    // SETUP
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "setup");

    // PREPARE
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prep_ms, "prep_prove");

    // PROVE
    let t0 = Instant::now();
    let proof =
        R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prove_ms, "prove");

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "verify");

    // Summary
    info!(
        "SUMMARY , setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
        setup_ms, prep_ms, prove_ms, verify_ms
    );
}

fn prove_sum_check_jwt() {
    let circuit = JWTCircuit;
    let pk_path = "keys/jwt_proving.key";
    let vk_path = "keys/jwt_verifying.key";

    let (pk, _vk) = match load_keys(pk_path, vk_path) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to load keys: {}", e);
            panic!("Could not load keys: {}", e);
        }
    };

    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("JWT prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    R1CSSNARK::<E>::prove_sum_check(&pk, circuit.clone(), &mut prep_snark, false)
        .expect("prove_sum_check failed");
    let sumcheck_ms = t0.elapsed().as_millis();

    info!("JWT prove_sum_check: {} ms", sumcheck_ms);

    let total_ms = prep_ms + sumcheck_ms;
    info!(
        "JWT sumcheck TOTAL: {} ms (~{:.1}s)",
        total_ms,
        total_ms as f64 / 1000.0
    );
}

fn prove_jwt() {
    let circuit = JWTCircuit;
    let pk_path = "keys/jwt_proving.key";
    let vk_path = "keys/jwt_verifying.key";

    let (pk, _vk) = match load_keys(pk_path, vk_path) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to load keys: {}", e);
            panic!("Could not load keys: {}", e);
        }
    };

    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("JWT prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let sumcheck_ms = t0.elapsed().as_millis();

    info!("JWT prove: {} ms", sumcheck_ms);

    let total_ms = prep_ms + sumcheck_ms;
    info!(
        "JWT prove sumcheck + Hyrax TOTAL: {} ms (~{:.1}s)",
        total_ms,
        total_ms as f64 / 1000.0
    );
}
fn prove_ecdsa() {
    let circuit = ECDSACircuit;
    let pk_path = "keys/ecdsa_proving.key";
    let vk_path = "keys/ecdsa_verifying.key";

    let (pk, _vk) = match load_keys(pk_path, vk_path) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to load keys: {}", e);
            panic!("Could not load keys: {}", e);
        }
    };

    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("JWT prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let sumcheck_ms = t0.elapsed().as_millis();

    info!("JWT prove: {} ms", sumcheck_ms);

    let total_ms = prep_ms + sumcheck_ms;
    info!(
        "JWT prove sumcheck + Hyrax TOTAL: {} ms (~{:.1}s)",
        total_ms,
        total_ms as f64 / 1000.0
    );
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let choice = args.get(1).map(|s| s.as_str()).unwrap_or("ecdsa");

    match choice {
        "setup-ecdsa" => {
            setup_ecdsa_keys();
        }
        "setup-jwt" => {
            setup_jwt_keys();
        }

        "ecdsa" => {
            info!("Running ECDSA circuit");
            run_circuit(ECDSACircuit);
        }
        "jwt" => {
            info!("Running JWT circuit");
            run_circuit(JWTCircuit);
        }
        "jwt_sum_check" => {
            info!("Running JWT sum check circuit");
            prove_sum_check_jwt();
        }
        "prove_jwt" => {
            info!("Spartan sumcheck + Hyrax PCS JWT");
            prove_jwt();
        }
        "prove_ecdsa" => {
            info!("Spartan sumcheck + Hyrax PCS ECDSA");
            prove_ecdsa();
        }
        other => {
            eprintln!("Unknown choice '{}'", other);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::time::Instant;

    use spartan2::spartan::R1CSSNARK;
    use tracing::info;

    use crate::setup::load_keys;

    #[test]
    fn test_proving_ecdsa_from_keys() {
        setup_ecdsa_keys();

        info!("=== ECDSA Proving: Using saved keys ===");
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
        let mut prep_snark =
            R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
        let prep_ms = t0.elapsed().as_millis();
        info!(elapsed_ms = prep_ms, "ECDSA prep_prove");

        // PROVE
        let t0 = Instant::now();
        let proof = R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false)
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
