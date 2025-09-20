use std::time::Instant;

use crate::{ecdsa_circuit::ECDSACircuit, jwt_circuit::JWTCircuit, setup::load_keys, E};

use spartan2::{spartan::R1CSSNARK, traits::snark::R1CSSNARKTrait};
use tracing::info;

pub fn prove_sum_check_jwt() {
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

pub fn prove_ecdsa() {
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
    info!("ECDSA prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let sumcheck_ms = t0.elapsed().as_millis();

    info!("ECDSA prove: {} ms", sumcheck_ms);

    let total_ms = prep_ms + sumcheck_ms;
    info!(
        "ECDSA prove sumcheck + Hyrax TOTAL: {} ms (~{:.1}s)",
        total_ms,
        total_ms as f64 / 1000.0
    );
}
