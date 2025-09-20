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

use crate::config_generator::{prove_ecdsa, prove_sum_check_jwt};
use crate::ecdsa_circuit::ECDSACircuit;
use crate::jwt_circuit::JWTCircuit;
use crate::setup::{
    load_proving_chunked_key, run_circuit, setup_ecdsa_keys, setup_jwt_chunked_keys, setup_jwt_keys,
};

use spartan2::spartan::R1CSSNARK;
use spartan2::traits::snark::R1CSSNARKTrait;
use spartan2::{provider::T256HyraxEngine, traits::Engine};
use std::{env::args, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

mod config_generator;
mod ecdsa_circuit;
mod jwt_circuit;
mod setup;

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
        "setup-chunked-jwt" => {
            setup_jwt_chunked_keys();
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

pub fn prove_jwt() {
    let circuit = JWTCircuit;
    let pk_path = "keys/chunked_jwt_keys/proving_key";

    let pk = load_proving_chunked_key(pk_path).expect("load proving key failed");

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
