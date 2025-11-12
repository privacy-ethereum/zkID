//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for Prepare, and Show circuits.
//!
//! Usage:
//! To benchmark complete Spartan2 flow
//!   RUST_LOG=info cargo run --release -- prepare
//!   RUST_LOG=info cargo run --release -- show
//!
//! To setup the Spartan2 circuits:
//!   RUST_LOG=info cargo run --release -- setup_prepare
//!   RUST_LOG=info cargo run --release -- setup_show
//!
//! To benchmark only Spartan2 Proof
//!   RUST_LOG=info cargo run --release -- prove_prepare
//!   RUST_LOG=info cargo run --release -- prove_show
//!
//! To verify saved proofs:
//!   RUST_LOG=info cargo run --release -- verify_prepare
//!   RUST_LOG=info cargo run --release -- verify_show

use crate::{
    circuits::{prepare_circuit::PrepareCircuit, show_circuit::ShowCircuit},
    prover::{generate_shared_blinds, prove_circuit, reblind, run_circuit, verify_circuit},
    setup::{
        PREPARE_INSTANCE, PREPARE_PROOF, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY, PREPARE_WITNESS, SHARED_BLINDS, SHOW_INSTANCE, SHOW_PROOF, SHOW_PROVING_KEY, SHOW_VERIFYING_KEY, SHOW_WITNESS, setup_circuit_keys
    },
};

use spartan2::{provider::T256HyraxEngine, traits::Engine};
use std::env::args;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

mod circuits;
mod prover;
mod setup;
mod utils;

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let choice = args.get(1).map(|s| s.as_str()).unwrap_or("ecdsa");
    // FIXME make this dynamic
    const NUM_SHARED: usize = 1;

    match choice {
        "setup_prepare" => {
            setup_circuit_keys(PrepareCircuit, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY);
        }
        "setup_show" => {
            setup_circuit_keys(ShowCircuit, SHOW_PROVING_KEY, SHOW_VERIFYING_KEY);
        }
        "generate_shared_blinds" => {
            generate_shared_blinds::<E>(SHARED_BLINDS, NUM_SHARED);
        }
        "prove_show" => {
            info!("Running Show circuit with ZK-Spartan");
            prove_circuit(
                ShowCircuit,
                SHOW_PROVING_KEY,
                SHOW_INSTANCE,
                SHOW_WITNESS,
                SHOW_PROOF,
            );
        }
        "reblind_show" => {
            info!("Reblind Spartan sumcheck + Hyrax PCS Show");
            reblind(
                ShowCircuit,
                SHOW_PROVING_KEY,
                SHOW_INSTANCE,
                SHOW_WITNESS,
                SHOW_PROOF,
                SHARED_BLINDS,
            );
        }
        "prove_prepare" => {
            info!("Spartan sumcheck + Hyrax PCS Prepare");
            prove_circuit(
                PrepareCircuit,
                PREPARE_PROVING_KEY,
                PREPARE_INSTANCE,
                PREPARE_WITNESS,
                PREPARE_PROOF,
            );
        }
        "reblind_prepare" => {
            info!("Reblind Spartan sumcheck + Hyrax PCS Prepare");
            reblind(
                PrepareCircuit,
                PREPARE_PROVING_KEY,
                PREPARE_INSTANCE,
                PREPARE_WITNESS,
                PREPARE_PROOF,
                SHARED_BLINDS,
            );
        }
        "verify_prepare" => {
            info!("Verifying Prepare circuit proof");
            verify_circuit(PREPARE_PROOF, PREPARE_VERIFYING_KEY);
        }
        "verify_show" => {
            info!("Verifying Show circuit proof");
            verify_circuit(SHOW_PROOF, SHOW_VERIFYING_KEY);
        }
        "prepare" => {
            info!("Running Prepare circuit with ZK-Spartan");
            run_circuit(PrepareCircuit);
        }
        "show" => {
            info!("Running Show circuit with ZK-Spartan");
            run_circuit(ShowCircuit);
        }
        other => {
            eprintln!("Unknown choice '{}'", other);
            std::process::exit(1);
        }
    }
}
