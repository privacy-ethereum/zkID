//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for Prepare, and Show circuits.
//!
//! Usage:
//! To benchmark complete Spartan2 flow
//!   RUST_LOG=info cargo run --release -- prepare
//!   RUST_LOG=info cargo run --release -- show
//!
//! To benchmark only Spartan2 Proof
//!   RUST_LOG=info cargo run --release -- prove_prepare
//!   RUST_LOG=info cargo run --release -- prove_show
//!
//! To setup the Spartan2 circuits:
//!   RUST_LOG=info cargo run --release -- setup_prepare
//!   RUST_LOG=info cargo run --release -- setup_show

use crate::{
    circuits::{prepare_circuit::PrepareCircuit, show_circuit::ShowCircuit},
    prover::{prove_circuit, run_circuit},
    setup::{
        setup_circuit_keys, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY, SHOW_PROVING_KEY,
        SHOW_VERIFYING_KEY,
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

    match choice {
        "setup_prepare" => {
            setup_circuit_keys(PrepareCircuit, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY);
        }
        "setup_show" => {
            setup_circuit_keys(ShowCircuit, SHOW_PROVING_KEY, SHOW_VERIFYING_KEY);
        }
        "prove_show" => {
            info!("Running Show circuit with ZK-Spartan");
            prove_circuit(ShowCircuit, SHOW_PROVING_KEY);
        }
        "prove_prepare" => {
            info!("Spartan sumcheck + Hyrax PCS Prepare");
            prove_circuit(PrepareCircuit, PREPARE_PROVING_KEY);
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
