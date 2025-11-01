//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for ECDSA, Prepare, and Show circuits.
//!
//! Usage:
//!   RUST_LOG=info cargo run --release -- ecdsa
//!   RUST_LOG=info cargo run --release -- jwt
//!   RUST_LOG=info cargo run --release -- show
//!
//! To benchmark only Spartan sum-check + Hyrax for ECDSA/Prepare:
//!   RUST_LOG=info cargo run --release -- prove_jwt
//!   RUST_LOG=info cargo run --release -- prove_ecdsa
//!
//! To setup the ECDSA circuit:
//!   RUST_LOG=info cargo run --release -- setup_ecdsa
//!
//! To setup the Prepare circuit:
//!   RUST_LOG=info cargo run --release -- setup_jwt
//!
//! To setup the chunked Prepare circuit:
//!   RUST_LOG=info cargo run --release -- setup_chunked_jwt

use crate::config_generator::{prove_ecdsa, prove_jwt};
use crate::ecdsa_circuit::ECDSACircuit;
use crate::prepare_circuit::PrepareCircuit;
use crate::setup::{run_circuit, setup_ecdsa_keys, setup_jwt_chunked_keys, setup_jwt_keys};
use crate::show_circuit::ShowCircuit;

use spartan2::{provider::T256HyraxEngine, traits::Engine};
use std::env::args;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

mod config_generator;
mod ecdsa_circuit;
mod prepare_circuit;
mod setup;
mod show_circuit;
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
        "setup_ecdsa" => {
            setup_ecdsa_keys();
        }
        "setup_jwt" => {
            setup_jwt_keys();
        }
        "setup_chunked_jwt" => {
            setup_jwt_chunked_keys();
        }
        "ecdsa" => {
            info!("Running ECDSA circuit with ZK-Spartan");
            run_circuit(ECDSACircuit);
        }
        "jwt" | "prepare" => {
            info!("Running Prepare circuit with ZK-Spartan");
            run_circuit(PrepareCircuit);
        }
        "show" => {
            info!("Running Show circuit with ZK-Spartan");
            run_circuit(ShowCircuit);
        }
        "prove_jwt" | "prove_prepare" => {
            info!("Spartan sumcheck + Hyrax PCS Prepare");
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
