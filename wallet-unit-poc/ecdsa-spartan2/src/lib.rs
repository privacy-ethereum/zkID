//! ECDSA and JWT circuit implementations using Spartan2
//!
//! This library provides zero-knowledge proof circuits for:
//! - ECDSA signature verification
//! - JWT token validation with selective disclosure
//!
//! The circuits use Spartan2's ZK-SNARK protocol with Hyrax polynomial commitment scheme.

use spartan2::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

pub mod circuits;
pub mod prover;
pub mod setup;
pub mod utils;

// Re-export commonly used types and functions
pub use circuits::{prepare_circuit::PrepareCircuit, show_circuit::ShowCircuit};
pub use prover::{
    generate_prepare_witness, generate_shared_blinds, prove_circuit, reblind, run_circuit,
    verify_circuit,
};
pub use setup::{
    load_proving_key, save_keys, setup_circuit_keys, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY,
    SHOW_PROVING_KEY, SHOW_VERIFYING_KEY,
};
pub use utils::{
    bigint_to_scalar, calculate_jwt_output_indices, convert_bigint_to_scalar, parse_jwt_inputs,
    parse_show_inputs,
};
