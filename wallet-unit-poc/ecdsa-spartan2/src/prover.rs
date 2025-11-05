use std::{env::current_dir, fs::File, time::Instant};

use crate::{
    circuits::prepare_circuit::jwt_witness,
    setup::load_proving_key,
    utils::{calculate_jwt_output_indices, convert_bigint_to_scalar, parse_jwt_inputs},
    Scalar, E,
};

use bellpepper_core::SynthesisError;
use serde_json::Value;
use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};
use tracing::info;

/// Run circuit using ZK-Spartan (setup, prepare, prove, verify)
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

    info!("comm_W_shared: {:?}", proof.comm_W_shared());
}

/// Only run the proving part of the circuit using ZK-Spartan (prep_prove, prove)
pub fn prove_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(circuit: C, pk_path: &str) {
    let pk = load_proving_key(pk_path).expect("load proving key failed");

    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("ZK-Spartan prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();

    info!("ZK-Spartan prove: {} ms", prove_ms);

    let total_ms = prep_ms + prove_ms;

    info!(
        "ZK-Spartan prep_prove: ({} ms) + prove: ({} ms) = TOTAL: {} ms",
        prep_ms, prove_ms, total_ms
    );
}

/// Generate witness for the Prepare circuit
/// Returns the witness vector and the extracted KeyBindingX and KeyBindingY values
pub fn generate_prepare_witness(
    input_json_path: Option<&std::path::Path>,
) -> Result<(Vec<Scalar>, Scalar, Scalar), SynthesisError> {
    let root = current_dir().unwrap().join("../circom");

    let json_path = input_json_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| root.join("inputs/jwt/default.json"));

    let json_file = File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;

    let json_value: Value =
        serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

    // Parse inputs using declarative field definitions
    let inputs = parse_jwt_inputs(&json_value)?;

    // Generate witness using native Rust (rust-witness)
    info!("Generating witness using native Rust (rust-witness)...");
    let t0 = Instant::now();
    let witness_bigint = jwt_witness(inputs);
    info!("rust-witness time: {} ms", t0.elapsed().as_millis());

    let witness: Vec<Scalar> = convert_bigint_to_scalar(witness_bigint)?;

    // Calculate KeyBindingX and KeyBindingY indices from circuit parameters
    // JWT circuit params: [maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength]
    // From circuits.json: [2048, 2000, 4, 50, 128]

    // Todo: we can make this dynamic by parsing the circuit parameters from the circuit file
    const MAX_MATCHES: usize = 4;
    const MAX_CLAIMS_LENGTH: usize = 128;

    let (keybinding_x_idx, keybinding_y_idx) =
        calculate_jwt_output_indices(MAX_MATCHES, MAX_CLAIMS_LENGTH);

    let keybinding_x = witness
        .get(keybinding_x_idx)
        .copied()
        .ok_or_else(|| SynthesisError::AssignmentMissing)?;

    let keybinding_y = witness
        .get(keybinding_y_idx)
        .copied()
        .ok_or_else(|| SynthesisError::AssignmentMissing)?;

    Ok((witness, keybinding_x, keybinding_y))
}
