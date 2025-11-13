use std::{env::current_dir, fs::File, time::Instant};

use crate::{
    circuits::prepare_circuit::jwt_witness,
    setup::{
        load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
        load_witness, save_instance, save_proof, save_shared_blinds, save_witness,
    },
    utils::{convert_bigint_to_scalar, parse_jwt_inputs},
    Scalar, E,
};

use bellpepper_core::SynthesisError;
use ff::{derive::rand_core::OsRng, Field};
use serde_json::Value;
use spartan2::{
    bellpepper::{solver::SatisfyingAssignment, zk_r1cs::SpartanWitness},
    errors::SpartanError,
    provider::traits::DlogGroup,
    traits::{
        circuit::SpartanCircuit, snark::R1CSSNARKTrait, transcript::TranscriptEngineTrait, Engine,
    },
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

pub fn generate_shared_blinds<E: Engine>(shared_blinds_path: &str, n: usize) {
    let blinds: Vec<_> = (0..n).map(|_| E::Scalar::random(OsRng)).collect();
    if let Err(e) = save_shared_blinds::<E>(shared_blinds_path, &blinds) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }
}

/// Only run the proving part of the circuit using ZK-Spartan (prep_prove, prove)
pub fn prove_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: &str,
    instance_path: &str,
    witness_path: &str,
    proof_path: &str,
) {
    let pk = load_proving_key(pk_path).expect("load proving key failed");

    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("ZK-Spartan prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    let mut transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    transcript.absorb(b"vk", &pk.vk_digest);

    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })
        .unwrap();

    // absorb the public values into the transcript
    transcript.absorb(b"public_values", &public_values.as_slice());

    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps,
        &pk.S,
        &pk.ck,
        &circuit,
        false,
        &mut transcript,
    )
    .unwrap();

    // generate a witness and proof
    let res = R1CSSNARK::<E>::prove_inner(&pk, &instance, &witness, &mut transcript).unwrap();
    let prove_ms = t0.elapsed().as_millis();

    info!("ZK-Spartan prove: {} ms", prove_ms);

    let total_ms = prep_ms + prove_ms;

    info!(
        "ZK-Spartan prep_prove: ({} ms) + prove: ({} ms) = TOTAL: {} ms",
        prep_ms, prove_ms, total_ms
    );

    // Save the instance to file
    if let Err(e) = save_instance(instance_path, &instance) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }

    // Save the witness to file
    if let Err(e) = save_witness(witness_path, &witness) {
        eprintln!("Failed to save witness: {}", e);
        std::process::exit(1);
    }

    // Save the proof to file
    if let Err(e) = save_proof(proof_path, &res) {
        eprintln!("Failed to save proof: {}", e);
        std::process::exit(1);
    }
}

pub fn reblind<C: SpartanCircuit<E>>(
    circuit: C,
    pk_path: &str,
    instance_path: &str,
    witness_path: &str,
    proof_path: &str,
    shared_blinds_path: &str,
) {
    let pk = load_proving_key(pk_path).expect("load proving key failed");

    let instance = load_instance(instance_path).expect("load instance failed");
    let witness = load_witness(witness_path).expect("load witness failed");

    let randomness =
        load_shared_blinds::<E>(shared_blinds_path).expect("load shared_blinds failed");

    assert_eq!(randomness.len(), instance.num_shared_rows());

    // Reblind instance and witness
    let mut reblind_transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    reblind_transcript.absorb(b"vk", &pk.vk_digest);

    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })
        .unwrap();

    // absorb the public values into the reblind_transcript
    reblind_transcript.absorb(b"public_values", &public_values.as_slice());

    let (new_instance, new_witness) = SatisfyingAssignment::reblind_r1cs_instance_and_witness(
        &randomness,
        instance,
        witness,
        &pk.ck,
        &mut reblind_transcript,
    )
    .unwrap();

    println!(
        "new instance: {:?}",
        new_instance
            .clone()
            .comm_W_shared
            .map(|v| v.comm.iter().for_each(|v| println!("v: {:?}", v.affine())))
    );

    // generate a witness and proof
    let res =
        R1CSSNARK::<E>::prove_inner(&pk, &new_instance, &new_witness, &mut reblind_transcript)
            .unwrap();

    // Save the instance to file
    if let Err(e) = save_instance(instance_path, &new_instance) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }

    // Save the witness to file
    if let Err(e) = save_witness(witness_path, &new_witness) {
        eprintln!("Failed to save witness: {}", e);
        std::process::exit(1);
    }

    // Save the proof to file
    if let Err(e) = save_proof(proof_path, &res) {
        eprintln!("Failed to save proof: {}", e);
        std::process::exit(1);
    }
}

/// Only run the verification part using ZK-Spartan
pub fn verify_circuit(proof_path: &str, vk_path: &str) {
    let proof = load_proof(proof_path).expect("load proof failed");
    let vk = load_verifying_key(vk_path).expect("load verifying key failed");

    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "ZK-Spartan verify");

    info!("Verification successful! Time: {} ms", verify_ms);
}

/// Generate witness for the Prepare circuit.
/// Returns the full witness vector, the decoded age-claim bytes, and the extracted KeyBindingX/Y values.
pub fn generate_prepare_witness(
    input_json_path: Option<&std::path::Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    let root = current_dir().unwrap().join("../circom");

    let json_path = input_json_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| root.join("inputs/jwt/default.json"));

    info!("Loading prepare inputs from {}", json_path.display());

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
    Ok(witness)
}
