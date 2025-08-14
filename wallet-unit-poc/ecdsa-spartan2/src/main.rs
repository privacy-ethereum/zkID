//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for either ECDSA or JWT circuits
//! Run with:
//!   RUST_LOG=info cargo run --release -- ecdsa
//!   RUST_LOG=info cargo run --release -- jwt
#![allow(non_snake_case)]

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use circom_scotia::{generate_witness_from_wasm, r1cs::CircomConfig, synthesize};
use spartan2::{
    R1CSSNARK,
    bellpepper::{r1cs::SpartanShape, shape_cs::ShapeCS},
    provider::T256HyraxEngine,
    traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};
use std::{
    env::{args, current_dir},
    fs::File,
    io::Read,
    path::PathBuf,
    time::Instant,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

// ecdsa/ecdsa.circom
#[derive(Debug, Clone)]
struct ECDSACircuit;

impl SpartanCircuit<E> for ECDSACircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let root = current_dir().unwrap().join("../circom");
        let witness_dir = root.join("build/ecdsa/ecdsa_js");
        let wtns = witness_dir.join("main.wasm");
        let r1cs = witness_dir.join("ecdsa.r1cs");

        let witness_input_json: String = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/ecdsa/default.json");
            let mut file = File::open(path).unwrap();
            let mut witness_input = String::new();
            file.read_to_string(&mut witness_input).unwrap();
            witness_input
        };

        let witness: Vec<_> = generate_witness_from_wasm(
            witness_dir,
            witness_input_json,
            PathBuf::from("output.wtns"),
        );

        let cfg = CircomConfig::new(wtns, r1cs).unwrap();
        synthesize(cs, cfg.r1cs.clone(), Some(witness))?;
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
}

// jwt.circom
#[derive(Debug, Clone)]
struct JWTCircuit;

impl SpartanCircuit<E> for JWTCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let root = current_dir().unwrap().join("../circom");
        let witness_dir = root.join("build/jwt/jwt_js");
        let wtns = witness_dir.join("main.wasm");
        let r1cs = witness_dir.join("jwt.r1cs");

        let witness_input_json: String = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/jwt/default.json");
            let mut file = File::open(path).unwrap();
            let mut witness_input = String::new();
            file.read_to_string(&mut witness_input).unwrap();
            witness_input
        };

        let witness: Vec<_> = generate_witness_from_wasm(
            witness_dir,
            witness_input_json,
            PathBuf::from("output.wtns"),
        );

        let cfg = CircomConfig::new(wtns, r1cs).unwrap();
        synthesize(cs, cfg.r1cs.clone(), Some(witness))?;
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
}

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

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let choice = args.get(1).map(|s| s.as_str()).unwrap_or("ecdsa");

    match choice {
        "ecdsa" => {
            info!("Running ECDSA circuit");
            run_circuit(ECDSACircuit);
        }
        "jwt" => {
            info!("Running JWT circuit");
            run_circuit(JWTCircuit);
        }
        other => {
            eprintln!("Unknown choice '{}'. Use 'ecdsa' or 'jwt'.", other);
            std::process::exit(1);
        }
    }
}
