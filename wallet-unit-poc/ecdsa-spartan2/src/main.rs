//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for a ECDSA Circuit
//! circuit with varying message lengths
//! Run with: `RUST_LOG=info cargo run --release
#![allow(non_snake_case)]
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{generate_witness_from_wasm, r1cs::CircomConfig, synthesize};
use spartan2::{
    bellpepper::{r1cs::SpartanShape, shape_cs::ShapeCS},
    provider::T256HyraxEngine,
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait, Engine},
    R1CSSNARK,
};
use std::{env::current_dir, fs::File, io::Read, path::PathBuf, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

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

    fn public_values(
        &self,
    ) -> Result<Vec<<E as spartan2::traits::Engine>::Scalar>, SynthesisError> {
        Ok(vec![])
    }

    fn shared<CS: ConstraintSystem<<E as spartan2::traits::Engine>::Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<
        Vec<bellpepper_core::num::AllocatedNum<<E as spartan2::traits::Engine>::Scalar>>,
        SynthesisError,
    > {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<<E as spartan2::traits::Engine>::Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[bellpepper_core::num::AllocatedNum<<E as spartan2::traits::Engine>::Scalar>],
    ) -> Result<
        Vec<bellpepper_core::num::AllocatedNum<<E as spartan2::traits::Engine>::Scalar>>,
        SynthesisError,
    > {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true) // no bold colour codes
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let circuit = ECDSACircuit;

    // SETUP
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    println!("setup: {}", setup_ms);

    // PROVE
    let t0 = Instant::now();
    let proof = R1CSSNARK::<E>::prove(&pk, circuit.clone(), false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    println!("prove : {}", prove_ms);

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    println!("verify: {}", verify_ms);
}
