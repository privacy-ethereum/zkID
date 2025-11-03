use std::{env::current_dir, fs::File, io::Read, path::PathBuf};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{generate_witness_from_wasm, r1cs::CircomConfig, synthesize};
use spartan2::traits::circuit::SpartanCircuit;

use crate::{Scalar, E};

// ecdsa/ecdsa.circom
#[derive(Debug, Clone)]
pub struct ECDSACircuit;

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
