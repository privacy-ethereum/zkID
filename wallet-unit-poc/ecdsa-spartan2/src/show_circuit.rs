use std::{collections::HashMap, env::current_dir, fs::File};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;

use crate::{utils::*, Scalar, E};

rust_witness::witness!(show);

// show.circom
#[derive(Debug, Clone)]
pub struct ShowCircuit;

impl SpartanCircuit<E> for ShowCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let root = current_dir().unwrap().join("../circom");
        let witness_dir = root.join("build/show/show_js");
        let r1cs = witness_dir.join("show.r1cs");
        let json_file = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/show/default.json");
            File::open(path).expect("Failed to open show_input.json")
        };

        let json_value: Value =
            serde_json::from_reader(json_file).expect("Failed to parse show_input.json");

        // Parse inputs
        let mut inputs = HashMap::new();
        inputs.insert(
            "deviceKeyX".to_string(),
            vec![parse_bigint_scalar(&json_value, "deviceKeyX")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "deviceKeyY".to_string(),
            vec![parse_bigint_scalar(&json_value, "deviceKeyY")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "sig_r".to_string(),
            vec![parse_bigint_scalar(&json_value, "sig_r")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "sig_s_inverse".to_string(),
            vec![parse_bigint_scalar(&json_value, "sig_s_inverse")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "nonceLength".to_string(),
            vec![parse_u64_scalar(&json_value, "nonceLength")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );

        // Parse array field
        inputs.insert(
            "nonce".to_string(),
            parse_bigint_string_array(&json_value, "nonce")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );

        // Generate witness using native Rust (rust-witness)
        let witness_bigint = show_witness(inputs);

        let witness: Vec<Scalar> = convert_bigint_to_scalar(witness_bigint)?;
        let r1cs = load_r1cs(r1cs);
        synthesize(cs, r1cs, Some(witness))?;
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
