use std::{any::type_name, collections::HashMap, env::current_dir, fs::File};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;

use crate::{utils::*, Scalar, E};

rust_witness::witness!(ecdsa);

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
        let r1cs = witness_dir.join("ecdsa.r1cs");

        // Detect if we're in setup phase (ShapeCS) or prove phase (SatisfyingAssignment)
        // During setup, we only need constraint structure instead of actual witness values
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs = load_r1cs(r1cs);
            // Pass None for witness during setup
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let json_file = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/ecdsa/default.json");
            File::open(path).expect("Failed to open ecdsa_input.json")
        };

        let json_value: Value =
            serde_json::from_reader(json_file).expect("Failed to parse ecdsa_input.json");

        // Parse inputs
        let mut inputs = HashMap::new();
        inputs.insert(
            "s_inverse".to_string(),
            vec![parse_bigint_scalar(&json_value, "s_inverse")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "r".to_string(),
            vec![parse_bigint_scalar(&json_value, "r")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "m".to_string(),
            vec![parse_bigint_scalar(&json_value, "m")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "pubKeyX".to_string(),
            vec![parse_bigint_scalar(&json_value, "pubKeyX")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "pubKeyY".to_string(),
            vec![parse_bigint_scalar(&json_value, "pubKeyY")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );

        // Generate witness using native Rust (rust-witness)
        let witness_bigint = ecdsa_witness(inputs);

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
