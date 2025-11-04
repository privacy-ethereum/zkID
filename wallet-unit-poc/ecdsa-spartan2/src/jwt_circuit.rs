use std::{any::type_name, collections::HashMap, env::current_dir, fs::File, time::Instant};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;
use tracing::info;

use crate::{utils::*, Scalar, E};

rust_witness::witness!(jwt);

// jwt.circom
#[derive(Debug, Clone)]
pub struct JWTCircuit;

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
        let r1cs = witness_dir.join("jwt.r1cs");

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
                .join("../circom/inputs/jwt/default.json");
            File::open(path).expect("Failed to open jwt_input.json")
        };

        let json_value: Value =
            serde_json::from_reader(json_file).expect("Failed to parse jwt_input.json");

        // Parse inputs
        let mut inputs = HashMap::new();
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
            "pubKeyX".to_string(),
            vec![parse_bigint_scalar(&json_value, "pubKeyX")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "pubKeyY".to_string(),
            vec![parse_bigint_scalar(&json_value, "pubKeyY")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );

        // Parse scalar u64 fields (stored as numbers)
        inputs.insert(
            "messageLength".to_string(),
            vec![parse_u64_scalar(&json_value, "messageLength")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "periodIndex".to_string(),
            vec![parse_u64_scalar(&json_value, "periodIndex")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );
        inputs.insert(
            "matchesCount".to_string(),
            vec![parse_u64_scalar(&json_value, "matchesCount")
                .map_err(|_| SynthesisError::AssignmentMissing)?],
        );

        // Parse array fields
        inputs.insert(
            "message".to_string(),
            parse_bigint_string_array(&json_value, "message")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );
        inputs.insert(
            "matchIndex".to_string(),
            parse_u64_array(&json_value, "matchIndex")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );
        inputs.insert(
            "matchLength".to_string(),
            parse_u64_array(&json_value, "matchLength")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );
        inputs.insert(
            "claimLengths".to_string(),
            parse_bigint_string_array(&json_value, "claimLengths")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );
        inputs.insert(
            "decodeFlags".to_string(),
            parse_u64_array(&json_value, "decodeFlags")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );

        // Parse 2D array fields (flattened)
        inputs.insert(
            "matchSubstring".to_string(),
            parse_2d_bigint_array(&json_value, "matchSubstring")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );
        inputs.insert(
            "claims".to_string(),
            parse_2d_bigint_array(&json_value, "claims")
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        );

        // Generate witness using native Rust (rust-witness)
        info!("Generating witness using native Rust (rust-witness)...");
        let t0 = Instant::now();
        let witness_bigint = jwt_witness(inputs);
        info!("rust-witness time: {} ms", t0.elapsed().as_millis());

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
