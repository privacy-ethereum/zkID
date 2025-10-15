use std::{collections::HashMap, env::current_dir, fs::File, str::FromStr};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use rust_witness::BigInt;
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;

use crate::{Scalar, E};

rust_witness::witness!(ecdsa);

/// Helper function to convert BigInt witness to Scalar witness
fn convert_bigint_to_scalar(bigint_witness: Vec<BigInt>) -> Vec<Scalar> {
    bigint_witness
        .iter()
        .map(|bigint_val| {
            let bytes = bigint_val.to_bytes_le().1;
            let mut padded = bytes.clone();
            // Pad to 32 bytes for Scalar
            padded.resize(32, 0);
            let array: [u8; 32] = padded.try_into().unwrap();
            Scalar::from_bytes(&array).unwrap()
        })
        .collect()
}

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
        let json_file = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/ecdsa/default.json");
            File::open(path).expect("Failed to open ecdsa_input.json")
        };

        let json_value: Value =
            serde_json::from_reader(json_file).expect("Failed to parse ecdsa_input.json");
        let mut inputs = HashMap::new();

        // Parse ECDSA-specific inputs
        inputs.insert(
            "s_inverse".to_string(),
            vec![BigInt::from_str(json_value["s_inverse"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "r".to_string(),
            vec![BigInt::from_str(json_value["r"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "m".to_string(),
            vec![BigInt::from_str(json_value["m"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "pubKeyX".to_string(),
            vec![BigInt::from_str(json_value["pubKeyX"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "pubKeyY".to_string(),
            vec![BigInt::from_str(json_value["pubKeyY"].as_str().unwrap()).unwrap()],
        );

        // Generate witness using native Rust (rust-witness)
        let witness_bigint = ecdsa_witness(inputs);

        let witness: Vec<Scalar> = convert_bigint_to_scalar(witness_bigint);
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
