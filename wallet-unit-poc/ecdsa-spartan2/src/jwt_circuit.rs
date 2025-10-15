use std::{collections::HashMap, env::current_dir, fs::File, str::FromStr, time::Instant};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use rust_witness::BigInt;
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;
use tracing::info;

use crate::{Scalar, E};

rust_witness::witness!(jwt);

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
        let json_file = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/jwt/default.json");
            File::open(path).expect("Failed to open jwt_input.json")
        };

        let json_value: Value =
            serde_json::from_reader(json_file).expect("Failed to parse jwt_input.json");

        let mut inputs = HashMap::new();

        // Parse JWT-specific inputs
        inputs.insert(
            "sig_r".to_string(),
            vec![BigInt::from_str(json_value["sig_r"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "sig_s_inverse".to_string(),
            vec![BigInt::from_str(json_value["sig_s_inverse"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "pubKeyX".to_string(),
            vec![BigInt::from_str(json_value["pubKeyX"].as_str().unwrap()).unwrap()],
        );
        inputs.insert(
            "pubKeyY".to_string(),
            vec![BigInt::from_str(json_value["pubKeyY"].as_str().unwrap()).unwrap()],
        );

        // Parse message array
        let message_array = json_value["message"].as_array().unwrap();
        let message: Vec<BigInt> = message_array
            .iter()
            .map(|v| BigInt::from_str(v.as_str().unwrap()).unwrap())
            .collect();
        inputs.insert("message".to_string(), message);

        inputs.insert(
            "messageLength".to_string(),
            vec![BigInt::from(json_value["messageLength"].as_u64().unwrap())],
        );
        inputs.insert(
            "periodIndex".to_string(),
            vec![BigInt::from(json_value["periodIndex"].as_u64().unwrap())],
        );
        inputs.insert(
            "matchesCount".to_string(),
            vec![BigInt::from(json_value["matchesCount"].as_u64().unwrap())],
        );

        // Parse matchSubstring (2D array) - flatten it into 1D
        let match_substring_array = json_value["matchSubstring"].as_array().unwrap();
        let match_substring_flat: Vec<BigInt> = match_substring_array
            .iter()
            .flat_map(|inner_array| {
                inner_array
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| BigInt::from_str(v.as_str().unwrap()).unwrap())
            })
            .collect();
        inputs.insert("matchSubstring".to_string(), match_substring_flat);

        // Parse matchLength array
        let match_length: Vec<BigInt> = json_value["matchLength"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                if let Some(s) = v.as_str() {
                    BigInt::from_str(s).unwrap()
                } else if let Some(n) = v.as_u64() {
                    BigInt::from(n)
                } else {
                    panic!("matchLength value must be string or number")
                }
            })
            .collect();
        inputs.insert("matchLength".to_string(), match_length);

        // Parse matchIndex array
        let match_index: Vec<BigInt> = json_value["matchIndex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| BigInt::from(v.as_u64().unwrap()))
            .collect();
        inputs.insert("matchIndex".to_string(), match_index);

        // Parse claims (2D array) - flatten it into 1D
        let claims_array = json_value["claims"].as_array().unwrap();
        let claims_flat: Vec<BigInt> = claims_array
            .iter()
            .flat_map(|inner_array| {
                inner_array
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| BigInt::from_str(v.as_str().unwrap()).unwrap())
            })
            .collect();
        inputs.insert("claims".to_string(), claims_flat);

        // Parse claimLengths array
        let claim_lengths: Vec<BigInt> = json_value["claimLengths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                if let Some(s) = v.as_str() {
                    BigInt::from_str(s).unwrap()
                } else if let Some(n) = v.as_u64() {
                    BigInt::from(n)
                } else {
                    panic!("claimLengths value must be string or number")
                }
            })
            .collect();
        inputs.insert("claimLengths".to_string(), claim_lengths);

        // Parse decodeFlags array
        let decode_flags: Vec<BigInt> = json_value["decodeFlags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| BigInt::from(v.as_u64().unwrap()))
            .collect();
        inputs.insert("decodeFlags".to_string(), decode_flags);

        // Generate witness using native Rust (rust-witness)
        let t0 = Instant::now();
        info!("Generating witness using native Rust (rust-witness)...");
        let witness_bigint = jwt_witness(inputs);
        info!("rust-witness time: {} ms", t0.elapsed().as_millis());

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
