use std::{env::current_dir, fs::File, sync::OnceLock};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;

use crate::{utils::*, Scalar, E};

rust_witness::witness!(show);

thread_local! {
    static KEYBINDING_X: OnceLock<Scalar> = OnceLock::new();
    static KEYBINDING_Y: OnceLock<Scalar> = OnceLock::new();
}

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

        // Parse inputs using declarative field definitions
        let inputs = parse_show_inputs(&json_value)?;

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
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let json_file = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/show/default.json");
            File::open(path).expect("Failed to open show_input.json")
        };

        let json_value: Value =
            serde_json::from_reader(json_file).expect("Failed to parse show_input.json");

        let inputs = parse_show_inputs(&json_value)?;
        let keybinding_x_bigint = inputs.get("deviceKeyX").unwrap()[0].clone();
        let keybinding_y_bigint = inputs.get("deviceKeyY").unwrap()[0].clone();

        // Convert BigInt to Scalar
        let keybinding_x = bigint_to_scalar(keybinding_x_bigint)?;
        let keybinding_y = bigint_to_scalar(keybinding_y_bigint)?;

        let kb_x = AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(keybinding_x))?;
        let kb_y = AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(keybinding_y))?;

        Ok(vec![kb_x, kb_y])
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
