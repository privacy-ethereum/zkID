use crate::{utils::*, Scalar, E};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;
use std::{any::type_name, env::current_dir, fs::File, path::PathBuf};
use tracing::info;

rust_witness::witness!(show);

// show.circom
#[derive(Debug, Clone, Default)]
pub struct ShowCircuit {
    input_path: Option<PathBuf>,
}

impl ShowCircuit {
    pub fn new<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            input_path: path.into(),
        }
    }

    fn input_path_absolute(&self, cwd: &PathBuf) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    cwd.join(p)
                }
            })
            .unwrap_or_else(|| cwd.join("../circom/inputs/show/default.json"))
    }

    fn load_inputs(&self, cwd: &PathBuf) -> Result<Value, SynthesisError> {
        let path = self.input_path_absolute(cwd);
        info!("Loading show inputs from {}", path.display());
        let file = File::open(&path).map_err(|_| SynthesisError::AssignmentMissing)?;
        serde_json::from_reader(file).map_err(|_| SynthesisError::AssignmentMissing)
    }
}

impl SpartanCircuit<E> for ShowCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cwd = current_dir().unwrap();
        let root = cwd.join("../circom");
        let witness_dir = root.join("build/show/show_js");
        let r1cs = witness_dir.join("show.r1cs");
        let json_value = self.load_inputs(&cwd)?;

        // Parse inputs using declarative field definitions
        let inputs = parse_show_inputs(&json_value)?;

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
        let cwd = current_dir().unwrap();
        let json_value = self.load_inputs(&cwd)?;

        let inputs = parse_show_inputs(&json_value)?;
        let keybinding_x_bigint = inputs.get("deviceKeyX").unwrap()[0].clone();
        let keybinding_y_bigint = inputs.get("deviceKeyY").unwrap()[0].clone();
        let claim_bigints = inputs
            .get("claim")
            .cloned()
            .ok_or(SynthesisError::AssignmentMissing)?;

        let keybinding_x = bigint_to_scalar(keybinding_x_bigint)?;
        let keybinding_y = bigint_to_scalar(keybinding_y_bigint)?;
        let claim_scalars = convert_bigint_to_scalar(claim_bigints)?;

        let kb_x = AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(keybinding_x))?;
        let kb_y = AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(keybinding_y))?;

        let mut shared_values = Vec::with_capacity(2 + claim_scalars.len());
        shared_values.push(kb_x);
        shared_values.push(kb_y);

        for (idx, claim_scalar) in claim_scalars.into_iter().enumerate() {
            let claim_value = claim_scalar;
            let claim_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("Claim{idx}")), move || {
                    Ok(claim_value)
                })?;
            shared_values.push(claim_alloc);
        }

        Ok(shared_values)
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
