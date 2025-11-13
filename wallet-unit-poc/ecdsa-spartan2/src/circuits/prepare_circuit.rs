use crate::{
    prover::generate_prepare_witness,
    utils::{compute_prepare_shared_scalars, PrepareSharedScalars},
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use serde_json::Value;
use spartan2::traits::circuit::SpartanCircuit;
use std::{any::type_name, cell::RefCell, env::current_dir, fs::File, path::PathBuf};

rust_witness::witness!(jwt);

thread_local! {
    static PREPARE_INPUT_PATH: RefCell<Option<PathBuf>> = RefCell::new(None);
}

pub fn set_prepare_input_path<P: Into<Option<PathBuf>>>(path: P) {
    PREPARE_INPUT_PATH.with(|cell| {
        *cell.borrow_mut() = path.into();
    });
}

fn prepare_input_path() -> Option<PathBuf> {
    PREPARE_INPUT_PATH.with(|cell| cell.borrow().clone())
}

// jwt.circom
#[derive(Debug, Clone)]
pub struct PrepareCircuit;

impl SpartanCircuit<E> for PrepareCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cwd = current_dir().unwrap();
        let root = cwd.join("../circom");
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

        // Generate witness using the dedicated function
        let input_path =
            prepare_input_path().map(|p| if p.is_absolute() { p } else { cwd.join(p) });

        let witness = generate_prepare_witness(input_path.as_ref().map(|p| p.as_path()))?;

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
        // Generate witness using the dedicated function
        let input_path =
            prepare_input_path().map(|p| if p.is_absolute() { p } else { cwd.join(p) });
        let root = current_dir().unwrap().join("../circom");

        let json_path = input_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| root.join("inputs/jwt/default.json"));

        let json_file = File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;

        let json_value: Value =
            serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

        let PrepareSharedScalars {
            keybinding_x,
            keybinding_y,
            claim_scalars,
        } = compute_prepare_shared_scalars(&json_value)?;

        let keybinding_x_alloc =
            AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(keybinding_x))?;
        let keybinding_y_alloc =
            AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(keybinding_y))?;

        let mut shared_values = Vec::with_capacity(2 + claim_scalars.len());
        shared_values.push(keybinding_x_alloc);
        shared_values.push(keybinding_y_alloc);

        for (idx, claim_scalar) in claim_scalars.into_iter().enumerate() {
            let claim_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("Claim{idx}")), move || {
                    Ok(claim_scalar)
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
