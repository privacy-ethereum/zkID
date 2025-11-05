use std::{any::type_name, env::current_dir, sync::OnceLock};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use spartan2::traits::circuit::SpartanCircuit;

use crate::{prover::generate_prepare_witness, Scalar, E};

rust_witness::witness!(jwt);

thread_local! {
    static KEYBINDING_X: OnceLock<Scalar> = OnceLock::new();
    static KEYBINDING_Y: OnceLock<Scalar> = OnceLock::new();
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

        // Generate witness using the dedicated function
        let (witness, keybinding_x, keybinding_y) = generate_prepare_witness(None)?;

        KEYBINDING_X.with(|cell| {
            cell.set(keybinding_x)
                .map_err(|_| SynthesisError::AssignmentMissing)
        })?;
        KEYBINDING_Y.with(|cell| {
            cell.set(keybinding_y)
                .map_err(|_| SynthesisError::AssignmentMissing)
        })?;

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
        let (keybinding_x, keybinding_y) = match (
            KEYBINDING_X.with(|cell| cell.get().copied()),
            KEYBINDING_Y.with(|cell| cell.get().copied()),
        ) {
            (Some(x), Some(y)) => (x, y),
            _ => (Scalar::zero(), Scalar::zero()),
        };

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
