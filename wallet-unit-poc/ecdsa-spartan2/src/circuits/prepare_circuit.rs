use std::{any::type_name, env::current_dir, sync::OnceLock};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use spartan2::traits::circuit::SpartanCircuit;

use crate::{prover::generate_prepare_witness, Scalar, E};

rust_witness::witness!(jwt);

thread_local! {
    static KEYBINDING_X: OnceLock<Scalar> = OnceLock::new();
    static KEYBINDING_Y: OnceLock<Scalar> = OnceLock::new();
    static AGE_CLAIM: OnceLock<Vec<Scalar>> = OnceLock::new();
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
        let (witness, age_claim, keybinding_x, keybinding_y) = generate_prepare_witness(None)?;

        let age_claim_scalars: Vec<Scalar> = age_claim
            .iter()
            .map(|byte| Scalar::from(*byte as u64))
            .collect();

        AGE_CLAIM.with(|cell| {
            cell.set(age_claim_scalars)
                .map_err(|_| SynthesisError::AssignmentMissing)
        })?;

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
            // FIXME this should error out
            _ => (Scalar::one(), Scalar::one() + Scalar::one()),
        };

        let age_claim = AGE_CLAIM
            .with(|cell| cell.get().cloned())
            .unwrap_or_default();

        let kb_x = AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(keybinding_x))?;
        let kb_y = AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(keybinding_y))?;

        let mut shared_values = Vec::with_capacity(2 + age_claim.len());
        shared_values.push(kb_x);
        shared_values.push(kb_y);

        for (idx, byte_scalar) in age_claim.iter().enumerate() {
            let byte_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("AgeClaimByte{idx}")), || {
                    Ok(*byte_scalar)
                })?;
            shared_values.push(byte_alloc);
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
