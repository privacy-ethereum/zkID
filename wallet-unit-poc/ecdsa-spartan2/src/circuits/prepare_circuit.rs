use super::synthesize_witness_only;
use crate::{
    paths::PathConfig, prover::generate_prepare_witness, utils::calculate_jwt_output_indices,
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};

// Native witness generation via witnesscalc_adapter (disabled for WASM builds)
#[cfg(all(feature = "native-witness", has_circuit_base))]
witnesscalc_adapter::witness!(jwt);

#[cfg(all(feature = "native-witness", has_circuit_1k))]
witnesscalc_adapter::witness!(jwt_1k);

#[cfg(all(feature = "native-witness", has_circuit_2k))]
witnesscalc_adapter::witness!(jwt_2k);

#[cfg(all(feature = "native-witness", has_circuit_4k))]
witnesscalc_adapter::witness!(jwt_4k);

#[cfg(all(feature = "native-witness", has_circuit_8k))]
witnesscalc_adapter::witness!(jwt_8k);

#[cfg(feature = "native-witness")]
pub(crate) fn call_jwt_witness(
    circuit_name: &str,
    inputs_json: &str,
) -> Result<Vec<u8>, SynthesisError> {
    let result = match circuit_name {
        #[cfg(has_circuit_base)]
        "jwt" => jwt_witness(inputs_json),

        #[cfg(has_circuit_1k)]
        "jwt_1k" => jwt_1k_witness(inputs_json),

        #[cfg(has_circuit_2k)]
        "jwt_2k" => jwt_2k_witness(inputs_json),

        #[cfg(has_circuit_4k)]
        "jwt_4k" => jwt_4k_witness(inputs_json),

        #[cfg(has_circuit_8k)]
        "jwt_8k" => jwt_8k_witness(inputs_json),

        name => {
            eprintln!(
                "Circuit '{}' is not compiled into this binary.\n\
                 Run `yarn compile:jwt:{} && cargo build --release` first.",
                name,
                name.strip_prefix("jwt_").unwrap_or(name)
            );
            return Err(SynthesisError::Unsatisfiable);
        }
    };

    result.map_err(|_| SynthesisError::Unsatisfiable)
}

// Stub for WASM builds - witness generation happens in JavaScript
#[cfg(not(feature = "native-witness"))]
pub(crate) fn call_jwt_witness(
    _circuit_name: &str,
    _inputs_json: &str,
) -> Result<Vec<u8>, SynthesisError> {
    Err(SynthesisError::Unsatisfiable)
}

/// PrepareCircuit wraps the JWT verification circuit.
#[derive(Debug, Clone)]
pub struct PrepareCircuit {
    /// Path configuration for resolving file paths
    path_config: PathConfig,
    /// Optional override for input JSON path
    input_path: Option<PathBuf>,
    /// Cached witness for reuse across synthesize and shared calls
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for PrepareCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl PrepareCircuit {
    /// Create a new PrepareCircuit with PathConfig and optional input path override.
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Create from just an input path (for backwards compatibility).
    /// Uses development PathConfig.
    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            path_config: PathConfig::development(),
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Create with pre-computed witness (for WASM usage where witness is generated externally).
    /// This bypasses filesystem I/O entirely.
    pub fn with_witness(witness: Vec<Scalar>) -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(Some(witness))),
        }
    }

    /// Resolve the input JSON path using PathConfig.
    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.input_json("jwt"))
    }

    /// Get the R1CS file path.
    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path("jwt")
    }

    /// Get cached witness or generate and cache it.
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let witness = generate_prepare_witness(
            &self.path_config,
            self.input_path.as_ref().map(|p| p.as_path()),
        )?;

        *cache = Some(witness.clone());

        Ok(witness)
    }
}

impl SpartanCircuit<E> for PrepareCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs =
                load_r1cs(&self.r1cs_path()).map_err(|_| SynthesisError::AssignmentMissing)?;
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;

        match load_r1cs::<Scalar>(&self.r1cs_path()) {
            Ok(r1cs) => {
                synthesize(cs, r1cs, Some(witness))?;
            }
            Err(_) => {
                // Prepare circuit public signals (in witness order):
                //   normalizedClaimValues[0..n_claims], KeyBindingX, KeyBindingY, pubKeyX, pubKeyY
                let layout = calculate_jwt_output_indices(
                    self.path_config.circuit_size.max_matches(),
                    self.path_config.circuit_size.max_claims_length(),
                );
                synthesize_witness_only(cs, &witness, layout.num_public())?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let layout = calculate_jwt_output_indices(
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_claims_length(),
        );
        let num_public = layout.num_public();

        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(num_public);
        for idx in 1..=num_public {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let layout = calculate_jwt_output_indices(
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_claims_length(),
        );

        // Check cached witness first (covers with_witness() path), then try
        // generating from input_path (native path). Returns None during setup.
        let witness = {
            let cache = self.cached_witness.lock().unwrap();
            cache.clone()
        }
        .or_else(|| {
            self.input_path
                .as_ref()
                .and_then(|_| self.get_or_generate_witness().ok())
        });

        let keybinding_x = witness
            .as_ref()
            .map(|w| w[layout.keybinding_x_index])
            .unwrap_or(Scalar::ZERO);
        let keybinding_y = witness
            .as_ref()
            .map(|w| w[layout.keybinding_y_index])
            .unwrap_or(Scalar::ZERO);

        let keybinding_x_alloc =
            AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(keybinding_x))?;
        let keybinding_y_alloc =
            AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(keybinding_y))?;

        // Shared layout (must match `ShowCircuit::shared`):
        //   [KeyBindingX, KeyBindingY, normalizedClaimValues[0..n_claims]]
        let mut shared_values = Vec::with_capacity(2 + layout.claim_values_len);
        shared_values.push(keybinding_x_alloc);
        shared_values.push(keybinding_y_alloc);

        for idx in 0..layout.claim_values_len {
            let claim_scalar = witness
                .as_ref()
                .map(|w| w[layout.claim_values_start + idx])
                .unwrap_or(Scalar::ZERO);
            let claim_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("ClaimValue{idx}")), move || {
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
