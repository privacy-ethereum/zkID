use super::synthesize_witness_only;
use crate::{paths::PathConfig, utils::*, Scalar, E};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
#[cfg(feature = "native-witness")]
use std::time::Instant;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tracing::info;

#[cfg(feature = "native-witness")]
witnesscalc_adapter::witness!(show);

// show.circom
#[derive(Debug, Clone)]
pub struct ShowCircuit {
    /// Path configuration for resolving file paths
    path_config: PathConfig,
    /// Optional override for input JSON path
    input_path: Option<PathBuf>,
    /// Cached witness for reuse across synthesize and shared calls
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for ShowCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl ShowCircuit {
    /// Create a new ShowCircuit with PathConfig and optional input path override.
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
            .unwrap_or_else(|| self.path_config.input_json("show"))
    }

    /// Get the R1CS file path.
    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path("show")
    }

    /// Get cached witness or generate and cache it.
    #[cfg(feature = "native-witness")]
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let path = self.resolve_input_json();
        info!("Loading show inputs from {}", path.display());

        let file = std::fs::File::open(&path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let json_value: serde_json::Value =
            serde_json::from_reader(file).map_err(|_| SynthesisError::AssignmentMissing)?;

        let inputs = parse_show_inputs(&json_value)?;

        info!("Generating witness using witnesscalc...");
        let t0 = Instant::now();

        // Show circuit has no 2D array fields, so the dimension args are unused;
        // pass through the configured sizes for symmetry with the JWT path.
        let inputs_json = hashmap_to_json_string(
            &inputs,
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_substring_length(),
            self.path_config.circuit_size.max_claims_length(),
        )?;
        let witness_bytes =
            show_witness(&inputs_json).map_err(|_| SynthesisError::Unsatisfiable)?;

        info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

        let witness = parse_witness(&witness_bytes)?;

        // Cache it
        *cache = Some(witness.clone());

        Ok(witness)
    }

    /// Get cached witness (for WASM builds where witness is pre-computed via with_witness()).
    #[cfg(not(feature = "native-witness"))]
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        // In WASM builds, witness must be provided via with_witness() constructor
        Err(SynthesisError::AssignmentMissing)
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
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs =
                load_r1cs(&self.r1cs_path()).map_err(|_| SynthesisError::AssignmentMissing)?;
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;

        // Try R1CS-based synthesis (native path). If R1CS is unavailable, fall back
        // to witness-only variable allocation (WASM path). The proving key already
        // contains the constraint matrices (A, B, C); Spartan2 only reads witness
        // values from the CS during proving, so constraints are not needed here.
        match load_r1cs::<Scalar>(&self.r1cs_path()) {
            Ok(r1cs) => {
                synthesize(cs, r1cs, Some(witness))?;
            }
            Err(_) => {
                let num_public = 1;
                synthesize_witness_only(cs, &witness, num_public)?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let witness = self.get_or_generate_witness().ok();

        let expression_result = witness
            .as_ref()
            .map(|w| w[1])
            .unwrap_or(Scalar::ZERO);
        Ok(vec![expression_result])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let layout =
            calculate_show_witness_indices(self.path_config.circuit_size.n_claims());

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

        let device_key_x = witness
            .as_ref()
            .map(|w| w[layout.device_key_x_index])
            .unwrap_or(Scalar::ZERO);
        let device_key_y = witness
            .as_ref()
            .map(|w| w[layout.device_key_y_index])
            .unwrap_or(Scalar::ZERO);

        let kb_x = AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(device_key_x))?;
        let kb_y = AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(device_key_y))?;

        // Shared layout (must match `PrepareCircuit::shared`):
        //   [KeyBindingX, KeyBindingY, claimValues[0..n_claims]]
        let mut shared_values = Vec::with_capacity(2 + layout.claim_values_len);
        shared_values.push(kb_x);
        shared_values.push(kb_y);

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
