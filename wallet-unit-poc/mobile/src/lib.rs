use ecdsa_spartan2::{
    load_instance, load_proof, load_shared_blinds, load_witness,
    paths::keys::{
        PREPARE_INSTANCE, PREPARE_PROOF, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY,
        PREPARE_WITNESS, SHARED_BLINDS, SHOW_INSTANCE, SHOW_PROOF, SHOW_PROVING_KEY,
        SHOW_VERIFYING_KEY, SHOW_WITNESS,
    },
    prover::{
        generate_shared_blinds as gen_shared_blinds, prove_circuit, prove_circuit_with_pk, reblind,
        reblind_with_loaded_data, verify_circuit, verify_circuit_with_loaded_data,
    },
    save_keys,
    setup::{setup_circuit_keys, setup_circuit_keys_no_save},
    CircuitSize, PathConfig, PrepareCircuit, ShowCircuit, E,
};
use std::path::PathBuf;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
mopro_ffi::app!();

const PREPARE_CIRCUIT_NAME: &str = "prepare";
const SHOW_CIRCUIT_NAME: &str = "show";

// ============================================================================
// Core Types
// ============================================================================

/// Result of a proving operation with timing and proof metadata
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProofResult {
    pub prep_ms: u64,
    pub prove_ms: u64,
    pub total_ms: u64,
    pub proof_size_bytes: u64,
    pub comm_w_shared: String,
}

/// Result of a complete benchmark run with timing and size metrics
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BenchmarkResults {
    // Timing metrics (milliseconds)
    pub prepare_setup_ms: u64,
    pub show_setup_ms: u64,
    pub generate_blinds_ms: u64,
    pub prove_prepare_ms: u64,
    pub reblind_prepare_ms: u64,
    pub prove_show_ms: u64,
    pub reblind_show_ms: u64,
    pub verify_prepare_ms: u64,
    pub verify_show_ms: u64,
    // Size metrics (bytes)
    pub prepare_proving_key_bytes: u64,
    pub prepare_verifying_key_bytes: u64,
    pub show_proving_key_bytes: u64,
    pub show_verifying_key_bytes: u64,
    pub prepare_proof_bytes: u64,
    pub show_proof_bytes: u64,
    pub prepare_witness_bytes: u64,
    pub show_witness_bytes: u64,
}

impl BenchmarkResults {
    /// Format bytes into human-readable size string
    pub fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Errors that can occur during ZK proof operations
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ZkProofError {
    FileNotFound { message: String },
    ProofGenerationFailed { message: String },
    VerificationFailed { message: String },
    InvalidInput { message: String },
    SetupRequired { message: String },
    IoError { message: String },
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofError::FileNotFound { message } => write!(f, "File not found: {}", message),
            ZkProofError::ProofGenerationFailed { message } => {
                write!(f, "Proof generation failed: {}", message)
            }
            ZkProofError::VerificationFailed { message } => {
                write!(f, "Verification failed: {}", message)
            }
            ZkProofError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
            ZkProofError::SetupRequired { message } => write!(f, "Setup required: {}", message),
            ZkProofError::IoError { message } => write!(f, "IO error: {}", message),
        }
    }
}

impl std::error::Error for ZkProofError {}

impl From<std::io::Error> for ZkProofError {
    fn from(e: std::io::Error) -> Self {
        ZkProofError::IoError {
            message: e.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a PathConfig for the given documents path (mobile environment).
fn make_config(documents_path: &str) -> PathConfig {
    PathConfig {
        base_dir: documents_path.into(),
        is_mobile: true,
        circuit_size: CircuitSize::Kb2,
    }
}

// ============================================================================
// Setup Operations
// ============================================================================

/// Setup Prepare (JWT) circuit keys
/// Generates proving and verifying keys for the Prepare circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_prepare_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = PrepareCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(PREPARE_PROVING_KEY),
        config.key_path(PREPARE_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "Prepare circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

/// Setup Show circuit keys
/// Generates proving and verifying keys for the Show circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_show_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = ShowCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(SHOW_PROVING_KEY),
        config.key_path(SHOW_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "Show circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

// ============================================================================
// Shared Blinds Generation
// ============================================================================

/// Generate shared blinding factors for both circuits
/// Creates random blinding factors that enable proof reblinding
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_shared_blinds(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);

    // Note: While circuits have 98 shared values (2 keybindings + 96 claim scalars),
    // Hyrax batches all these into a single commitment point.
    // num_shared_rows() returns the number of Hyrax commitment points, not individual scalars.
    const NUM_SHARED: usize = 1;
    gen_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS), NUM_SHARED);

    Ok("Shared blinds generated successfully".to_string())
}

// ============================================================================
// Prove Operations
// ============================================================================

/// Generate Prepare (JWT) circuit proof
/// Runs prep_prove + prove phases using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_prepare(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let input_dir =
        PathBuf::from(documents_path).join(format!("{}_input.json", PREPARE_CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("{} input file not found", PREPARE_CIRCUIT_NAME),
        });
    }
    println!("input_dir: {}", input_dir.display());
    println!(
        "config: {}",
        config.artifact_path(PREPARE_INSTANCE).display()
    );
    println!(
        "key_path: {}",
        config.key_path(PREPARE_PROVING_KEY).display()
    );
    println!(
        "witness_path: {}",
        config.artifact_path(PREPARE_WITNESS).display()
    );
    println!(
        "proof_path: {}",
        config.artifact_path(PREPARE_PROOF).display()
    );

    let circuit = PrepareCircuit::new(config.clone(), Some(input_dir));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(PREPARE_PROVING_KEY),
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let total_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(PREPARE_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0, // prover doesn't separate timing
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

/// Generate Show circuit proof
/// Runs prep_prove + prove phases using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let input_dir = PathBuf::from(documents_path).join(format!("{}_input.json", SHOW_CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("{} input file not found", SHOW_CIRCUIT_NAME),
        });
    }

    println!("input_dir: {}", input_dir.display());
    println!(
        "config: {}",
        config.artifact_path(SHOW_INSTANCE).display()
    );
    println!(
        "key_path: {}",
        config.key_path(SHOW_PROVING_KEY).display()
    );
    println!(
        "witness_path: {}",
        config.artifact_path(SHOW_WITNESS).display()
    );
    println!(
        "proof_path: {}",
        config.artifact_path(SHOW_PROOF).display()
    );

    let circuit = ShowCircuit::new(config.clone(), Some(input_dir));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(SHOW_PROVING_KEY),
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let total_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(SHOW_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

// ============================================================================
// Reblind Operations
// ============================================================================

/// Reblind Prepare circuit proof
/// Generates a new unlinkable proof while preserving comm_W_shared
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reblind_prepare(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let start = std::time::Instant::now();
    reblind(
        config.key_path(PREPARE_PROVING_KEY),
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
        config.artifact_path(SHARED_BLINDS),
    );
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(PREPARE_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: elapsed_ms,
        total_ms: elapsed_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

/// Reblind Show circuit proof
/// Generates a new unlinkable proof while preserving comm_W_shared
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reblind_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let start = std::time::Instant::now();
    reblind(
        config.key_path(SHOW_PROVING_KEY),
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
        config.artifact_path(SHARED_BLINDS),
    );
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(SHOW_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: elapsed_ms,
        total_ms: elapsed_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

// ============================================================================
// Verify Operations
// ============================================================================

/// Verify Prepare circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_prepare(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    verify_circuit(
        config.artifact_path(PREPARE_PROOF),
        config.key_path(PREPARE_VERIFYING_KEY),
    );
    Ok(true)
}

/// Verify Show circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_show(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    verify_circuit(
        config.artifact_path(SHOW_PROOF),
        config.key_path(SHOW_VERIFYING_KEY),
    );
    Ok(true)
}

// ============================================================================
// Benchmark Operations
// ============================================================================

/// Run complete benchmark pipeline for both Prepare and Show circuits
/// Executes all 9 steps: setup, prove, reblind, and verify for both circuits
/// Returns comprehensive timing and size metrics
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark(
    documents_path: String,
) -> Result<BenchmarkResults, ZkProofError> {
    let config = make_config(&documents_path);
    let prepare_input =
        PathBuf::from(&documents_path).join(format!("{}_input.json", PREPARE_CIRCUIT_NAME));
    let show_input =
        PathBuf::from(&documents_path).join(format!("{}_input.json", SHOW_CIRCUIT_NAME));

    // Note: While circuits have 98 shared values (2 keybindings + 96 claim scalars),
    // Hyrax batches all these into a single commitment point.
    // num_shared_rows() returns the number of Hyrax commitment points, not individual scalars.
    const NUM_SHARED: usize = 1;

    // Step 1: Setup Prepare Circuit
    let prepare_circuit = PrepareCircuit::new(config.clone(), Some(prepare_input.clone()));
    let start = std::time::Instant::now();
    let (prepare_pk, prepare_vk) = setup_circuit_keys_no_save(prepare_circuit);
    let prepare_setup_ms = start.elapsed().as_millis() as u64;

    // Save Prepare keys after timing
    save_keys(
        config.key_path(PREPARE_PROVING_KEY),
        config.key_path(PREPARE_VERIFYING_KEY),
        &prepare_pk,
        &prepare_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save Prepare keys: {}", e),
    })?;

    // Step 2: Setup Show Circuit
    let show_circuit = ShowCircuit::new(config.clone(), Some(show_input.clone()));
    let start = std::time::Instant::now();
    let (show_pk, show_vk) = setup_circuit_keys_no_save(show_circuit);
    let show_setup_ms = start.elapsed().as_millis() as u64;

    // Save Show keys after timing
    save_keys(
        config.key_path(SHOW_PROVING_KEY),
        config.key_path(SHOW_VERIFYING_KEY),
        &show_pk,
        &show_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save Show keys: {}", e),
    })?;

    // Step 3: Generate Shared Blinds
    let start = std::time::Instant::now();
    gen_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS), NUM_SHARED);
    let generate_blinds_ms = start.elapsed().as_millis() as u64;

    // Step 4: Prove Prepare Circuit
    let start = std::time::Instant::now();
    let prepare_circuit = PrepareCircuit::new(config.clone(), Some(prepare_input));
    prove_circuit_with_pk(
        prepare_circuit,
        &prepare_pk,
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let prove_prepare_ms = start.elapsed().as_millis() as u64;

    // Step 5: Reblind Prepare
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let prepare_instance = load_instance(config.artifact_path(PREPARE_INSTANCE)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load prepare instance: {}", e),
        }
    })?;
    let prepare_witness = load_witness(config.artifact_path(PREPARE_WITNESS)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load prepare witness: {}", e),
        }
    })?;
    let shared_blinds =
        load_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS)).map_err(|e| {
            ZkProofError::FileNotFound {
                message: format!("Failed to load shared blinds: {}", e),
            }
        })?;

    let start = std::time::Instant::now();
    reblind_with_loaded_data(
        &prepare_pk,
        prepare_instance,
        prepare_witness,
        &shared_blinds,
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let reblind_prepare_ms = start.elapsed().as_millis() as u64;

    // Step 6: Prove Show Circuit
    let start = std::time::Instant::now();
    let show_circuit = ShowCircuit::new(config.clone(), Some(show_input));
    prove_circuit_with_pk(
        show_circuit,
        &show_pk,
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let prove_show_ms = start.elapsed().as_millis() as u64;

    // Step 7: Reblind Show
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let show_instance = load_instance(config.artifact_path(SHOW_INSTANCE)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load show instance: {}", e),
        }
    })?;
    let show_witness = load_witness(config.artifact_path(SHOW_WITNESS)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load show witness: {}", e),
        }
    })?;
    // Reuse shared_blinds from Prepare step (already loaded)

    let start = std::time::Instant::now();
    reblind_with_loaded_data(
        &show_pk,
        show_instance,
        show_witness,
        &shared_blinds,
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let reblind_show_ms = start.elapsed().as_millis() as u64;

    // Step 8: Verify Prepare
    // Load proof before timing (file I/O should not be part of verify benchmark)
    let prepare_proof = load_proof(config.artifact_path(PREPARE_PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load prepare proof: {}", e),
        }
    })?;

    let start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&prepare_proof, &prepare_vk);
    let verify_prepare_ms = start.elapsed().as_millis() as u64;

    // Step 9: Verify Show
    // Load proof before timing (file I/O should not be part of verify benchmark)
    let show_proof =
        load_proof(config.artifact_path(SHOW_PROOF)).map_err(|e| ZkProofError::FileNotFound {
            message: format!("Failed to load show proof: {}", e),
        })?;

    let start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&show_proof, &show_vk);
    let verify_show_ms = start.elapsed().as_millis() as u64;

    // Measure file sizes
    let prepare_proving_key_bytes = get_proof_size(&config.key_path(PREPARE_PROVING_KEY))?;
    let prepare_verifying_key_bytes = get_proof_size(&config.key_path(PREPARE_VERIFYING_KEY))?;
    let show_proving_key_bytes = get_proof_size(&config.key_path(SHOW_PROVING_KEY))?;
    let show_verifying_key_bytes = get_proof_size(&config.key_path(SHOW_VERIFYING_KEY))?;
    let prepare_proof_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let show_proof_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let prepare_witness_bytes = get_proof_size(&config.artifact_path(PREPARE_WITNESS))?;
    let show_witness_bytes = get_proof_size(&config.artifact_path(SHOW_WITNESS))?;

    Ok(BenchmarkResults {
        prepare_setup_ms,
        show_setup_ms,
        generate_blinds_ms,
        prove_prepare_ms,
        reblind_prepare_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_prepare_ms,
        verify_show_ms,
        prepare_proving_key_bytes,
        prepare_verifying_key_bytes,
        show_proving_key_bytes,
        show_verifying_key_bytes,
        prepare_proof_bytes,
        show_proof_bytes,
        prepare_witness_bytes,
        show_witness_bytes,
    })
}

// ============================================================================
// Inspection Operations
// ============================================================================

/// Get the shared witness commitment for a circuit
/// Returns hex-encoded commitment that links Prepare and Show proofs
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_comm_w_shared(
    documents_path: String,
    circuit_type: String,
) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let instance_path = match circuit_type.as_str() {
        "prepare" => config.artifact_path(PREPARE_INSTANCE),
        "show" => config.artifact_path(SHOW_INSTANCE),
        _ => {
            return Err(ZkProofError::InvalidInput {
                message: format!(
                    "Invalid circuit_type '{}'. Must be 'prepare' or 'show'",
                    circuit_type
                ),
            })
        }
    };

    extract_comm_w_shared(&instance_path)
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Extract comm_W_shared from a saved instance file
fn extract_comm_w_shared(
    instance_path: impl AsRef<std::path::Path>,
) -> Result<String, ZkProofError> {
    let instance_path = instance_path.as_ref();
    let instance = load_instance(instance_path).map_err(|e| ZkProofError::FileNotFound {
        message: format!(
            "Failed to load instance from '{}': {}",
            instance_path.display(),
            e
        ),
    })?;

    // Convert comm_W_shared to hex string
    let comm_w_shared_hex = format!("{:?}", instance.comm_W_shared);
    Ok(comm_w_shared_hex)
}

/// Get the size of a proof file in bytes
fn get_proof_size(proof_path: impl AsRef<std::path::Path>) -> Result<u64, ZkProofError> {
    let proof_path = proof_path.as_ref();
    let metadata = std::fs::metadata(proof_path).map_err(|e| ZkProofError::FileNotFound {
        message: format!(
            "Failed to get proof size from '{}': {}",
            proof_path.display(),
            e
        ),
    })?;

    Ok(metadata.len())
}

// ============================================================================
// Legacy Test Function
// ============================================================================

/// Test function for basic UniFFI integration
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(mopro_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_path_config_mobile() {
        let config = make_config("/app/Documents");
        assert_eq!(
            config.key_path(PREPARE_PROVING_KEY),
            PathBuf::from("/app/Documents/keys/prepare_proving.key")
        );
        assert_eq!(
            config.artifact_path(PREPARE_PROOF),
            PathBuf::from("/app/Documents/keys/prepare_proof.bin")
        );
    }

    #[test]
    fn test_make_config_uses_2k() {
        let config = make_config("/docs");
        assert_eq!(config.circuit_size, CircuitSize::Kb2);
        assert!(config.is_mobile);
    }

    #[test]
    fn test_invalid_circuit_type() {
        let result = get_comm_w_shared(".".to_string(), "invalid".to_string());
        assert!(matches!(result, Err(ZkProofError::InvalidInput { .. })));
    }
}

// ============================================================================
// E2E Tests
// ============================================================================

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use std::fs;

    // Absolute path to this crate, set at compile time.
    const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn circom_root() -> PathBuf {
        PathBuf::from(CRATE_DIR)
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .join("circom")
    }

    /// Builds a temp directory tree that matches the mobile app's document structure:
    ///
    ///   {temp}/circom/                          ← documents_path passed to Rust FFI
    ///     build/jwt/jwt_js/jwt.r1cs             ← jwt_2k r1cs, using mobile-style name
    ///     build/show/show_js/show.r1cs
    ///     prepare_input.json                    ← 2k JWT inputs (for prove_prepare + run_complete_benchmark)
    ///     show_input.json                       ← show inputs (for prove_show + run_complete_benchmark)
    ///
    /// Returns the documents_path string.
    fn setup_mobile_docs(path: &PathBuf) -> String {
        let docs = path.join("circom");
        let circom = circom_root();

        let jwt_dir = docs.join("build/jwt/jwt_js");
        let show_dir = docs.join("build/show/show_js");
        fs::create_dir_all(&jwt_dir).expect("create jwt dir");
        fs::create_dir_all(&show_dir).expect("create show dir");

        fs::copy(
            circom.join("build/jwt_2k/jwt_2k_js/jwt_2k.r1cs"),
            jwt_dir.join("jwt.r1cs"),
        )
        .expect("copy jwt_2k.r1cs -> jwt.r1cs");
        fs::copy(
            circom.join("build/show/show_js/show.r1cs"),
            show_dir.join("show.r1cs"),
        )
        .expect("copy show.r1cs");

        let jwt_2k_input = circom.join("inputs/jwt/2k/default.json");
        let show_input = circom.join("inputs/show/2k/default.json");

        fs::copy(&jwt_2k_input, docs.join("prepare_input.json"))
            .expect("copy jwt 2k input -> prepare_input.json");
        fs::copy(&show_input, docs.join("show_input.json"))
            .expect("copy show 2k input -> show_input.json");

        docs.to_string_lossy().into_owned()
    }

    /// Full 9-step ZK workflow matching the Flutter app's E2E sequence:
    ///   setup_prepare → setup_show → generate_blinds →
    ///   prove_prepare → reblind_prepare → prove_show → reblind_show →
    ///   verify_prepare → verify_show → comm_W_shared linkage check
    #[test]
    #[ignore = "Long-running e2e (~5 min); run with: cargo test -- --ignored e2e_full_workflow"]
    fn e2e_full_workflow() {
        let temp = tempfile::tempdir().expect("create temp dir");

        let docs = setup_mobile_docs(&temp);

        // Step 1: Setup Prepare keys
        let r = setup_prepare_keys(docs.clone());
        assert!(r.is_ok(), "setup_prepare_keys failed: {:?}", r.err());

        // Step 2: Setup Show keys
        let r = setup_show_keys(docs.clone());
        assert!(r.is_ok(), "setup_show_keys failed: {:?}", r.err());

        // Step 3: Generate shared blinds
        let r = generate_shared_blinds(docs.clone());
        assert!(r.is_ok(), "generate_shared_blinds failed: {:?}", r.err());

        // Step 4: Prove Prepare
        let r = prove_prepare(docs.clone());
        assert!(r.is_ok(), "prove_prepare failed: {:?}", r.err());
        let pr = r.unwrap();
        assert!(pr.proof_size_bytes > 0, "proof_size_bytes must be > 0");
        assert!(
            !pr.comm_w_shared.is_empty(),
            "comm_w_shared must be non-empty"
        );

        // Step 5: Reblind Prepare — new unlinkable proof, same commitment
        let r = reblind_prepare(docs.clone());
        assert!(r.is_ok(), "reblind_prepare failed: {:?}", r.err());

        // Step 6: Prove Show
        let r = prove_show(docs.clone());
        assert!(r.is_ok(), "prove_show failed: {:?}", r.err());
        let sr = r.unwrap();
        assert!(sr.proof_size_bytes > 0, "show proof_size_bytes must be > 0");
        assert!(
            !sr.comm_w_shared.is_empty(),
            "show comm_w_shared must be non-empty"
        );

        // Step 7: Reblind Show
        let r = reblind_show(docs.clone());
        assert!(r.is_ok(), "reblind_show failed: {:?}", r.err());

        // Step 8: Verify Prepare (reblinded proof must pass)
        let r = verify_prepare(docs.clone());
        assert!(r.is_ok(), "verify_prepare failed: {:?}", r.err());
        assert!(r.unwrap(), "prepare proof must verify");

        // Step 9: Verify Show (reblinded proof must pass)
        let r = verify_show(docs.clone());
        assert!(r.is_ok(), "verify_show failed: {:?}", r.err());
        assert!(r.unwrap(), "show proof must verify");

        // Verify get_comm_w_shared works for both circuits.
        // Note: comm_W_shared equality (linkage) requires end-to-end compatible inputs where
        // prepare and show share the same deviceKey and claims. The default test inputs are
        // independent, so we only assert each commitment is readable and non-empty.
        let prep_comm = get_comm_w_shared(docs.clone(), "prepare".to_string())
            .expect("get_comm_w_shared(prepare) must succeed");
        let show_comm = get_comm_w_shared(docs.clone(), "show".to_string())
            .expect("get_comm_w_shared(show) must succeed");
        assert!(
            !prep_comm.is_empty(),
            "prepare comm_W_shared must be non-empty"
        );
        assert!(
            !show_comm.is_empty(),
            "show comm_W_shared must be non-empty"
        );
    }

    /// Complete benchmark pipeline — exercises all 9 operations with precise timing.
    #[test]
    #[ignore = "Long-running e2e (~10 min); run with: cargo test -- --ignored e2e_complete_benchmark"]
    fn e2e_complete_benchmark() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let docs = setup_mobile_docs(&temp);

        let r = run_complete_benchmark(docs);
        assert!(r.is_ok(), "run_complete_benchmark failed: {:?}", r.err());

        let b = r.unwrap();

        // Long-running operations must record positive ms timings.
        // generate_blinds is sub-millisecond so we only assert it doesn't panic.
        assert!(b.prepare_setup_ms > 0, "prepare_setup_ms must be > 0");
        assert!(b.show_setup_ms > 0, "show_setup_ms must be > 0");
        assert!(b.prove_prepare_ms > 0, "prove_prepare_ms must be > 0");
        assert!(b.reblind_prepare_ms > 0, "reblind_prepare_ms must be > 0");
        assert!(b.prove_show_ms > 0, "prove_show_ms must be > 0");
        assert!(b.reblind_show_ms > 0, "reblind_show_ms must be > 0");
        assert!(b.verify_prepare_ms > 0, "verify_prepare_ms must be > 0");
        assert!(b.verify_show_ms > 0, "verify_show_ms must be > 0");

        // All artifacts must be non-empty
        assert!(b.prepare_proof_bytes > 0, "prepare_proof_bytes must be > 0");
        assert!(b.show_proof_bytes > 0, "show_proof_bytes must be > 0");
        assert!(
            b.prepare_proving_key_bytes > 0,
            "prepare_proving_key_bytes must be > 0"
        );
        assert!(
            b.show_proving_key_bytes > 0,
            "show_proving_key_bytes must be > 0"
        );
        assert!(
            b.prepare_witness_bytes > 0,
            "prepare_witness_bytes must be > 0"
        );
        assert!(b.show_witness_bytes > 0, "show_witness_bytes must be > 0");
    }
}
