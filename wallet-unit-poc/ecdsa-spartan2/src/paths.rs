//! Path config for cross-platform compatibility.

use std::path::{Path, PathBuf};

/// Path config for all file operations.
///
/// This struct replaces the previous pattern of changing the global working directory,
/// providing explicit, thread-safe path resolution.
#[derive(Clone, Debug)]
pub struct PathConfig {
    /// Base directory for all file operations (Documents dir on mobile, cwd in dev)
    pub base_dir: PathBuf,
    /// Whether running in mobile environment (affects path resolution patterns)
    pub is_mobile: bool,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::development()
    }
}

impl PathConfig {
    /// Create a new PathConfig with explicit settings.
    pub fn new(base_dir: impl Into<PathBuf>, is_mobile: bool) -> Self {
        Self {
            base_dir: base_dir.into(),
            is_mobile,
        }
    }

    /// Create config for mobile environment.
    ///
    /// Mobile apps typically extract assets to a Documents directory with a flat structure:
    /// - `{documents}/rs256_input.json`
    /// - `{documents}/keys/*.key`
    /// - `{documents}/rs256.r1cs`
    pub fn mobile(documents_path: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: documents_path.into(),
            is_mobile: true,
        }
    }

    /// Create config for development environment.
    ///
    /// Development uses nested paths relative to the current working directory:
    /// - `../circom/inputs/cert_chain_rs2048/default.json`
    /// - `keys/*.key`
    /// - `../circom/build/certChainRS2048/certChainRS2048_js/certChainRS2048.r1cs`
    pub fn development() -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            is_mobile: false,
        }
    }

    /// Resolve the input JSON path for a circuit.
    ///
    /// # Arguments
    /// * `circuit` - Circuit name (e.g., "cert_chain_rs2048")
    ///
    /// # Returns
    /// Full path to the input JSON file.
    pub fn input_json(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            // Mobile: flat structure in documents directory
            self.base_dir.join(format!("{}_input.json", circuit))
        } else {
            // Development: nested structure
            self.base_dir
                .join(format!("../circom/inputs/{}/default.json", circuit))
        }
    }

    /// Resolve the R1CS file path for a circuit.
    ///
    /// # Arguments
    /// * `circuit` - Circuit name (e.g., "cert_chain_rs2048")
    ///
    /// # Returns
    /// Full path to the R1CS file.
    pub fn r1cs_path(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            // Mobile: flat structure in documents directory
            self.base_dir.join(format!("{}.r1cs", circuit))
        } else {
            // Development: nested structure
            self.base_dir
                .join("../circom/build")
                .join(circuit)
                .join(format!("{}_js", circuit))
                .join(format!("{}.r1cs", circuit))
        }
    }

    fn keys_subdir_file(&self, name: &str) -> PathBuf {
        self.base_dir.join("keys").join(name)
    }

    /// Resolve a key file path (proving/verifying keys).
    ///
    /// # Arguments
    /// * `name` - Key filename (e.g., "rs256_proving.key")
    ///
    /// # Returns
    /// Full path to the key file.
    pub fn key_path(&self, name: &str) -> PathBuf {
        self.keys_subdir_file(name)
    }

    /// Resolve an artifact file path (proofs, witnesses, instances).
    ///
    /// # Arguments
    /// * `name` - Artifact filename (e.g., "rs256_proof.bin")
    ///
    /// # Returns
    /// Full path to the artifact file.
    pub fn artifact_path(&self, name: &str) -> PathBuf {
        self.keys_subdir_file(name)
    }

    /// Resolve an absolute path, joining relative paths with base_dir.
    ///
    /// If the path is already absolute, it's returned as-is.
    /// Otherwise, it's joined with the base directory.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_config() {
        let config = PathConfig::mobile("/app/Documents");

        assert_eq!(
            config.input_json("cert_chain_rs2048"),
            PathBuf::from("/app/Documents/cert_chain_rs2048_input.json")
        );
        assert_eq!(
            config.r1cs_path("certChainRS2048"),
            PathBuf::from("/app/Documents/certChainRS2048.r1cs")
        );
        assert_eq!(
            config.key_path("cert_chain_rs2048_proving.key"),
            PathBuf::from("/app/Documents/keys/cert_chain_rs2048_proving.key")
        );
    }

    #[test]
    fn test_development_config() {
        let config = PathConfig::new("/project", false);

        assert_eq!(
            config.input_json("cert_chain_rs2048"),
            PathBuf::from("/project/../circom/inputs/cert_chain_rs2048/default.json")
        );
    }

    #[test]
    fn test_resolve_absolute() {
        let config = PathConfig::mobile("/app/Documents");

        let absolute = PathBuf::from("/custom/path/input.json");
        assert_eq!(config.resolve(&absolute), absolute);
    }

    #[test]
    fn test_resolve_relative() {
        let config = PathConfig::mobile("/app/Documents");

        let relative = PathBuf::from("custom/input.json");
        assert_eq!(
            config.resolve(&relative),
            PathBuf::from("/app/Documents/custom/input.json")
        );
    }
}
