//! Core `Sha256RsaCircuit<T>` struct and its `SpartanCircuit` impl.

use crate::{paths::PathConfig, reader::load_r1cs_mmap, utils::parse_witness, Scalar, E};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::synthesize;
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use tracing::info;
use web_time::Instant;
use x509_cert::Certificate;

use super::types::Pkcs11InfoResponse;

/// Compile-time constants and witness generation for a specific RSA key size.
///
/// Implement on a zero-sized marker type (e.g. `CertChainRsa2048`) and use as
/// the type parameter of [`Sha256RsaCircuit<T>`].
pub trait RsaKeySize: Send + Sync + Clone + 'static {
    /// 121-bit limb count (`k` in `RSAVerifier65537(121, k)`).
    const RSA_K: usize;
    /// Snake_case name used for Rust-internal file naming (keys, proof, witness).
    const CIRCUIT_NAME: &'static str;
    /// CamelCase name matching the circomkit circuit ID, used for the build output path.
    const BUILD_NAME: &'static str;
    const NUM_PUBLIC: usize;
    const PROVING_KEY: &'static str;
    const VERIFYING_KEY: &'static str;
    const PROOF: &'static str;
    const WITNESS: &'static str;
    const INSTANCE: &'static str;
    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String>;
}

/// Generic RSA-SHA256 circuit backed by Spartan2.
///
/// `T` selects the circuit variant at compile time (see `split_circuits`).
#[derive(Clone)]
pub struct Sha256RsaCircuit<T: RsaKeySize> {
    path_config: PathConfig,
    input_path: Option<PathBuf>,
    cached_witness: Arc<OnceLock<Vec<Scalar>>>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: RsaKeySize> std::fmt::Debug for Sha256RsaCircuit<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256RsaCircuit")
            .field("circuit", &T::CIRCUIT_NAME)
            .field("path_config", &self.path_config)
            .field("input_path", &self.input_path)
            .finish()
    }
}

impl<T: RsaKeySize> Default for Sha256RsaCircuit<T> {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(OnceLock::new()),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: RsaKeySize> Sha256RsaCircuit<T> {
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(OnceLock::new()),
            _marker: std::marker::PhantomData,
        }
    }

    /// Convenience constructor using development PathConfig.
    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            path_config: PathConfig::development(),
            input_path: path.into(),
            cached_witness: Arc::new(OnceLock::new()),
            _marker: std::marker::PhantomData,
        }
    }

    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.input_json(T::CIRCUIT_NAME))
    }

    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path(T::BUILD_NAME)
    }

    // Forwarding methods -- preserve `CertChainCircuit::method()` call sites.

    pub fn extract_issuer_cert(pkcs11info: &Pkcs11InfoResponse) -> Result<Certificate, Box<dyn std::error::Error>> {
        super::cert::extract_issuer_cert(pkcs11info)
    }

    pub fn fetch_cert_from_file(path: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
        super::cert::fetch_cert_from_file(path)
    }

    pub fn generate_user_cert_from_certb64(certb64: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
        super::cert::generate_user_cert_from_certb64(certb64)
    }

    pub fn generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let json_path = self.resolve_input_json();

        let mut file = File::open(&json_path).map_err(|e| {
            eprintln!("Failed to open input JSON at {:?}: {}", json_path, e);
            SynthesisError::AssignmentMissing
        })?;

        let mut json_string = String::new();
        file.read_to_string(&mut json_string).map_err(|e| {
            eprintln!("Failed to read input JSON: {}", e);
            SynthesisError::AssignmentMissing
        })?;

        // Generate witness using witnesscalc adapter.
        // Spawned on a dedicated thread with a large stack: the witnesscalc C++
        // library reallocates its internal buffer when the circuit is large
        // (sha256rsa4096 needs ~122 MB). On macOS, realloc() moves the
        // allocation and the library's stale interior pointers trigger SIGSEGV
        // on the main thread. A fresh thread with pre-committed virtual address
        // space makes realloc() more likely to grow in-place, avoiding the move.
        info!(
            "Generating witness using witnesscalc ({})...",
            T::CIRCUIT_NAME
        );
        let t0 = Instant::now();
        let witness_bytes = {
            let json_for_thread = json_string.clone();
            std::thread::Builder::new()
                .stack_size(256 * 1024 * 1024) // 256 MB
                .spawn(move || T::generate_witness_bytes(&json_for_thread))
                .map_err(|e| {
                    eprintln!("Failed to spawn witness thread: {e}");
                    SynthesisError::Unsatisfiable
                })?
                .join()
                .map_err(|_| {
                    eprintln!("Witness generation thread panicked");
                    SynthesisError::Unsatisfiable
                })?
                .map_err(|e| {
                    eprintln!("Witness generation failed: {e}");
                    SynthesisError::Unsatisfiable
                })?
        };
        info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

        let witness = parse_witness(&witness_bytes)?;
        info!("witness generation completed: {} elements", witness.len());
        Ok(witness)
    }

    fn get_or_generate_witness(&self) -> Result<&Vec<Scalar>, SynthesisError> {
        if let Some(w) = self.cached_witness.get() {
            return Ok(w);
        }
        let witness = self.generate_witness()?;
        Ok(self.cached_witness.get_or_init(|| witness))
    }

    /// Pre-cache the witness before memory-heavy operations (like setup)
    /// to avoid C++ witnesscalc allocation failures under memory pressure.
    pub fn warm_witness_cache(&self) -> Result<(), SynthesisError> {
        self.get_or_generate_witness()?;
        Ok(())
    }

    #[cfg(test)]
    fn get_attr(name: &x509_cert::name::Name, oid: const_oid::ObjectIdentifier) -> String {
        use der::asn1::{PrintableStringRef, Utf8StringRef};
        name.0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|attr| attr.oid == oid)
            .map(|attr| {
                if let Ok(s) = Utf8StringRef::try_from(&attr.value) {
                    s.as_str().to_string()
                } else if let Ok(s) = PrintableStringRef::try_from(&attr.value) {
                    s.as_str().to_string()
                } else {
                    String::from_utf8_lossy(attr.value.value()).to_string()
                }
            })
            .unwrap_or_default()
    }
}

impl<T: RsaKeySize> SpartanCircuit<E> for Sha256RsaCircuit<T> {
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
            let r1cs_path = self.r1cs_path();
            let r1cs = load_r1cs_mmap(&r1cs_path)
                .expect("failed to load r1cs");
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        // During prove, cs is SatisfyingAssignment whose enforce() is a no-op
        // (see Spartan2 src/bellpepper/solver.rs:70-78)
        // Allocate wires directly from the pre-computed witness instead.
        let witness = self.get_or_generate_witness()?;
        let num_inputs = T::NUM_PUBLIC + 1; // +1 for the constant-1 wire at index 0
        let num_aux = witness.len().saturating_sub(num_inputs);

        debug_assert!(
            witness.len() >= num_inputs,
            "witness too short: len={} but NUM_PUBLIC={} requires num_inputs={}",
            witness.len(),
            T::NUM_PUBLIC,
            num_inputs,
        );

        // Index 0 is the implicit constant-1 wire, so start at 1
        for i in 1..num_inputs {
            cs.alloc_input(|| format!("public_{i}"), || Ok(witness[i]))?;
        }
        for i in 0..num_aux {
            cs.alloc(|| format!("aux_{i}"), || Ok(witness[i + num_inputs]))?;
        }
        Ok(())
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let num_public = T::NUM_PUBLIC;
        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(num_public);
        for idx in 1..=num_public {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::cert::parse_cert_offsets;
    use crate::circuits::split_circuits::CertChainRsa2048;
    use crate::circuits::types::{CardSignResponse, Pkcs11InfoResponse};
    use base64::Engine as _;
    use const_oid::db::rfc4519::*;
    use der::{Decode, Encode};
    use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};

    const SIGN_RESPONSE: &str = include_str!("../../tests/testdata/response_sign_test.json");
    const PKCS11_RESPONSE: &str = include_str!("../../tests/testdata/pkcs11info_test.json");

    fn load_user_cert() -> Certificate {
        let response: CardSignResponse = serde_json::from_str(SIGN_RESPONSE).unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&response.certb64)
            .unwrap();
        Certificate::from_der(&der).unwrap()
    }

    #[test]
    fn test_extract_issuer_cert() {
        let pkcs11: Pkcs11InfoResponse = serde_json::from_str(PKCS11_RESPONSE).unwrap();
        let cert = Sha256RsaCircuit::<CertChainRsa2048>::extract_issuer_cert(&pkcs11).unwrap();
        let ou = Sha256RsaCircuit::<CertChainRsa2048>::get_attr(&cert.tbs_certificate.subject, ORGANIZATIONAL_UNIT_NAME);
        assert!(!ou.is_empty(), "Issuer cert should have an OU");
    }

    #[test]
    fn test_parse_cert_offsets() {
        let user_cert = load_user_cert();
        let der = user_cert.to_der().unwrap();
        let offsets = parse_cert_offsets(&der).unwrap();

        assert_eq!(der[offsets.modulus_tag_offset], 0x02);
        assert!(offsets.modulus_offset > offsets.modulus_tag_offset);

        let spki_der = user_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der).unwrap();
        let expected_bytes = rsa_pub.n().to_bytes_be();

        let extracted = &der[offsets.modulus_offset..offsets.modulus_offset + expected_bytes.len()];
        assert_eq!(extracted, expected_bytes.as_slice());
    }
}
