//! Split circuit marker types (Phase 2 cert-chain + device-sig).
//!
//! Each marker implements [`RsaKeySize`] and plugs into [`Sha256RsaCircuit<T>`].
//! `generate_split_inputs` lives in `zkid-input-builder` so the browser prover
//! produces byte-identical circuit input JSON.

use super::circuit::{RsaKeySize, Sha256RsaCircuit};

pub use zkid_input_builder::{
    generate_split_inputs, random_pk_blind, APP_ID_LEN, MAX_CERT_CHAIN_LENGTH,
};

#[cfg(feature = "cert_chain_rs2048")]
witnesscalc_adapter::witness!(cert_chain_rs2048);
#[cfg(feature = "cert_chain_rs4096")]
witnesscalc_adapter::witness!(cert_chain_rs4096);
#[cfg(feature = "device_sig_rs2048")]
witnesscalc_adapter::witness!(device_sig_rs2048);

/// RSA-2048 issuer + RSA-2048 user (MOICA-G2).
#[derive(Debug, Clone, Copy)]
pub struct CertChainRsa2048;

/// RSA-4096 issuer + RSA-2048 user.
#[derive(Debug, Clone, Copy)]
pub struct CertChainRsa4096;

#[allow(unused_variables)]
impl RsaKeySize for CertChainRsa2048 {
    const RSA_K: usize = 17;
    const CIRCUIT_NAME: &'static str = "cert_chain_rs2048";
    const NUM_PUBLIC: usize = 19;
    const PROVING_KEY: &'static str = "cert_chain_rs2048_proving.key";
    const VERIFYING_KEY: &'static str = "cert_chain_rs2048_verifying.key";
    const PROOF: &'static str = "cert_chain_rs2048_proof.bin";
    const WITNESS: &'static str = "cert_chain_rs2048_witness.bin";
    const INSTANCE: &'static str = "cert_chain_rs2048_instance.bin";

    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String> {
        #[cfg(feature = "cert_chain_rs2048")]
        return cert_chain_rs2048_witness(json).map_err(|e| e.to_string());
        #[cfg(not(feature = "cert_chain_rs2048"))]
        Err("Feature `cert_chain_rs2048` is not enabled".to_string())
    }
}

#[allow(unused_variables)]
impl RsaKeySize for CertChainRsa4096 {
    const RSA_K: usize = 34;
    const CIRCUIT_NAME: &'static str = "cert_chain_rs4096";
    const NUM_PUBLIC: usize = 36;
    const PROVING_KEY: &'static str = "cert_chain_rs4096_proving.key";
    const VERIFYING_KEY: &'static str = "cert_chain_rs4096_verifying.key";
    const PROOF: &'static str = "cert_chain_rs4096_proof.bin";
    const WITNESS: &'static str = "cert_chain_rs4096_witness.bin";
    const INSTANCE: &'static str = "cert_chain_rs4096_instance.bin";

    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String> {
        #[cfg(feature = "cert_chain_rs4096")]
        return cert_chain_rs4096_witness(json).map_err(|e| e.to_string());
        #[cfg(not(feature = "cert_chain_rs4096"))]
        Err("Feature `cert_chain_rs4096` is not enabled".to_string())
    }
}

/// Device signature -- always RSA-2048 (user keys).
#[derive(Debug, Clone, Copy)]
pub struct DeviceSigRsa2048;

#[allow(unused_variables)]
impl RsaKeySize for DeviceSigRsa2048 {
    const RSA_K: usize = 17;
    const CIRCUIT_NAME: &'static str = "device_sig_rs2048";
    // pk_commit, nullifier, app_id_packed, challenge.
    const NUM_PUBLIC: usize = 4;
    const PROVING_KEY: &'static str = "device_sig_rs2048_proving.key";
    const VERIFYING_KEY: &'static str = "device_sig_rs2048_verifying.key";
    const PROOF: &'static str = "device_sig_rs2048_proof.bin";
    const WITNESS: &'static str = "device_sig_rs2048_witness.bin";
    const INSTANCE: &'static str = "device_sig_rs2048_instance.bin";

    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String> {
        #[cfg(feature = "device_sig_rs2048")]
        return device_sig_rs2048_witness(json).map_err(|e| e.to_string());
        #[cfg(not(feature = "device_sig_rs2048"))]
        Err("Feature `device_sig_rs2048` is not enabled".to_string())
    }
}

pub type CertChainCircuit = Sha256RsaCircuit<CertChainRsa2048>;
pub type CertChainRs4096Circuit = Sha256RsaCircuit<CertChainRsa4096>;
pub type DeviceSigCircuit = Sha256RsaCircuit<DeviceSigRsa2048>;
