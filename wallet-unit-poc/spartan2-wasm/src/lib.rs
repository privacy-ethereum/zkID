//! Standalone WebAssembly crate for Spartan2 zkID proving.
//! Supports all zkID circuits via runtime `CircuitKind`.
//! Transcript flow is kept in sync with `ecdsa-spartan2` by `native_drift`.

pub mod inputs;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use serde::{Deserialize, Serialize};
use spartan2::{
    bellpepper::{solver::SatisfyingAssignment, zk_r1cs::SpartanWitness},
    provider::T256HyraxEngine,
    traits::{
        circuit::SpartanCircuit, snark::R1CSSNARKTrait, transcript::TranscriptEngineTrait, Engine,
    },
    zk_spartan::R1CSSNARK,
};
use std::sync::Mutex;
use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;

// ── Type aliases (from ecdsa-spartan2/src/lib.rs) ────────────────────────────
pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

// Public aliases so the native drift test can round-trip proofs via bincode
// with the same concrete types ecdsa-spartan2 uses.
pub type R1CSSNARKForTest = R1CSSNARK<E>;
pub type VerifierKeyForTest = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;

// ── CircuitKind and its metadata ─────────────────────────────────────────────
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CircuitKind {
    CertChainRs2048 = 0,
    CertChainRs4096 = 1,
    DeviceSigRs2048 = 2,
}

impl CircuitKind {
    /// NUM_PUBLIC per circuit.
    pub fn num_public(self) -> usize {
        match self {
            CircuitKind::CertChainRs2048 => 21,
            CircuitKind::CertChainRs4096 => 38,
            CircuitKind::DeviceSigRs2048 => 2,
        }
    }

    /// Index into `public_values` for `pk_commit`.
    pub fn pk_commit_index(self) -> usize {
        match self {
            CircuitKind::CertChainRs2048 | CircuitKind::CertChainRs4096 => 1,
            CircuitKind::DeviceSigRs2048 => 0,
        }
    }
}

// Parse circom `.wtns` into scalars with checked offset arithmetic.
fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<Scalar>, SynthesisError> {
    let len = witness_bytes.len();
    let mut pos = 0usize;
    if len < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 8; // magic + version (fixed small literal, no overflow risk)
    if len.saturating_sub(pos) < 4 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let mut n8 = 0usize;
    for _ in 0..n_sections {
        if len.saturating_sub(pos) < 12 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let section_id = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let section_length =
            u64::from_le_bytes(witness_bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        match section_id {
            1 => {
                if len.saturating_sub(pos) < 4 {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                // Advance to the next section safely.
                pos = pos.saturating_add(section_length);
            }
            2 => {
                let end = pos
                    .checked_add(section_length)
                    .ok_or(SynthesisError::Unsatisfiable)?;
                if n8 == 0 || end > len {
                    return Err(SynthesisError::Unsatisfiable);
                }
                let data = &witness_bytes[pos..end];
                let num = section_length / n8;
                let mut scalars = Vec::with_capacity(num);
                for chunk in data.chunks(n8) {
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    let s = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(s);
                }
                return Ok(scalars);
            }
            _ => pos = pos.saturating_add(section_length),
        }
    }
    Err(SynthesisError::Unsatisfiable)
}

// ── WasmCircuit: parameterized by NUM_PUBLIC ─────────────────────────────────
#[derive(Clone, Debug)]
struct WasmCircuit {
    witness: Vec<Scalar>,
    num_public: usize,
}

impl SpartanCircuit<E> for WasmCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self, cs: &mut CS, _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>], _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let num_inputs = 1 + self.num_public;
        if self.witness.len() < num_inputs { return Err(SynthesisError::Unsatisfiable); }
        let num_aux = self.witness.len() - num_inputs;
        for i in 1..num_inputs {
            AllocatedNum::alloc_input(cs.namespace(|| format!("public_{}", i)),
                || Ok(self.witness[i]))?;
        }
        for i in 0..num_aux {
            AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)),
                || Ok(self.witness[i + num_inputs]))?;
        }
        Ok(())
    }
    fn shared<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS)
        -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> { Ok(vec![]) }
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        if self.witness.len() < 1 + self.num_public { return Err(SynthesisError::Unsatisfiable); }
        Ok(self.witness[1..=self.num_public].to_vec())
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS,
        _: &[AllocatedNum<Scalar>]) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize { 0 }
}

// ── Global PK cache: one slot per CircuitKind ────────────────────────────────
type PkCell = Mutex<Option<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey>>;
static PK_CERT_2048: PkCell = Mutex::new(None);
static PK_CERT_4096: PkCell = Mutex::new(None);
static PK_DEVICE_2048: PkCell = Mutex::new(None);

fn pk_slot(kind: CircuitKind) -> &'static PkCell {
    match kind {
        CircuitKind::CertChainRs2048 => &PK_CERT_2048,
        CircuitKind::CertChainRs4096 => &PK_CERT_4096,
        CircuitKind::DeviceSigRs2048 => &PK_DEVICE_2048,
    }
}

/// Lock PK slot and recover from poison to avoid wasm runtime abort.
fn lock_pk_mut(
    kind: CircuitKind,
) -> std::sync::MutexGuard<'static, Option<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey>> {
    pk_slot(kind).lock().unwrap_or_else(|e| e.into_inner())
}

// Core prove path shared by wasm_bindgen and native test entry points.
// Keep transcript order aligned with `ecdsa-spartan2` and `native_drift`.
fn prove_core(
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    kind: CircuitKind,
    wtns_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<Scalar>), String> {
    let witness = parse_witness(wtns_bytes).map_err(|e| format!("witness parse: {e:?}"))?;
    let circuit = WasmCircuit { witness, num_public: kind.num_public() };

    let mut prep_snark = R1CSSNARK::<E>::prep_prove(pk, circuit.clone(), false)
        .map_err(|e| format!("prep_prove: {e:?}"))?;
    let mut t = <E as Engine>::TE::new(b"R1CSSNARK");
    t.absorb(b"vk", &pk.vk_digest);
    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| format!("public_values: {e:?}"))?;
    t.absorb(b"public_values", &public_values.as_slice());
    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps, &pk.S, &pk.ck, &circuit, false, &mut t,
    ).map_err(|e| format!("instance/witness: {e:?}"))?;
    let proof = R1CSSNARK::<E>::prove_inner(pk, &instance, &witness, &mut t)
        .map_err(|e| format!("prove_inner: {e:?}"))?;

    Ok((
        bincode::serialize(&proof).map_err(|e| e.to_string())?,
        bincode::serialize(&instance).map_err(|e| e.to_string())?,
        public_values,
    ))
}

// ── wasm-bindgen entry points ────────────────────────────────────────────────
#[wasm_bindgen(start)]
pub fn wasm_init() { console_error_panic_hook::set_once(); }

#[wasm_bindgen]
pub fn load_pk(kind: CircuitKind, pk_bytes: &[u8]) -> Result<(), JsError> {
    let pk = bincode::deserialize(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialize ({kind:?}): {e}")))?;
    *lock_pk_mut(kind) = Some(pk);
    Ok(())
}

#[wasm_bindgen]
pub fn drop_pk(kind: CircuitKind) { *lock_pk_mut(kind) = None; }

#[derive(Serialize)]
struct ProveJs { proof: Vec<u8>, instance: Vec<u8>, public_values: Vec<String> }

#[wasm_bindgen]
pub fn prove(kind: CircuitKind, wtns_bytes: &[u8]) -> Result<JsValue, JsError> {
    let guard = lock_pk_mut(kind);
    let pk = guard.as_ref().ok_or_else(|| JsError::new("PK not loaded. Call load_pk() first."))?;
    let (proof, instance, pv) = prove_core(pk, kind, wtns_bytes).map_err(|e| JsError::new(&e))?;
    let out = ProveJs {
        proof, instance,
        public_values: pv.iter().map(|s| format!("{s:?}")).collect(),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize)]
struct VerifyJs { valid: bool, public_values: Vec<String>, error: Option<String> }

#[wasm_bindgen]
pub fn verify(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<JsValue, JsError> {
    let proof: R1CSSNARK<E> = bincode::deserialize(proof_bytes)
        .map_err(|e| JsError::new(&format!("proof deserialize: {e}")))?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey = bincode::deserialize(vk_bytes)
        .map_err(|e| JsError::new(&format!("vk deserialize: {e}")))?;
    let out = match proof.verify(&vk) {
        Ok(pv) => VerifyJs {
            valid: true,
            public_values: pv.iter().map(|s| format!("{s:?}")).collect(),
            error: None,
        },
        Err(e) => VerifyJs { valid: false, public_values: vec![], error: Some(format!("{e:?}")) },
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

/// Assert pk_commit equality between a cert-chain proof's public values and a
/// device-sig proof's public values. Both are passed as Vec<String> (debug-printed
/// scalars) to match what `prove()` and `verify()` return to JS.
#[wasm_bindgen]
pub fn link_verify(cert_pubs: Vec<String>, device_pubs: Vec<String>) -> Result<JsValue, JsError> {
    let cert_pk = cert_pubs.get(CircuitKind::CertChainRs2048.pk_commit_index())
        .ok_or_else(|| JsError::new("cert public values missing pk_commit"))?;
    let device_pk = device_pubs.get(CircuitKind::DeviceSigRs2048.pk_commit_index())
        .ok_or_else(|| JsError::new("device public values missing pk_commit"))?;
    let ok = cert_pk == device_pk;
    #[derive(Serialize)]
    struct LinkJs { ok: bool, cert_pk_commit: String, device_pk_commit: String }
    serde_wasm_bindgen::to_value(&LinkJs {
        ok, cert_pk_commit: cert_pk.clone(), device_pk_commit: device_pk.clone(),
    }).map_err(|e| JsError::new(&e.to_string()))
}

// ── Native-only API for the drift test ───────────────────────────────────────
#[cfg(not(target_arch = "wasm32"))]
pub fn prove_native_for_test(
    kind: CircuitKind, pk_bytes: &[u8], wtns_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<Scalar>), String> {
    let pk = bincode::deserialize(pk_bytes).map_err(|e| format!("pk deserialize: {e}"))?;
    prove_core(&pk, kind, wtns_bytes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_roundtrip(
    proof_bytes: &[u8], vk_bytes: &[u8],
) -> Result<Vec<Scalar>, String> {
    let proof: R1CSSNARK<E> = bincode::deserialize(proof_bytes).map_err(|e| e.to_string())?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        bincode::deserialize(vk_bytes).map_err(|e| e.to_string())?;
    proof.verify(&vk).map_err(|e| format!("{e:?}"))
}

// ── Unit tests (native; parse_witness edge cases) ────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn parse_witness_bad_magic() {
        assert!(parse_witness(b"XXXX\x00\x00\x00\x00\x02\x00\x00\x00").is_err());
    }
    #[test] fn parse_witness_truncated() {
        assert!(parse_witness(b"wtns\x01\x00\x00\x00").is_err());
    }
    #[test] fn parse_witness_empty() {
        assert!(parse_witness(&[]).is_err());
    }
    #[test] fn num_public_matches_spec() {
        assert_eq!(CircuitKind::CertChainRs2048.num_public(), 21);
        assert_eq!(CircuitKind::CertChainRs4096.num_public(), 38);
        assert_eq!(CircuitKind::DeviceSigRs2048.num_public(), 2);
    }

    /// Regression: oversized section lengths must return Err, not panic.
    #[test] fn parse_witness_oversized_section_length_no_overflow() {
        // Valid magic (4) + version (4) + n_sections=1 (4) = 12
        // + section_id=2 (4) + section_length=usize::MAX (8) = 24
        let mut bytes = Vec::from(&b"wtns\x02\x00\x00\x00\x01\x00\x00\x00"[..]);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_witness(&bytes).is_err());
    }
}
