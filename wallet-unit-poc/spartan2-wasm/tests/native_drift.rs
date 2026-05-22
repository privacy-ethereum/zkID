//! Native drift test: prove via spartan2-wasm, verify via ecdsa-spartan2.
//! Fails if transcript flows diverge.
//! Runs only on native target.

#![cfg(not(target_arch = "wasm32"))]

use ecdsa_spartan2::{
    circuits::{
        circuit::{RsaKeySize, Sha256RsaCircuit},
        split_circuits::{CertChainRsa2048, UserSigRsa2048},
    },
    setup::setup_circuit_keys_no_save,
};
use spartan2_wasm::{
    load_pk_via_streaming_for_test, prove_native_for_test, CircuitKind,
};

fn fixture_input(kind: CircuitKind) -> String {
    let path = match kind {
        CircuitKind::CertChainRs2048 => "../circom/inputs/cert_chain_rs2048/input.json",
        CircuitKind::CertChainRs4096 => panic!("RS4096 fixture not available in unit tests"),
        CircuitKind::UserSigRs2048 => "../circom/inputs/user_sig_rs2048/input.json",
    };
    std::fs::read_to_string(path).expect("read fixture input")
}

/// Witness generation can overflow default test thread stack on macOS.
/// Run it in a 256 MB stack thread.
fn witness_bytes_in_big_stack<T: RsaKeySize + Send + 'static>(input: String) -> Vec<u8> {
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || T::generate_witness_bytes(&input))
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked")
        .expect("witness-gen failed")
}

#[test]
fn cert_chain_rs2048_drift() {
    let input = fixture_input(CircuitKind::CertChainRs2048);
    let wtns = witness_bytes_in_big_stack::<CertChainRsa2048>(input);

    let (pk, vk) = setup_circuit_keys_no_save::<Sha256RsaCircuit<CertChainRsa2048>>(
        Sha256RsaCircuit::<CertChainRsa2048>::default(),
    );

    let pk_bytes = bincode::serialize(&pk).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();

    let (proof_bytes, _instance_bytes, public_values) =
        prove_native_for_test(CircuitKind::CertChainRs2048, &pk_bytes, &wtns)
            .expect("spartan2-wasm prove");

    let proof: spartan2_wasm::R1CSSNARKForTest =
        bincode::deserialize(&proof_bytes).unwrap();
    let vk_native: spartan2_wasm::VerifierKeyForTest = bincode::deserialize(&vk_bytes).unwrap();
    let pv = ecdsa_spartan2::prover::verify_circuit_with_loaded_data(&proof, &vk_native);

    assert_eq!(
        pv.len(),
        CircuitKind::CertChainRs2048.num_public(),
        "cert_chain_rs2048 NUM_PUBLIC"
    );
    assert_eq!(pv, public_values, "public values round-trip");
}

#[test]
fn user_sig_rs2048_drift() {
    let input = fixture_input(CircuitKind::UserSigRs2048);
    let wtns = witness_bytes_in_big_stack::<UserSigRsa2048>(input);

    let (pk, vk) = setup_circuit_keys_no_save::<Sha256RsaCircuit<UserSigRsa2048>>(
        Sha256RsaCircuit::<UserSigRsa2048>::default(),
    );

    let pk_bytes = bincode::serialize(&pk).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();

    let (proof_bytes, _instance_bytes, public_values) =
        prove_native_for_test(CircuitKind::UserSigRs2048, &pk_bytes, &wtns).unwrap();

    let proof: spartan2_wasm::R1CSSNARKForTest = bincode::deserialize(&proof_bytes).unwrap();
    let vk_native: spartan2_wasm::VerifierKeyForTest = bincode::deserialize(&vk_bytes).unwrap();
    let pv = ecdsa_spartan2::prover::verify_circuit_with_loaded_data(&proof, &vk_native);

    assert_eq!(
        pv.len(),
        CircuitKind::UserSigRs2048.num_public(),
        "user_sig_rs2048 NUM_PUBLIC"
    );
    assert_eq!(pv, public_values);
}

/// Cross-mode parity: both eager and streaming-bincode storage must
/// round-trip the input bytes to a `ProverKey` that re-serializes to the
/// exact same bytes. A divergence means the chunk-drain `Read` adapter has
/// a chunk-boundary bug. Uses `user_sig_rs2048` because the rs4096 in-test
/// setup is too heavy for unit-test wall-clock; the parity check does not
/// depend on which PK shape we feed it.
#[test]
fn streaming_load_pk_parity_user_sig_rs2048() {
    let (pk, _vk) = setup_circuit_keys_no_save::<Sha256RsaCircuit<UserSigRsa2048>>(
        Sha256RsaCircuit::<UserSigRsa2048>::default(),
    );
    let pk_bytes = bincode::serialize(&pk).unwrap();

    // 4 MiB matches the web worker's `PK_LOAD_CHUNK_BYTES`; the small
    // size stresses chunk-boundary handling when chunks are smaller than
    // typical bincode reads.
    for &chunk_size in &[4 * 1024 * 1024usize, 137usize] {
        let eager_round_trip = load_pk_via_streaming_for_test(
            CircuitKind::UserSigRs2048,
            &pk_bytes,
            chunk_size,
            false,
        )
        .expect("eager load_pk");
        assert_eq!(
            eager_round_trip, pk_bytes,
            "eager re-serialize must match original (chunk_size={chunk_size})",
        );

        let streaming_round_trip = load_pk_via_streaming_for_test(
            CircuitKind::UserSigRs2048,
            &pk_bytes,
            chunk_size,
            true,
        )
        .expect("streaming load_pk");
        assert_eq!(
            streaming_round_trip, pk_bytes,
            "streaming re-serialize must match original (chunk_size={chunk_size})",
        );
    }
}
