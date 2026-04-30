pragma circom 2.2.3;

include "rs256.circom";
include "components/pk_commit.circom";

/// @title DeviceSigRSA256
/// @notice Circuit B of the CertChain + DeviceSig pair. Verifies an RSA
///         signature over the SHA-256-padded `tbs` and emits `pk_commit`,
///         `nullifier = ChunkedPoseidonP256(signature)`, and `app_id_packed`
///         (`tbs[0..31]` packed into one field element).
///
///         `challenge` is a per-session field element issued by the verifier,
///         bound into the proof via a Semaphore-style dummy square
///         (https://github.com/semaphore-protocol/semaphore/blob/341475c66bee7473f8d25f44bc0dcf6b255b5a6c/packages/circuits/src/semaphore.circom#L74).
///         Together with the verifier's per-session TTL on `challenge_id`,
///         this prevents pre-generated proofs from being replayed.
///
/// @param maxMessageLength  Max byte length of `tbs` (1536)
/// @param n                 RSA limb bits (e.g. 121)
/// @param k                 RSA limb count (17 for 2048-bit, 34 for 4096-bit)
template DeviceSigRSA256(maxMessageLength, n, k) {
    signal input tbs[maxMessageLength];
    signal input tbs_length;

    signal input user_pk_limbs[k];
    signal input user_rsa_signature[k];

    // Must match CertChainRSA256's pk_blind.
    signal input pk_blind;

    // Per-session nonce from the verifier's /challenge endpoint.
    signal input challenge;

    signal output pk_commit;
    signal output nullifier;
    signal output app_id_packed;

    CertRSA256Verify(maxMessageLength, n, k)(
        tbs,
        tbs_length,
        user_pk_limbs,
        user_rsa_signature
    );

    // Pack tbs[0..31] little-endian into one field element. Byte-range of
    // tbs[i] is already enforced inside CertRSA256Verify (Num2Bits(8) on the
    // message), so no extra range checks are needed.
    component appIdPacker = PackBytes(31, maxMessageLength);
    for (var i = 0; i < maxMessageLength; i++) {
        appIdPacker.in[i] <== tbs[i];
    }
    app_id_packed <== appIdPacker.out[0];

    // Semaphore-style dummy square: binds `challenge` into the constraint
    // system without it entering pk_commit or the nullifier.
    signal challengeSquared;
    challengeSquared <== challenge * challenge;

    component pkCommit = ChunkedPoseidonP256(k + 1);
    for (var i = 0; i < k; i++) {
        pkCommit.inputs[i] <== user_pk_limbs[i];
    }
    pkCommit.inputs[k] <== pk_blind;
    pk_commit <== pkCommit.out;

    component nullifierHash = ChunkedPoseidonP256(k);
    for (var i = 0; i < k; i++) {
        nullifierHash.inputs[i] <== user_rsa_signature[i];
    }
    nullifier <== nullifierHash.out;
}
