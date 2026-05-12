pragma circom 2.2.3;

include "poseidonP256.circom";

/// @title ChunkedPoseidonP256
/// @notice Sponge-style hash over an arbitrary number of field elements.
///         Wraps PoseidonP256(2) so we can hash N+1 inputs without needing new
///         round constants for higher Poseidon arities (PoseidonP256 only ships
///         t=3 and t=4).
/// @dev    state[0] = 0
///         state[i+1] = PoseidonP256(2)(state[i], inputs[i])
///         out = state[nInputs]
///
///         Cost: nInputs * Poseidon(2). Each Poseidon(2) is roughly 650
///         constraints, so ChunkedPoseidonP256(18) ≈ 12K constraints,
///         ChunkedPoseidonP256(35) ≈ 23K — both negligible vs the
///         ~50K-constraint RSA verify each split circuit performs.
///
///         Binding: an adversary cannot find a different input vector that
///         produces the same `out` without breaking Poseidon's preimage
///         resistance (modulo the standard assumption).
///
///         Hiding: NOT inherently hiding. The caller must include a fresh,
///         random `pkBlind` as the last input element to randomize `out`
///         per session. See cert_chain.circom and user_sig.circom for usage.
///         The `pkBlind` input is a per-session uniform field element drawn
///         by the prover; see SPEC.md §"Why per-session randomness for pkBlind".
/// @param nInputs  Number of input field elements (must be >= 1)
/// @input  inputs  The field elements to hash
/// @output out     Single-field commitment
template ChunkedPoseidonP256(nInputs) {
    signal input inputs[nInputs];
    signal output out;

    component hash[nInputs];
    signal state[nInputs + 1];
    state[0] <== 0;

    for (var i = 0; i < nInputs; i++) {
        hash[i] = PoseidonP256(2);
        hash[i].inputs[0] <== state[i];
        hash[i].inputs[1] <== inputs[i];
        state[i + 1] <== hash[i].out;
    }

    out <== state[nInputs];
}
