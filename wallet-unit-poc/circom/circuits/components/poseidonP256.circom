pragma circom 2.2.3;

include "poseidonP256Constants.circom";

/// @title Sigma
/// @notice S-box: x^5
template PoseidonP256Sigma() {
    signal input in;
    signal output out;
    signal in2;
    signal in4;
    in2 <== in * in;
    in4 <== in2 * in2;
    out <== in4 * in;
}

/// @title PoseidonP256
/// @notice Standard (non-optimized) Poseidon hash over P-256 scalar field.
///         Uses raw round constants and MDS matrix (no sparse optimization).
/// @param nInputs Number of inputs (2 or 3)
template PoseidonP256(nInputs) {
    signal input inputs[nInputs];
    signal output out;

    var t = nInputs + 1;
    var N_ROUNDS_P[2] = [57, 56]; // t=3 -> 57, t=4 -> 56
    var nRoundsF = 8;
    var nRoundsP = N_ROUNDS_P[t - 3];
    var totalRounds = nRoundsF + nRoundsP;
    var halfF = nRoundsF \ 2;

    // Select constants based on t
    var C[totalRounds * t];
    var M[t][t];

    if (t == 3) {
        C = POSEIDON_P256_C_3();
        M = POSEIDON_P256_M_3();
    } else {
        C = POSEIDON_P256_C_4();
        M = POSEIDON_P256_M_4();
    }

    // State: [capacity=0, input1, input2, ...]
    // After each round: add constants -> S-box -> MDS mix
    component sigma[totalRounds][t];
    signal state[totalRounds + 1][t];

    // Initialize state
    state[0][0] <== 0; // capacity
    for (var i = 0; i < nInputs; i++) {
        state[0][i + 1] <== inputs[i];
    }

    for (var r = 0; r < totalRounds; r++) {
        var isFull = (r < halfF) || (r >= halfF + nRoundsP);

        // Add round constants + S-box
        for (var j = 0; j < t; j++) {
            sigma[r][j] = PoseidonP256Sigma();
            if (isFull || j == 0) {
                // Full round: S-box on all elements
                // Partial round: S-box only on first element
                sigma[r][j].in <== state[r][j] + C[r * t + j];
            } else {
                // Partial round, j > 0: identity (pass through with constant)
                sigma[r][j].in <== 0; // unused, we handle below
            }
        }

        // MDS mixing
        for (var i = 0; i < t; i++) {
            var lc = 0;
            for (var j = 0; j < t; j++) {
                if (isFull || j == 0) {
                    lc += M[i][j] * sigma[r][j].out;
                } else {
                    lc += M[i][j] * (state[r][j] + C[r * t + j]);
                }
            }
            state[r + 1][i] <== lc;
        }
    }

    out <== state[totalRounds][0];
}
