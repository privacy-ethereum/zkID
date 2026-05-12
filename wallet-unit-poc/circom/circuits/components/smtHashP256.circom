pragma circom 2.2.3;

include "poseidonP256.circom";

/// @title SMTHash1P256
/// @notice Leaf hash: Poseidon(key, value, 1) over P-256 field
template SMTHash1P256() {
    signal input key;
    signal input value;
    signal output out;

    component h = PoseidonP256(3);
    h.inputs[0] <== key;
    h.inputs[1] <== value;
    h.inputs[2] <== 1;
    out <== h.out;
}

/// @title SMTHash2P256
/// @notice Branch hash: Poseidon(L, R) over P-256 field
template SMTHash2P256() {
    signal input L;
    signal input R;
    signal output out;

    component h = PoseidonP256(2);
    h.inputs[0] <== L;
    h.inputs[1] <== R;
    out <== h.out;
}
