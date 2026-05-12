pragma circom 2.2.3;

include "smtVerifierP256.circom";

/// @title SMTNonMembershipVerifier
/// @notice Wrapper around SMTVerifierP256 that hardcodes non-membership semantics
/// @param depth Number of levels in the Sparse Merkle Tree
template SMTNonMembershipVerifier(depth) {
    signal input root;
    signal input key;
    signal input siblings[depth];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    // enabled=1, value=0 (non-membership), fnc=1 (non-inclusion)
    SMTVerifierP256(depth)(1, root, siblings, oldKey, oldValue, isOld0, key, 0, 1);
}
