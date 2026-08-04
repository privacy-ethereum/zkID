pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "eval-predicate.circom";

/// @title EvalPredicates
/// @notice Evaluates an array of atomic predicates over a fixed-size claim array.
/// @dev Claim references are integer indices into `claimValues`.
/// @dev Predicate tuple encoding per slot i:
/// @dev   [predicateClaimRefs[i], predicateOps[i], rhsIsRef[i], rhsRef[i], rhsValue[i]]
/// @dev Operator encoding:
/// @dev   0 = <=
/// @dev   1 = >=
/// @dev   2 = ==
template EvalPredicates(N_CLAIMS, MAX_PREDICATES, VALUE_BITS) {
    signal input claimValues[N_CLAIMS]; // Canonically normalized claim values.

    // Number of active predicate tuples in [0, MAX_PREDICATES]
    signal input predicateLen; // Number of active predicate tuples.

    signal input predicateClaimRefs[MAX_PREDICATES]; // Left-hand claim reference per predicate.
    signal input predicateOps[MAX_PREDICATES]; // Operator per predicate: 0<=, 1>=, 2==.
    signal input predicateRhsIsRef[MAX_PREDICATES]; // Right-hand side (RHS) mode: 0=literal, 1=claim reference.
    signal input predicateRhsValues[MAX_PREDICATES]; // RHS operand: claim index when predicateRhsIsRef is 1, literal value when 0.

    // A claim slot is otherwise just a number, so a holder could satisfy a
    // policy using a different signed attribute with a friendlier value.
    signal input claimIdentifierHashes[N_CLAIMS]; // Attribute identity per slot.
    signal input predicateClaimIdentifiers[MAX_PREDICATES]; // Identity the policy requires.

    signal output predicateResults[MAX_PREDICATES];

    signal idProduct[MAX_PREDICATES][N_CLAIMS];
    signal idAccum[MAX_PREDICATES][N_CLAIMS + 1];

    component claimRefEq[MAX_PREDICATES][N_CLAIMS];
    signal refSelected[MAX_PREDICATES][N_CLAIMS];
    signal refProduct[MAX_PREDICATES][N_CLAIMS];
    signal refCount[MAX_PREDICATES][N_CLAIMS + 1];
    signal refAccum[MAX_PREDICATES][N_CLAIMS + 1];
    signal selectedClaimValues[MAX_PREDICATES];
    component rhsRefEq[MAX_PREDICATES][N_CLAIMS];
    signal rhsRefSelected[MAX_PREDICATES][N_CLAIMS];
    signal rhsRefProduct[MAX_PREDICATES][N_CLAIMS];
    signal rhsRefCount[MAX_PREDICATES][N_CLAIMS + 1];
    signal rhsRefAccum[MAX_PREDICATES][N_CLAIMS + 1];
    signal selectedRhsRefValues[MAX_PREDICATES];
    signal rhsIsRef[MAX_PREDICATES];
    signal rhsRefActive[MAX_PREDICATES];
    signal literalRhsValue[MAX_PREDICATES];
    signal refRhsValue[MAX_PREDICATES];
    signal selectedCompareValues[MAX_PREDICATES];
    component activeLt[MAX_PREDICATES];
    signal isActive[MAX_PREDICATES];
    signal effectiveClaimValue[MAX_PREDICATES];
    signal effectiveOp[MAX_PREDICATES];
    signal effectiveCompareValue[MAX_PREDICATES];
    component lenRange;
    component predicateEval[MAX_PREDICATES];

    // 0 <= predicateLen <= MAX_PREDICATES
    lenRange = LessThan(16);
    lenRange.in[0] <== predicateLen;
    lenRange.in[1] <== MAX_PREDICATES + 1;
    lenRange.out === 1;

    for (var i = 0; i < MAX_PREDICATES; i++) {
        activeLt[i] = LessThan(16);
        activeLt[i].in[0] <== i;
        activeLt[i].in[1] <== predicateLen;
        isActive[i] <== activeLt[i].out;
        rhsIsRef[i] <== predicateRhsIsRef[i];
        rhsIsRef[i] * (rhsIsRef[i] - 1) === 0;
        rhsRefActive[i] <== isActive[i] * rhsIsRef[i];

        refCount[i][0] <== 0;
        refAccum[i][0] <== 0;
        idAccum[i][0] <== 0;
        rhsRefCount[i][0] <== 0;
        rhsRefAccum[i][0] <== 0;

        for (var j = 0; j < N_CLAIMS; j++) {
            claimRefEq[i][j] = IsEqual();
            claimRefEq[i][j].in[0] <== predicateClaimRefs[i];
            claimRefEq[i][j].in[1] <== j;

            refSelected[i][j] <== isActive[i] * claimRefEq[i][j].out;
            refProduct[i][j] <== refSelected[i][j] * claimValues[j];
            refCount[i][j + 1] <== refCount[i][j] + refSelected[i][j];
            refAccum[i][j + 1] <== refAccum[i][j] + refProduct[i][j];

            // Same one-hot selector, applied to the slot's identity.
            idProduct[i][j] <== refSelected[i][j] * claimIdentifierHashes[j];
            idAccum[i][j + 1] <== idAccum[i][j] + idProduct[i][j];

            rhsRefEq[i][j] = IsEqual();
            rhsRefEq[i][j].in[0] <== predicateRhsValues[i];
            rhsRefEq[i][j].in[1] <== j;

            rhsRefSelected[i][j] <== rhsRefActive[i] * rhsRefEq[i][j].out;
            rhsRefProduct[i][j] <== rhsRefSelected[i][j] * claimValues[j];
            rhsRefCount[i][j + 1] <== rhsRefCount[i][j] + rhsRefSelected[i][j];
            rhsRefAccum[i][j + 1] <== rhsRefAccum[i][j] + rhsRefProduct[i][j];
        }

        // Active predicates must reference exactly one valid claim index.
        // Inactive predicates must reference none (count 0).
        refCount[i][N_CLAIMS] - isActive[i] === 0;
        rhsRefCount[i][N_CLAIMS] - rhsRefActive[i] === 0;

        // The referenced slot must hold the attribute the policy names.
        isActive[i] * (idAccum[i][N_CLAIMS] - predicateClaimIdentifiers[i]) === 0;

        selectedClaimValues[i] <== refAccum[i][N_CLAIMS];
        selectedRhsRefValues[i] <== rhsRefAccum[i][N_CLAIMS];
        literalRhsValue[i] <== (1 - rhsIsRef[i]) * predicateRhsValues[i];
        refRhsValue[i] <== rhsIsRef[i] * selectedRhsRefValues[i];
        selectedCompareValues[i] <== literalRhsValue[i] + refRhsValue[i];
        effectiveClaimValue[i] <== isActive[i] * selectedClaimValues[i];
        effectiveCompareValue[i] <== isActive[i] * selectedCompareValues[i];
        effectiveOp[i] <== isActive[i] * predicateOps[i] + (1 - isActive[i]) * 2;

        predicateEval[i] = EvalPredicate(VALUE_BITS);
        predicateEval[i].claimValue <== effectiveClaimValue[i];
        predicateEval[i].op <== effectiveOp[i];
        predicateEval[i].compareValue <== effectiveCompareValue[i];

        predicateResults[i] <== isActive[i] * predicateEval[i].out;
        predicateResults[i] * (predicateResults[i] - 1) === 0;
    }
}
