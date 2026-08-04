pragma circom 2.2.3;

include "eval-predicates.circom";
include "logical-expressions.circom";

/// @title ExpressionEvaluator
/// @notice Two-phase generalized predicate evaluation.
/// @dev Phase 1: evaluate atomic predicates over claim values.
/// @dev Phase 2: evaluate a postfix boolean expression over predicate results.
/// @dev Claims are referenced by integer indices into `claimValues`.
/// @dev Claim values must already be canonically encoded as field elements.
template ExpressionEvaluator(N_CLAIMS, MAX_PREDICATES, MAX_EXPR_TOKENS, VALUE_BITS) {
    signal input claimValues[N_CLAIMS]; // Canonically normalized claim values.

    // Predicate tuples: [claimRef, op, rhsIsRef, rhsRef, rhsValue]
    signal input predicateLen; // Number of active predicate tuples.
    signal input predicateClaimRefs[MAX_PREDICATES]; // Left-hand claim reference per predicate.
    signal input predicateOps[MAX_PREDICATES]; // Operator per predicate: 0<=, 1>=, 2==.
    signal input predicateRhsIsRef[MAX_PREDICATES]; // Right-hand side (RHS) mode: 0=literal, 1=claim reference.
    signal input predicateRhsValues[MAX_PREDICATES]; // RHS operand: claim index when predicateRhsIsRef is 1, literal value when 0.
    signal input claimIdentifierHashes[N_CLAIMS]; // Attribute identity per slot.
    signal input predicateClaimIdentifiers[MAX_PREDICATES]; // Identity the policy requires.

    // Postfix expression token arrays.
    // tokenTypes[i]: 0=REF, 1=AND, 2=OR, 3=NOT
    // tokenValues[i]: predicate index for REF, else 0
    signal input tokenTypes[MAX_EXPR_TOKENS]; // Postfix token kind: 0=REF, 1=AND, 2=OR, 3=NOT.
    signal input tokenValues[MAX_EXPR_TOKENS]; // Token payload: predicate index for REF tokens.
    signal input exprLen; // Number of active logical-expression tokens.

    signal output predicateResults[MAX_PREDICATES];
    signal output finalResult;

    component predicatePhase = EvalPredicates(N_CLAIMS, MAX_PREDICATES, VALUE_BITS);
    predicatePhase.claimValues <== claimValues;
    predicatePhase.predicateLen <== predicateLen;
    predicatePhase.predicateClaimRefs <== predicateClaimRefs;
    predicatePhase.predicateOps <== predicateOps;
    predicatePhase.predicateRhsIsRef <== predicateRhsIsRef;
    predicatePhase.predicateRhsValues <== predicateRhsValues;
    predicatePhase.claimIdentifierHashes <== claimIdentifierHashes;
    predicatePhase.predicateClaimIdentifiers <== predicateClaimIdentifiers;

    predicateResults <== predicatePhase.predicateResults;

    component logicPhase = EvalLogicPostfix(MAX_EXPR_TOKENS, MAX_PREDICATES);
    logicPhase.predicateResults <== predicateResults;
    logicPhase.tokenTypes <== tokenTypes;
    logicPhase.tokenValues <== tokenValues;
    logicPhase.exprLen <== exprLen;

    finalResult <== logicPhase.out;
}
