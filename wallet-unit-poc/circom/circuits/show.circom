pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "components/expression.circom";

/// @title Show
/// @notice Verifies device binding and evaluates a logical expression over predicate results.
/// @param nClaims: number of claim field elements available for predicate references
/// @param maxPredicates: maximum number of predicates to evaluate
/// @param maxLogicTokens: capacity of the RPN token array for the logical expression
/// @param valueBits: bit width for claim/compare values in generalized predicates
///
/// Logical expression token encoding (postfix):
///   tokenTypes[i]: 0=REF, 1=AND, 2=OR, 3=NOT
///   tokenValues[i]: predicate index for REF, else 0
template Show(nClaims, maxPredicates, maxLogicTokens, valueBits) {
    signal input deviceKeyX; // Device binding public key x-coordinate.
    signal input deviceKeyY; // Device binding public key y-coordinate.
    signal input messageHash; // Scalar-field reduced hash of the verifier nonce.
    signal input sig_r; // ECDSA signature r value over messageHash.
    signal input sig_s_inverse; // Multiplicative inverse of signature s in the scalar field.

    // Generalized predicate phase inputs
    signal input predicateLen; // Number of active predicates.
    signal input claimValues[nClaims]; // Normalized claim values addressable by reference index.
    signal input predicateClaimRefs[maxPredicates]; // Left-hand claim reference per predicate.
    signal input predicateOps[maxPredicates]; // Operator per predicate: 0<=, 1>=, 2==.
    signal input predicateRhsIsRef[maxPredicates]; // Right-hand side (RHS) mode per predicate: 0=literal, 1=claim reference.
    signal input predicateRhsValues[maxPredicates]; // RHS operand: claim index when predicateRhsIsRef is 1, literal value when 0.
    signal input claimIdentifierHashes[nClaims]; // Attribute identity per slot, bound to MDOC via the shared segment.
    signal input predicateClaimIdentifiers[maxPredicates]; // Public: identity the verifier bound each predicate to.

    // Logical expression over predicate results in Reverse Polish Notation.
    signal input tokenTypes[maxLogicTokens]; // Postfix token kind: 0=REF, 1=AND, 2=OR, 3=NOT.
    signal input tokenValues[maxLogicTokens]; // Token payload: predicate index for REF tokens.
    signal input exprLen; // Number of active expression tokens.

    // Output: result of the logical expression over all predicate results
    signal output expressionResult;

    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== messageHash;
    ecdsa.pubKeyX <== deviceKeyX;
    ecdsa.pubKeyY <== deviceKeyY;

    // Evaluate generalized predicates and then the postfix boolean expression
    component expressionEval = ExpressionEvaluator(nClaims, maxPredicates, maxLogicTokens, valueBits);
    expressionEval.claimValues <== claimValues;
    expressionEval.predicateLen <== predicateLen;
    expressionEval.predicateClaimRefs <== predicateClaimRefs;
    expressionEval.predicateOps <== predicateOps;
    expressionEval.predicateRhsIsRef <== predicateRhsIsRef;
    expressionEval.predicateRhsValues <== predicateRhsValues;
    expressionEval.claimIdentifierHashes <== claimIdentifierHashes;
    expressionEval.predicateClaimIdentifiers <== predicateClaimIdentifiers;
    expressionEval.tokenTypes <== tokenTypes;
    expressionEval.tokenValues <== tokenValues;
    expressionEval.exprLen <== exprLen;
    expressionResult <== expressionEval.finalResult;
}

