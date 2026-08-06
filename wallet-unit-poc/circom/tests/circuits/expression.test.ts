import type { WitnessTester } from "circomkit";
import assert from "assert";
import { circomkit } from "../common/index.ts";

describe("ExpressionEvaluator", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("ExpressionEvaluator", {
      file: "components/expression",
      template: "ExpressionEvaluator",
      params: [3, 3, 8, 64],
      recompile: true,
    });
  });

  it("evaluates atomic predicates and combines them with AND", async () => {
    // Example:
    //   pred0: claim[0] <= 20080101  => 20000101 <= 20080101 => true
    //   pred1: claim[1] == 528       => 528 == 528           => true
    //   pred2: claim[2] >= 50000     => 60000 >= 50000       => true
    // Expression in postfix form: REF(0) REF(1) AND REF(2) AND
    // Equivalent boolean expression: (pred0 AND pred1) AND pred2
    const witness = await circuit.calculateWitness({
      claimValues: [20000101, 528, 60000],
      predicateLen: 3,
      predicateClaimRefs: [0, 1, 2],
      predicateOps: [0, 2, 1],
      predicateRhsIsRef: [0, 0, 0],
      predicateRhsValues: [20080101, 528, 50000],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 22, 33],
      predicateRhsClaimIdentifiers: [0, 0, 0],
      tokenTypes: [0, 0, 1, 0, 1, 0, 0, 0],
      tokenValues: [0, 1, 0, 2, 0, 0, 0, 0],
      exprLen: 5,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.deepStrictEqual(predicateResults.slice(0, 3), [1n, 1n, 1n]);
    assert.strictEqual(signals.finalResult, 1n);
  });

  it("supports OR and NOT over predicate references", async () => {
    // Example:
    //   pred0: claim[0] <= 20080101  => 20150101 <= 20080101 => false
    //   pred1: claim[1] == 528       => 840 == 528           => false
    // Expression in postfix form: REF(0) REF(1) NOT OR
    // Equivalent boolean expression: pred0 OR (NOT pred1)
    // With pred0 = false and pred1 = false, the result is false OR true => true.
    const witness = await circuit.calculateWitness({
      claimValues: [20150101, 840, 1000],
      predicateLen: 3,
      predicateClaimRefs: [0, 1, 2],
      predicateOps: [0, 2, 1],
      predicateRhsIsRef: [0, 0, 0],
      predicateRhsValues: [20080101, 528, 50000],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 22, 33],
      predicateRhsClaimIdentifiers: [0, 0, 0],
      // REF(0), REF(1), NOT, OR
      tokenTypes: [0, 0, 3, 2, 0, 0, 0, 0],
      tokenValues: [0, 1, 0, 0, 0, 0, 0, 0],
      exprLen: 4,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.deepStrictEqual(predicateResults.slice(0, 3), [0n, 0n, 0n]);
    assert.strictEqual(signals.finalResult, 1n);
  });

  it("returns false when an AND expression includes a false predicate", async () => {
    // Example:
    //   pred0: claim[0] <= 20080101  => 20000101 <= 20080101 => true
    //   pred1: claim[1] == 528       => 840 == 528           => false
    // Expression in postfix form: REF(0) REF(1) AND
    // Equivalent boolean expression: pred0 AND pred1 => true AND false => false.
    const witness = await circuit.calculateWitness({
      claimValues: [20000101, 840, 60000],
      predicateLen: 3,
      predicateClaimRefs: [0, 1, 2],
      predicateOps: [0, 2, 1],
      predicateRhsIsRef: [0, 0, 0],
      predicateRhsValues: [20080101, 528, 50000],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 22, 33],
      predicateRhsClaimIdentifiers: [0, 0, 0],
      tokenTypes: [0, 0, 1, 0, 0, 0, 0, 0],
      tokenValues: [0, 1, 0, 0, 0, 0, 0, 0],
      exprLen: 3,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.deepStrictEqual(predicateResults.slice(0, 3), [1n, 0n, 1n]);
    assert.strictEqual(signals.finalResult, 0n);
  });

  it("returns false for OR when all referenced predicates are false", async () => {
    // Example:
    //   pred0: claim[0] <= 20080101  => 20150101 <= 20080101 => false
    //   pred1: claim[1] == 528       => 840 == 528           => false
    // Expression in postfix form: REF(0) REF(1) OR
    // Equivalent boolean expression: pred0 OR pred1 => false OR false => false.
    const witness = await circuit.calculateWitness({
      claimValues: [20150101, 840, 1000],
      predicateLen: 3,
      predicateClaimRefs: [0, 1, 2],
      predicateOps: [0, 2, 1],
      predicateRhsIsRef: [0, 0, 0],
      predicateRhsValues: [20080101, 528, 50000],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 22, 33],
      predicateRhsClaimIdentifiers: [0, 0, 0],
      tokenTypes: [0, 0, 2, 0, 0, 0, 0, 0],
      tokenValues: [0, 1, 0, 0, 0, 0, 0, 0],
      exprLen: 3,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.deepStrictEqual(predicateResults.slice(0, 3), [0n, 0n, 0n]);
    assert.strictEqual(signals.finalResult, 0n);
  });

  it("double NOT preserves predicate truth value", async () => {
    // Example:
    //   pred0: claim[0] <= 20080101  => 20000101 <= 20080101 => true
    // Expression in postfix form: REF(0) NOT NOT
    // Equivalent boolean expression: NOT(NOT(pred0)) => pred0 => true.
    const witness = await circuit.calculateWitness({
      claimValues: [20000101, 528, 60000],
      predicateLen: 3,
      predicateClaimRefs: [0, 1, 2],
      predicateOps: [0, 2, 1],
      predicateRhsIsRef: [0, 0, 0],
      predicateRhsValues: [20080101, 528, 50000],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 22, 33],
      predicateRhsClaimIdentifiers: [0, 0, 0],
      tokenTypes: [0, 3, 3, 0, 0, 0, 0, 0],
      tokenValues: [0, 0, 0, 0, 0, 0, 0, 0],
      exprLen: 3,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["finalResult"]);
    assert.strictEqual(signals.finalResult, 1n);
  });

  it("rejects malformed postfix expressions with insufficient operands", async () => {
    // Example:
    //   token stream: REF(0) AND
    // AND is binary, so this postfix expression is invalid because there is
    // only one operand on the stack when AND is evaluated.
    await assert.rejects(
      circuit.calculateWitness({
        claimValues: [20000101, 528, 60000],
        predicateLen: 3,
        predicateClaimRefs: [0, 1, 2],
        predicateOps: [0, 2, 1],
        predicateRhsIsRef: [0, 0, 0],
        predicateRhsValues: [20080101, 528, 50000],
        claimIdentifierHashes: [0, 0, 0],
        predicateClaimIdentifiers: [0, 0, 0],
        // REF(0), AND is malformed because AND needs two operands.
        tokenTypes: [0, 1, 0, 0, 0, 0, 0, 0],
        tokenValues: [0, 0, 0, 0, 0, 0, 0, 0],
        exprLen: 2,
      })
    );
  });

  it("rejects expressions that reference a predicate index out of range", async () => {
    // Example:
    //   token stream: REF(3)
    // With MAX_PREDICATES = 3, only refs 0..2 are valid, so REF(3) must fail.
    await assert.rejects(
      circuit.calculateWitness({
        claimValues: [20000101, 528, 60000],
        predicateLen: 3,
        predicateClaimRefs: [0, 1, 2],
        predicateOps: [0, 2, 1],
        predicateRhsIsRef: [0, 0, 0],
        predicateRhsValues: [20080101, 528, 50000],
        claimIdentifierHashes: [0, 0, 0],
        predicateClaimIdentifiers: [0, 0, 0],
        tokenTypes: [0, 0, 0, 0, 0, 0, 0, 0],
        tokenValues: [3, 0, 0, 0, 0, 0, 0, 0],
        exprLen: 1,
      })
    );
  });

  it("rejects empty expressions (exprLen = 0)", async () => {
    await assert.rejects(
      circuit.calculateWitness({
        claimValues: [20000101, 528, 60000],
        predicateLen: 3,
        predicateClaimRefs: [0, 1, 2],
        predicateOps: [0, 2, 1],
        predicateRhsIsRef: [0, 0, 0],
        predicateRhsValues: [20080101, 528, 50000],
        claimIdentifierHashes: [0, 0, 0],
        predicateClaimIdentifiers: [0, 0, 0],
        tokenTypes: [0, 0, 0, 0, 0, 0, 0, 0],
        tokenValues: [0, 0, 0, 0, 0, 0, 0, 0],
        exprLen: 0,
      })
    );
  });

  it("ignores inactive predicate tuples beyond predicateLen", async () => {
    // Example:
    //   predicateLen = 1 means only pred0 is active.
    //   pred1/pred2 are intentionally malformed but must be ignored.
    // Expression: REF(0)
    const witness = await circuit.calculateWitness({
      claimValues: [20000101, 840, 1000],
      predicateLen: 1,
      predicateClaimRefs: [0, 99, 77],
      predicateOps: [0, 7, 9],
      predicateRhsIsRef: [0, 0, 0],
      predicateRhsValues: [20080101, 12345, 99999],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 22, 33],
      predicateRhsClaimIdentifiers: [0, 0, 0],
      tokenTypes: [0, 0, 0, 0, 0, 0, 0, 0],
      tokenValues: [0, 0, 0, 0, 0, 0, 0, 0],
      exprLen: 1,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.deepStrictEqual(predicateResults.slice(0, 3), [1n, 0n, 0n]);
    assert.strictEqual(signals.finalResult, 1n);
  });

  it("supports using another claim reference as the predicate RHS", async () => {
    // pred0: claim[0] >= claim[1] => 25 >= 18 => true
    // Expression: REF(0)
    const witness = await circuit.calculateWitness({
      claimValues: [25, 18, 999],
      predicateLen: 1,
      predicateClaimRefs: [0, 0, 0],
      predicateOps: [1, 2, 2],
      predicateRhsIsRef: [1, 0, 0],
      predicateRhsValues: [1, 0, 0],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 0, 0],
      predicateRhsClaimIdentifiers: [22, 0, 0],
      tokenTypes: [0, 0, 0, 0, 0, 0, 0, 0],
      tokenValues: [0, 0, 0, 0, 0, 0, 0, 0],
      exprLen: 1,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.strictEqual(predicateResults[0], 1n);
    assert.strictEqual(signals.finalResult, 1n);
  });

  it("supports mixed RHS modes across predicates in one expression", async () => {
    // pred0: claim[0] >= claim[1] => 30 >= 18 => true   (RHS is claim reference)
    // pred1: claim[2] == 59999    => 60000 == 59999 => false (RHS is literal)
    // Expression: REF(0) REF(1) OR
    const witness = await circuit.calculateWitness({
      claimValues: [30, 18, 60000],
      predicateLen: 2,
      predicateClaimRefs: [0, 2, 0],
      predicateOps: [1, 2, 2],
      predicateRhsIsRef: [1, 0, 0],
      predicateRhsValues: [1, 59999, 0],
      claimIdentifierHashes: [11, 22, 33],
      predicateClaimIdentifiers: [11, 33, 0],
      predicateRhsClaimIdentifiers: [22, 0, 0],
      tokenTypes: [0, 0, 2, 0, 0, 0, 0, 0],
      tokenValues: [0, 1, 0, 0, 0, 0, 0, 0],
      exprLen: 3,
    });

    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitnessSignals(witness, ["predicateResults", "finalResult"]);
    const predicateResults = signals.predicateResults as bigint[];

    assert.deepStrictEqual(predicateResults.slice(0, 2), [1n, 0n]);
    assert.strictEqual(signals.finalResult, 1n);
  });
});
