import { WasmBridge } from "./wasm-bridge.js";
import { deserializeProofBundle } from "./prover.js";
import { buildShowStatementPublicValues } from "./inputs/show-statement.js";
import { DEFAULT_SHOW_PARAMS } from "./types.js";
import type {
  VerificationResult,
  VerifyingKeys,
  SerializedProof,
  ExpectedStatement,
} from "./types.js";

/**
 * Parse a Show public value (a serialized secq256r1 scalar) into a bigint.
 *
 * The WASM `verify` formats each scalar with Rust's `{:?}`, which renders ff
 * field elements as a big-endian `0x`-prefixed hex string. We extract that hex
 * run and parse it; a bare decimal string is accepted as a fallback.
 */
function parseScalar(value: string): bigint {
  if (!value) return 0n;
  const hex = value.match(/0x([0-9a-fA-F]+)/);
  if (hex) return BigInt("0x" + hex[1]);
  const dec = value.match(/-?\d+/);
  if (dec) return BigInt(dec[0]);
  return 0n;
}

export class Verifier {
  private bridge: WasmBridge;

  constructor(bridge: WasmBridge) {
    this.bridge = bridge;
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    let bundle;
    try {
      bundle = deserializeProofBundle(proof);
    } catch {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Invalid proof format",
      };
    }

    return this.verifyInternal(
      () =>
        this.bridge.verify(
          bundle.prepareProof,
          keys.prepareVerifyingKey,
          bundle.prepareInstance,
          bundle.showProof,
          keys.showVerifyingKey,
          bundle.showInstance,
        ),
      expected,
      startTime,
    );
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
    expected: ExpectedStatement,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    return this.verifyInternal(
      () =>
        this.bridge.verify(
          prepareProof,
          keys.prepareVerifyingKey,
          prepareInstance,
          showProof,
          keys.showVerifyingKey,
          showInstance,
        ),
      expected,
      startTime,
    );
  }

  /**
   * Run the SNARK verification, then bind the result to the verifier's expected
   * statement: recompute the Show proof's public values (nonce hash + compiled
   * predicate program) and require them to match the proof's public IO
   * index-by-index. Any mismatch fails verification, so a `valid` result also
   * means the proof was produced for this exact nonce and predicate program.
   */
  private async verifyInternal(
    runVerify: () => Promise<{
      valid: boolean;
      showPublicValues: string[];
      error?: string;
    }>,
    expected: ExpectedStatement,
    startTime: number,
  ): Promise<VerificationResult> {
    // Build the public-value vector the verifier expects from its own nonce and
    // predicate program (in circuit terms). No credential claims are consulted:
    // the verifier decides what statement it required, independent of anything
    // the holder discloses. A malformed expectation surfaces as an explicit
    // error rather than a silent mismatch.
    let expectedStatementValues: bigint[];
    try {
      expectedStatementValues = buildShowStatementPublicValues(
        DEFAULT_SHOW_PARAMS,
        expected.nonce,
        expected.predicates,
        expected.logicExpression,
      );
    } catch (e) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: `Invalid expected statement: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    const result = await runVerify();

    if (!result.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: result.error ?? "Proof verification failed",
      };
    }

    // Public IO layout: index 0 = expressionResult, indices 1.. = the bound
    // verifier statement (messageHash + predicate program).
    const publicValues = result.showPublicValues.map(parseScalar);
    const expressionResult = (publicValues[0] ?? 0n) !== 0n;

    const boundValues = publicValues.slice(1);
    if (boundValues.length !== expectedStatementValues.length) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: `Statement binding size mismatch: proof exposes ${boundValues.length} bound values, expected ${expectedStatementValues.length}`,
      };
    }

    for (let i = 0; i < expectedStatementValues.length; i++) {
      if (boundValues[i] !== expectedStatementValues[i]) {
        // Index 0 of the bound values is messageHash (freshness); the rest are
        // the predicate program (policy).
        const kind = i === 0 ? "nonce" : "policy";
        return {
          valid: false,
          expressionResult: null,
          deviceKey: null,
          verifyMs: performance.now() - startTime,
          error: `Statement binding mismatch (${kind}): proof was not generated for the expected nonce and policy`,
        };
      }
    }

    return {
      valid: true,
      expressionResult,
      deviceKey: null,
      verifyMs: performance.now() - startTime,
    };
  }
}
