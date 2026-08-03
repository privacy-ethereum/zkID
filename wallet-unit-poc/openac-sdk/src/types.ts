export interface OpenACConfig {
  wasmPath?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  wasmModule?: any;
  assetsDir?: string;
  artifacts?: CircuitArtifacts;
  memory?: { initial?: number; maximum?: number };
  keysBaseUrl?: string;
}

export interface CircuitArtifacts {
  prepareR1cs?: Uint8Array | string;
  showR1cs?: Uint8Array | string;
  prepareWitnessWasm?: Uint8Array | string;
  showWitnessWasm?: Uint8Array | string;
}

export interface JwtCircuitParams {
  maxMessageLength: number;
  maxB64PayloadLength: number;
  maxMatches: number;
  maxSubstringLength: number;
  maxClaimLength: number;
}

export interface ShowCircuitParams {
  nClaims: number;
  maxPredicates: number;
  maxLogicTokens: number;
  valueBits: number;
}

export const DEFAULT_JWT_PARAMS: JwtCircuitParams = {
  maxMessageLength: 1920,
  maxB64PayloadLength: 1900,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

export const DEFAULT_SHOW_PARAMS: ShowCircuitParams = {
  nClaims: 2,
  maxPredicates: 2,
  maxLogicTokens: 8,
  valueBits: 64,
};

export interface EcdsaPublicKey {
  kty: "EC";
  crv: "P-256";
  x: string; // base64url-encoded X coordinate
  y: string; // base64url-encoded Y coordinate
  kid?: string;
}

export type EcdsaPrivateKey = string | Uint8Array;

export interface PemPublicKey {
  pem: string;
}

export type IssuerPublicKey = EcdsaPublicKey | PemPublicKey;

export interface ProofPublicValues {
  expressionResult: boolean;
  normalizedClaimValues: bigint[];
}

export interface VerifyingKeys {
  prepareVerifyingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
}

/**
 * The verifier's expected statement, required by all verification APIs. The
 * verifier recomputes the Show proof's public values (nonce hash + predicate
 * program) from this and rejects any proof whose public values do not match, so
 * a valid proof also confirms it was produced for exactly this nonce and this
 * policy, not merely that some hidden predicate over the linked credential was
 * true for some hidden nonce.
 *
 * The verifier authors the policy and issues the nonce, so it supplies the
 * predicate program in the circuit's own (claim-index) terms. It does NOT take
 * the holder's disclosed claims: the statement the verifier requires is decided
 * by the verifier, independent of anything the holder discloses. A verifier that
 * prefers the name-based DSL can compile it once against its credential schema
 * via `compilePredicateExpression` and reuse the resulting `predicates` /
 * `logicExpression` here.
 *
 * Covers freshness and policy only. Issuer trust is not part of the expected
 * statement: `verify()` reports the issuer key and leaves the decision to the
 * caller. See `VerificationResult.issuerKey`.
 */
export interface ExpectedStatement {
  /** The exact nonce/challenge the verifier issued for this session (freshness). */
  nonce: string;
  /** The required predicate program, in circuit (claim-index) form. */
  predicates: import("./inputs/show-input-builder.js").PredicateSpec[];
  /** Postfix logic expression over predicate results (REF/AND/OR/NOT). */
  logicExpression: Array<{ type: number; value: number }>;
}

/**
 * The issuer key a presentation was built under, read out of the Prepare proof's
 * public IO. Given as both curve coordinates and a canonical P-256 JWK so it can
 * be compared against a trust store holding either form.
 */
export interface ProvenIssuerKey {
  /** Issuer public key x-coordinate, as proven in the circuit. */
  x: bigint;
  /** Issuer public key y-coordinate, as proven in the circuit. */
  y: bigint;
  /** The same point as a canonical P-256 JWK (32-byte base64url coordinates). */
  jwk: EcdsaPublicKey;
}

export interface VerificationResult {
  /**
   * The proofs verified and are bound to the expected nonce and policy.
   *
   * Does not cover issuer identity. The circuit checks the credential signature
   * against whatever key was supplied at proving time, so `valid` alone means
   * "signed by some P-256 key", not "signed by an issuer you trust". Check
   * `issuerKey` as well before acting on the result.
   */
  valid: boolean;
  expressionResult: boolean | null;
  /**
   * The issuer key this presentation was proven under. Non-null exactly when
   * `valid` is true.
   *
   * Compare it against the issuer keys your deployment trusts, resolved from
   * your own configuration by expected `iss`/`kid`/credential type rather than
   * from anything the holder sent. A credential signed by a key outside that set
   * still verifies, so this comparison is what establishes issuer identity:
   *
   * ```ts
   * const result = await openac.verify(proof, vks, expected);
   * if (!result.valid || !result.issuerKey) return reject(result.error);
   * if (!myTrustStore.isTrustedIssuer(result.issuerKey.jwk)) return reject();
   * // only now is result.expressionResult meaningful
   * ```
   */
  issuerKey: ProvenIssuerKey | null;
  /** Always null. The device-key binding flows through comm_W_shared, not a public output. */
  deviceKey: null;
  verifyMs: number;
  error?: string;
}

export interface KeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
  verifyingKeys(): VerifyingKeys;
  serialize(): SerializedKeySet;
}

export interface SerializedKeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
}

export interface SerializedProofJSON {
  version: string;
  prepareProof: string; // base64
  showProof: string; // base64
  prepareInstance: string; // base64
  showInstance: string; // base64
  publicValues: {
    expressionResult: boolean;
  };
}

export type SerializedProof = Uint8Array;

export type ErrorCode =
  | "SETUP_FAILED"
  | "KEYS_NOT_FOUND"
  | "PROOF_GENERATION_FAILED"
  | "WITNESS_GENERATION_FAILED"
  | "REBLIND_FAILED"
  | "VERIFICATION_FAILED"
  | "INVALID_PROOF_FORMAT"
  | "COMMITMENT_MISMATCH"
  | "INVALID_JWT"
  | "INVALID_KEY"
  | "INVALID_SIGNATURE"
  | "MISSING_DISCLOSURE"
  | "BIRTHDAY_NOT_FOUND"
  | "CLAIM_NOT_FOUND"
  | "PARAMS_EXCEEDED"
  | "WASM_LOAD_FAILED"
  | "WASM_OOM"
  | "WASM_NOT_INITIALIZED";

export interface DisclosedClaim {
  index: number;
  salt: string;
  name: string;
  value: string;
  raw: string;
  digest: string; // SHA-256 of disclosure (base64url, matches _sd array)
}

export interface WasmExports {
  setup_prepare(
    r1csBytes: Uint8Array,
  ): Promise<{ pk: Uint8Array; vk: Uint8Array }>;
  setup_show(
    r1csBytes: Uint8Array,
  ): Promise<{ pk: Uint8Array; vk: Uint8Array }>;

  prove_prepare(
    pk: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;
  prove_show(
    pk: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;

  reblind(
    pk: Uint8Array,
    instance: Uint8Array,
    witness: Uint8Array,
    blinds: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;

  verify(
    proof: Uint8Array,
    vk: Uint8Array,
  ): Promise<{ valid: boolean; publicValues: bigint[] }>;

  generate_shared_blinds(count: number): Promise<Uint8Array>;

  generate_witness(
    inputsJson: string,
    circuitWasm: Uint8Array,
  ): Promise<Uint8Array>;
}

export interface JwtCircuitInputs {
  sig_r: bigint;
  sig_s_inverse: bigint;
  pubKeyX: bigint;
  pubKeyY: bigint;
  message: bigint[];
  messageLength: number;
  periodIndex: number;
  matchesCount: number;
  matchSubstring: bigint[][];
  matchLength: number[];
  matchIndex: number[];
  claims: bigint[][];
  claimLengths: bigint[];
  decodeFlags: number[];
  claimFormats: bigint[];
}

export interface ShowCircuitInputs {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
  predicateLen: bigint;
  claimValues: bigint[];
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
}

export interface PrecomputeRequest {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: IssuerPublicKey;
  keys: KeySet;

  /** Predicates the holder wants to prove. Drives format inference and vcSize selection. */
  predicates: import("./predicates.js").PredicateExpression;
}

export interface SerializedCredential {
  jwt: string;
  disclosures: string[];
  deviceBindingKey: EcdsaPublicKey;
}

export interface PrecomputedCredential {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  prepareWitness: Uint8Array;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  /**
   * Normalized claim values extracted from the JWT circuit witness. Required
   * input to the Show circuit's predicate evaluation. Consumers that use the
   * typed predicate DSL never need to read this; `present()` consumes it
   * internally. Exposed so cached credentials survive serialize/deserialize.
   */
  normalizedClaimValues: bigint[];
  timing: PrecomputeTiming;
  serialize(): Uint8Array;
  toJSON(): SerializedPrecomputedCredentialJSON;
}

export interface PrecomputeTiming {
  parseCredentialMs: number;
  buildInputsMs: number;
  prepareWitnessMs: number;
  prepareProveMs: number;
  totalMs: number;
}

export interface SerializedPrecomputedCredentialJSON {
  version: string;
  prepareProof: string;
  prepareInstance: string;
  prepareWitness: string;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  normalizedClaimValues: string[]; // bigints serialized as decimal strings
}

export interface PresentRequest {
  precomputed: PrecomputedCredential;
  verifierNonce: string;
  devicePrivateKey: EcdsaPrivateKey;
  keys: KeySet;

  /** Predicates to evaluate against the precomputed credential. */
  predicates: import("./predicates.js").PredicateExpression;
}

export interface PresentationProof {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
  publicValues: ProofPublicValues;
  timing: PresentationTiming;
  serialize(): Uint8Array;
  toBase64(): string;
  toJSON(): SerializedProofJSON;
}

export interface PresentationTiming {
  showWitnessMs: number;
  showProveMs: number;
  presentMs: number;
  totalMs: number;
}
