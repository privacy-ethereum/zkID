import { describe, expect, it } from "vitest";

import { transition, type AppEvent, type AppState, type ProvingRun } from "./store";

function makeRun(overrides: Partial<ProvingRun> = {}): ProvingRun {
  return {
    challenge: "215078321887317284868454961554019057364",
    certChainType: "rs2048",
    certProofBytes: new Uint8Array([1, 2, 3]),
    userSigProofBytes: new Uint8Array([4, 5, 6]),
    certKind: "certChainRS2048",
    provingMs: 1234,
    ...overrides,
  };
}

describe("transition", () => {
  it("landing + start → setup", () => {
    expect(transition({ phase: "landing" }, { type: "start" })).toEqual({
      phase: "setup",
    });
  });

  it("setup + setup_complete → ready", () => {
    expect(
      transition({ phase: "setup" }, { type: "setup_complete" }),
    ).toEqual({ phase: "ready" });
  });

  it("ready + start_proving → proving with startedAt", () => {
    const next = transition({ phase: "ready" }, { type: "start_proving" });
    expect(next.phase).toBe("proving");
    if (next.phase === "proving") {
      expect(typeof next.startedAt).toBe("number");
    }
  });

  it("proving + proving_complete → review carries run", () => {
    const run = makeRun();
    const next = transition(
      { phase: "proving", startedAt: 0 },
      { type: "proving_complete", run },
    );
    expect(next.phase).toBe("review");
    if (next.phase === "review") {
      expect(next.run).toBe(run);
    }
  });

  it("review + send_proof → submitting preserves run", () => {
    const run = makeRun();
    const next = transition(
      { phase: "review", run },
      { type: "send_proof" },
    );
    expect(next.phase).toBe("submitting");
    if (next.phase === "submitting") {
      expect(next.run).toBe(run);
      expect(typeof next.startedAt).toBe("number");
    }
  });

  it("submitting + submit_complete → result carries both timings", () => {
    const run = makeRun({ provingMs: 500 });
    const next = transition(
      { phase: "submitting", run, startedAt: 0 },
      { type: "submit_complete", verified: true, submitMs: 200 },
    );
    expect(next).toEqual({
      phase: "result",
      verified: true,
      provingMs: 500,
      submitMs: 200,
    });
  });

  it("submit_complete threads server nullifier + parsed inputs into result", () => {
    const parsed = {
      challenge: "0xdead",
      pkCommit: "0x2",
      nullifier: "0xabc",
      smt_root: "0xbeef",
      issuerRsaModulus: ["0xaa", "0xbb"],
    };
    const next = transition(
      { phase: "submitting", run: makeRun(), startedAt: 0 },
      {
        type: "submit_complete",
        verified: true,
        submitMs: 10,
        nullifier: "0xabc",
        parsedInputs: parsed,
      },
    );
    if (next.phase !== "result") throw new Error("expected result phase");
    expect(next.nullifier).toBe("0xabc");
    expect(next.parsedInputs).toEqual(parsed);
  });

  it("review + retry_proving → setup (strict single-use: re-verify PIN)", () => {
    const next = transition(
      { phase: "review", run: makeRun() },
      { type: "retry_proving" },
    );
    expect(next).toEqual({ phase: "setup" });
  });

  it("result + retry_proving → setup (strict single-use: re-verify PIN)", () => {
    const next = transition(
      { phase: "result", verified: true, provingMs: 1, submitMs: 2 },
      { type: "retry_proving" },
    );
    expect(next).toEqual({ phase: "setup" });
  });

  it("ready + reset_to_setup → setup", () => {
    expect(
      transition({ phase: "ready" }, { type: "reset_to_setup" }),
    ).toEqual({ phase: "setup" });
  });

  it("review + reset_to_setup → setup", () => {
    expect(
      transition(
        { phase: "review", run: makeRun() },
        { type: "reset_to_setup" },
      ),
    ).toEqual({ phase: "setup" });
  });

  it("proving + reset_to_setup → setup (cancel)", () => {
    expect(
      transition(
        { phase: "proving", startedAt: 123 },
        { type: "reset_to_setup" },
      ),
    ).toEqual({ phase: "setup" });
  });

  it("pipeline_error routes active phases to error", () => {
    const activePhases: AppState[] = [
      { phase: "setup" },
      { phase: "ready" },
      { phase: "proving", startedAt: 0 },
      { phase: "review", run: makeRun() },
      { phase: "submitting", run: makeRun(), startedAt: 0 },
    ];
    for (const s of activePhases) {
      expect(
        transition(s, { type: "pipeline_error", where: "x", message: "y" }),
      ).toEqual({ phase: "error", where: "x", message: "y" });
    }
  });

  it("pipeline_error from terminal phases is ignored", () => {
    const terminals: AppState[] = [
      { phase: "landing" },
      { phase: "result", verified: true, provingMs: 1, submitMs: 2 },
      { phase: "error", where: "x", message: "y" },
    ];
    for (const s of terminals) {
      expect(
        transition(s, { type: "pipeline_error", where: "a", message: "b" }),
      ).toEqual(s);
    }
  });

  it("any + reset → landing", () => {
    const states: AppState[] = [
      { phase: "setup" },
      { phase: "ready" },
      { phase: "proving", startedAt: 0 },
      { phase: "review", run: makeRun() },
      { phase: "submitting", run: makeRun(), startedAt: 0 },
      { phase: "result", verified: false, provingMs: 10, submitMs: 5 },
      { phase: "error", where: "x", message: "y" },
    ];
    for (const s of states) {
      expect(transition(s, { type: "reset" })).toEqual({ phase: "landing" });
    }
  });

  it("illegal transitions return current state unchanged", () => {
    const cases: Array<[AppState, AppEvent]> = [
      // start only valid from landing.
      [{ phase: "setup" }, { type: "start" }],
      [{ phase: "ready" }, { type: "start" }],
      // setup_complete only valid from setup.
      [{ phase: "landing" }, { type: "setup_complete" }],
      [{ phase: "ready" }, { type: "setup_complete" }],
      // start_proving only valid from ready.
      [{ phase: "setup" }, { type: "start_proving" }],
      [{ phase: "proving", startedAt: 0 }, { type: "start_proving" }],
      // proving_complete only valid from proving.
      [{ phase: "ready" }, { type: "proving_complete", run: makeRun() }],
      // send_proof only valid from review.
      [{ phase: "ready" }, { type: "send_proof" }],
      [
        { phase: "proving", startedAt: 0 },
        { type: "send_proof" },
      ],
      // submit_complete only valid from submitting.
      [
        { phase: "review", run: makeRun() },
        { type: "submit_complete", verified: true, submitMs: 1 },
      ],
      // retry_proving only valid from review / result.
      [{ phase: "ready" }, { type: "retry_proving" }],
      [{ phase: "landing" }, { type: "retry_proving" }],
      // reset_to_setup not valid from landing / submitting / result / error.
      [{ phase: "landing" }, { type: "reset_to_setup" }],
      [
        { phase: "submitting", run: makeRun(), startedAt: 0 },
        { type: "reset_to_setup" },
      ],
    ];
    for (const [state, event] of cases) {
      expect(transition(state, event)).toEqual(state);
    }
  });
});
