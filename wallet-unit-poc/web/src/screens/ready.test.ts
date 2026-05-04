import { describe, expect, it } from "vitest";

import type { ChallengeState } from "../challenge-state";
import { startButtonStateFor } from "./ready";

describe("ready screen / startButtonStateFor", () => {
  it("disables the button while pending or fetching", () => {
    const pending: ChallengeState = { status: "pending" };
    const fetching: ChallengeState = { status: "fetching" };
    expect(startButtonStateFor(pending).disabled).toBe(true);
    expect(startButtonStateFor(fetching).disabled).toBe(true);
  });

  it("enables Start proving once a challenge is ready", () => {
    const ready: ChallengeState = {
      status: "ready",
      challenge: {
        challenge: "1",
        app_id: "deadbeefcafebabe1234567890abcde",
        expires_at: "2099-01-01T00:00:00Z",
      },
    };
    const s = startButtonStateFor(ready);
    expect(s.disabled).toBe(false);
    expect(s.label).toBe("Start proving");
  });

  // Regression: the error state must keep the button enabled, otherwise the
  // "Retry challenge" label is a lie — disabled buttons swallow click events
  // before they can reach onStart's refetch path.
  it("keeps the button enabled in the error state so retry actually fires", () => {
    const errored: ChallengeState = {
      status: "error",
      message: "POST /challenge returned 503 Unavailable",
    };
    const s = startButtonStateFor(errored);
    expect(s.disabled).toBe(false);
    expect(s.label).toBe("Retry challenge");
  });
});
