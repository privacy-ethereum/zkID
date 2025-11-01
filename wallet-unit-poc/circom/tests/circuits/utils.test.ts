import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { base64urlToBase64 } from "../../src/utils";

describe("DecodeSD circuit", () => {
  let circuit: WitnessTester<["sdBytes", "sdLen"], ["base64Out"]>;
  const maxLength = 50;
  const byteLength = 32;

  const sd1 = "JciGc5bKidOGmxjuvC8LdUykaVXBXBPhBX1kXpDe-Lo";
  const sd2 = "pVOw2Nj57G2NkeVHBCWwhEBjufSJhp9lp3m5W9mAh9A";

  before(async () => {
    circuit = await circomkit.WitnessTester("DecodeSD", {
      file: "utils/utils",
      template: "DecodeSD",
      params: [maxLength, byteLength],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  for (const [idx, sd] of [sd1, sd2].entries()) {
    it(`decodes sd${idx + 1} correctly`, async () => {
      const asciiCodes = Array.from(sd, (c) => c.charCodeAt(0));
      const sdLen = asciiCodes.length;
      while (asciiCodes.length < maxLength) asciiCodes.push(0);

      const b64 = base64urlToBase64(sd);
      const expected = Array.from(Buffer.from(b64, "base64"));

      let inputs = {
        sdBytes: asciiCodes,
        sdLen: sdLen,
      };
      await circuit.expectPass(inputs, { base64Out: expected });
    });
  }
});
