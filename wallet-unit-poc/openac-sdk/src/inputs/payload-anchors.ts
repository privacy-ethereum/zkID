import { InputError } from "../errors.js";
import { Credential } from "../credential.js";

// The JWT circuit locates the device binding key and the disclosure digests by
// substring match over the decoded payload. It does not parse JSON, so a match
// constrains the index to point at those bytes and says nothing about the JSON
// path the index falls in. The index a match resolves to is therefore only well
// defined when the payload offers a single position for it.
//
// This module checks that condition on the payload the circuit will run over:
// each device key anchor occurs once and directly precedes the cnf.jwk
// coordinate, and each disclosure digest occurs once, as an element of the
// credential's _sd array. The payload is fixed by the issuer signature the
// circuit verifies, so the condition is a property of the credential and is
// checked here once, before jwt-input-builder.ts derives the match indices.
//
// See the PRECONDITION notice on the JWT template in circom/circuits/jwt.circom.

/** Match patterns for the device binding key coordinates, in circuit slot order. */
export const DEVICE_KEY_ANCHORS = ['"x":"', '"y":"'] as const;

const SD_ANCHOR = '"_sd":[';

/**
 * Reject payloads where the circuit's substring matches would be ambiguous.
 *
 * @param credential parsed credential, used for the `cnf.jwk` coordinates
 * @param decodedPayload the decoded JWS payload the circuit matches against
 * @param digests the disclosure digests passed as additional match patterns
 */
export function assertUnambiguousPayload(
  credential: Credential,
  decodedPayload: string,
  digests: string[],
): void {
  const jwk = credential.deviceBindingKey;
  if (!jwk) {
    throw new InputError(
      "AMBIGUOUS_PAYLOAD",
      "Payload has no P-256 cnf.jwk, so the extracted device binding key would not be the credential's",
    );
  }

  assertDeviceKeyAnchor(decodedPayload, DEVICE_KEY_ANCHORS[0], jwk.x, "x");
  assertDeviceKeyAnchor(decodedPayload, DEVICE_KEY_ANCHORS[1], jwk.y, "y");

  const sdSpan = sdArraySpan(decodedPayload);

  for (const digest of digests) {
    const occurrences = occurrenceIndices(decodedPayload, digest);
    if (occurrences.length === 0) {
      throw new InputError(
        "CLAIM_NOT_FOUND",
        `Disclosure digest "${digest}" not found in JWT payload`,
      );
    }
    if (occurrences.length > 1) {
      throw new InputError(
        "AMBIGUOUS_PAYLOAD",
        `Disclosure digest "${digest}" occurs ${occurrences.length} times in the payload; the matched occurrence is not determined`,
      );
    }

    const start = occurrences[0]!;
    const end = start + digest.length;
    const quoted =
      decodedPayload[start - 1] === '"' && decodedPayload[end] === '"';
    if (!quoted || start < sdSpan.start || end > sdSpan.end) {
      throw new InputError(
        "AMBIGUOUS_PAYLOAD",
        `Disclosure digest "${digest}" is not an element of the credential's _sd array`,
      );
    }
  }
}

// The anchor must occur once, and the bytes the circuit reads after it must be
// the coordinate from cnf.jwk. Uniqueness alone leaves open that the single
// occurrence is some other object's `x`; comparing the value closes that.
function assertDeviceKeyAnchor(
  decodedPayload: string,
  anchor: string,
  coordinate: string,
  label: string,
): void {
  const occurrences = occurrenceIndices(decodedPayload, anchor);
  if (occurrences.length !== 1) {
    throw new InputError(
      "AMBIGUOUS_PAYLOAD",
      `Anchor ${anchor} occurs ${occurrences.length} times in the payload; the device binding key ${label} coordinate is not determined`,
    );
  }

  const start = occurrences[0]! + anchor.length;
  if (decodedPayload.slice(start, start + coordinate.length) !== coordinate) {
    throw new InputError(
      "AMBIGUOUS_PAYLOAD",
      `Anchor ${anchor} does not precede the cnf.jwk ${label} coordinate`,
    );
  }
}

// Digests are base64url, so they contain no `]` and the first `]` after the
// anchor closes the array.
function sdArraySpan(decodedPayload: string): { start: number; end: number } {
  const occurrences = occurrenceIndices(decodedPayload, SD_ANCHOR);
  if (occurrences.length !== 1) {
    throw new InputError(
      "AMBIGUOUS_PAYLOAD",
      `Anchor ${SD_ANCHOR} occurs ${occurrences.length} times in the payload; the disclosure digest set is not determined`,
    );
  }

  const start = occurrences[0]! + SD_ANCHOR.length;
  const end = decodedPayload.indexOf("]", start);
  if (end === -1) {
    throw new InputError(
      "AMBIGUOUS_PAYLOAD",
      "Unterminated _sd array in the payload",
    );
  }

  return { start, end };
}

function occurrenceIndices(haystack: string, needle: string): number[] {
  const found: number[] = [];
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return found;
    found.push(at);
    from = at + 1;
  }
}
