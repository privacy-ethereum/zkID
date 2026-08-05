pragma circom 2.2.3;

include "utils/es256.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "@zk-email/circuits/lib/sha.circom";
include "components/claim-decoder.circom";
include "utils/utils.circom";
include "components/payload_matcher.circom";
include "components/ec-extractor.circom";
include "components/claim-value-extractor.circom";
include "components/claim-value-normalizer.circom";

/// @title JWT
/// @notice Verifies an ES256-signed SD-JWT and extracts normalized claim values.
/// @notice match slots 0 and 1 are reserved for device binding key extraction (x/y patterns).
/// @notice PRECONDITION on the signed payload. Matching here is positional: the template
///         proves that a substring occurs at the supplied index, not that the index lies
///         at the JSON path the substring is meant to come from. The device binding key
///         and the disclosure digests are only well defined when each match has a single
///         possible position, so the decoded payload must satisfy:
///           - "x":" occurs exactly once, directly before cnf.jwk.x
///           - "y":" occurs exactly once, directly before cnf.jwk.y
///           - "_sd":[ occurs exactly once, so there is one disclosure array and no
///             nested ones
///           - every disclosure digest occurs exactly once, as an element of that array
///         A nested object with an x or y key, a nested _sd array, or a signed string
///         that repeats a digest each add a second position and leave the match
///         undetermined. The payload bytes are fixed by the ES256 check below, so this
///         is a property of what the issuer signed rather than of the witness, and it
///         holds for schemas reviewed against the rules above. assertUnambiguousPayload()
///         in openac-sdk/src/inputs/payload-anchors.ts enforces it before match indices
///         are built.
/// @notice Claim arrays are claim-only and map directly to normalizedClaimValues.
/// @notice pubKeyX/pubKeyY (the issuer key the ES256 check runs against) are public
///         inputs of the main component, so they appear in the proof's public IO and
///         a verifier can compare them against the issuers it trusts.
/// @notice decodeFlags/claimFormats are public inputs too. They decide how each claim
///         value in normalizedClaimValues was produced, so a verifier reading those
///         values needs them to know what the values mean: an undecoded slot holds 0
///         rather than the claim, and a slot decoded under one format is not
///         comparable to a literal in another.
/// @output normalizedClaimValues: one integer per claim slot; 0 for undecoded slots.
/// @output KeyBindingX, KeyBindingY: extracted device binding public key coordinates.
template JWT(
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    assert(maxMatches >= 2);
    var maxClaims = maxMatches - 2;
    var decodedLen = (maxClaimsLength * 3) / 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) / 4;
    var maxValueLen = decodedLen;

    signal input message[maxMessageLength];
    signal input messageLength;
    signal input periodIndex;

    signal input sig_r;
    signal input sig_s_inverse;
    signal input pubKeyX;
    signal input pubKeyY;

    signal input matchesCount;
    signal input matchSubstring[maxMatches][maxSubstringLength];
    signal input matchLength[maxMatches];
    signal input matchIndex[maxMatches];

    signal input claims[maxClaims][maxClaimsLength];
    signal input claimLengths[maxClaims];
    // decodeFlags[i] = 1 if claim slot i should be decoded and normalized, 0 otherwise.
    signal input decodeFlags[maxClaims];
    // claimFormats[i]: format for normalizing claim slot i (0=bool,1=uint,2=iso_date,3=roc_date,4=string).
    // Only meaningful when decodeFlags[i] = 1.
    signal input claimFormats[maxClaims];

    signal decodedClaims[maxClaims][decodedLen] <== ClaimDecoder(maxClaims, maxClaimsLength)(claims, claimLengths, decodeFlags);
    signal claimHashes[maxClaims][32] <== ClaimHasher(maxClaims, maxClaimsLength)(claims);

    signal claimMatchSubstring[maxClaims][maxSubstringLength];
    signal claimMatchLength[maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        for (var j = 0; j < maxSubstringLength; j++) {
            claimMatchSubstring[i][j] <== matchSubstring[i + 2][j];
        }
        claimMatchLength[i] <== matchLength[i + 2];
    }

    // Compare the claim hashes with the match substrings
    ClaimComparator(maxClaims, maxSubstringLength)(claimHashes, claimLengths, claimMatchSubstring, claimMatchLength);

    // Verify the issuer signature
    ES256(maxMessageLength)(message, messageLength, sig_r, sig_s_inverse, pubKeyX, pubKeyY);

    // Extract the payload
    signal payload[maxPayloadLength] <== PayloadExtractor(maxMessageLength, maxB64PayloadLength)(
        message,
        messageLength,
        periodIndex
    );

    // Check if the match substrings are in the payload
    signal payloadHash <== PayloadSubstringMatcher(maxPayloadLength, maxMatches, maxSubstringLength)(
        payload,
        matchesCount,
        matchSubstring,
        matchLength,
        matchIndex
    );

    // Extract the device binding public key from the payload
    component ecExtractor = ECPublicKeyExtractor_Optimized(maxPayloadLength, 32);
    ecExtractor.payload <== payload;
    ecExtractor.xStartIndex <== matchIndex[0] + matchLength[0];
    ecExtractor.yStartIndex <== matchIndex[1] + matchLength[1];

    // Extract and normalize claim values.
    // Claim arrays are claim-only. Each claim is extracted and normalized when decodeFlags[i]=1.
    component claimExtractors[maxClaims];
    component claimNormalizers[maxClaims];
    signal output normalizedClaimValues[maxClaims];

    for (var i = 0; i < maxClaims; i++) {
        claimExtractors[i] = ClaimValueExtractor(decodedLen);
        claimExtractors[i].claim    <== decodedClaims[i];
        claimExtractors[i].isActive <== decodeFlags[i];

        claimNormalizers[i] = ClaimValueNormalizer(maxValueLen);
        claimNormalizers[i].value       <== claimExtractors[i].value;
        claimNormalizers[i].valueLength <== claimExtractors[i].valueLength;
        claimNormalizers[i].format      <== claimFormats[i];

        normalizedClaimValues[i] <== claimNormalizers[i].normalizedValue;
    }

    // Output the device binding public key
    signal output KeyBindingX <== ecExtractor.pubKeyX;
    signal output KeyBindingY <== ecExtractor.pubKeyY;
}
