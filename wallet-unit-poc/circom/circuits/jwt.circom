pragma circom 2.2.3;

include "utils/es256.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "@zk-email/circuits/lib/sha.circom";
include "components/claim-decoder.circom";
include "utils/utils.circom";
include "components/payload_matcher.circom";
include "components/ec-extractor.circom";
include "components/age-verifier.circom";

template JWT(
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    var decodedLen = (maxClaimsLength * 3) / 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) / 4;

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

    signal input claims[maxMatches][maxClaimsLength];
    signal input claimLengths[maxMatches];
    signal input decodeFlags[maxMatches];
    signal input ageClaimIndex;

    signal decodedClaims[maxMatches][decodedLen] <== ClaimDecoder(maxMatches, maxClaimsLength)(claims, claimLengths, decodeFlags);
    signal claimHashes[maxMatches][32] <== ClaimHasher(maxMatches, maxClaimsLength)(claims);
    
    // Compare the claim hashes with the match substrings
    ClaimComparator(maxMatches, maxSubstringLength)(claimHashes ,claimLengths, matchSubstring, matchLength);

    // Verify the signature
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

    // Extract the device binding public key
    component ecExtractor = ECPublicKeyExtractor_Optimized(maxPayloadLength, 32);
    ecExtractor.payload <== payload;
    ecExtractor.xStartIndex <== matchIndex[0] + matchLength[0];
    ecExtractor.yStartIndex <== matchIndex[1] + matchLength[1];

    component ageSelector = Multiplexer(decodedLen, maxMatches);
    ageSelector.sel <== ageClaimIndex;
    ageSelector.inp <== decodedClaims;

    // Output the age claim
    signal output ageClaim[decodedLen] <== ageSelector.out;
    
    // Output the key binding public key
    signal output KeyBindingX <== ecExtractor.pubKeyX;
    signal output KeyBindingY <== ecExtractor.pubKeyY;
}
