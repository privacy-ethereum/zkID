pragma circom 2.1.6;

include "es256.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "@zk-email/circuits/lib/sha.circom";
include "claim-decoder.circom";
include "utils.circom";
include "payload_matcher.circom";
include "ec-extractor.circom";

// Prepare Circuit
template JWT(
    maxMessageLength,
    maxB64PayloadLength,

    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    var decodedLen = (maxClaimsLength * 3) / 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) / 4;

    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input periodIndex; // Index of the period in the JWT message

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

   
    signal decodedClaims[maxMatches][decodedLen] <== ClaimDecoder(maxMatches, maxClaimsLength)(claims, claimLengths, decodeFlags);
    signal claimHashes[maxMatches][32] <== ClaimHasher(maxMatches, maxClaimsLength)(claims);
    ClaimComparator(maxMatches, maxSubstringLength)(claimHashes ,claimLengths, matchSubstring, matchLength);

    // Verify the signature
    ES256(maxMessageLength)(message, messageLength, sig_r, sig_s_inverse, pubKeyX, pubKeyY);

    signal payload[maxPayloadLength] <== PayloadExtractor(maxMessageLength, maxB64PayloadLength)(message, messageLength, periodIndex);

    signal payloadHash <== PayloadSubstringMatcher(maxPayloadLength, maxMatches, maxSubstringLength)(
        payload,
        matchesCount,
        matchSubstring,
        matchLength,
        matchIndex
    );

  
    component ecExtractor = ECPublicKeyExtractor_Optimized(maxPayloadLength, 32);
    ecExtractor.payload <== payload;
    ecExtractor.xStartIndex <==  matchIndex[0] + matchLength[0];
    ecExtractor.yStartIndex <==  matchIndex[1] + matchLength[1];


    signal output KeyBindingX <== ecExtractor.pubKeyX;
    signal output KeyBindingY <== ecExtractor.pubKeyY;

    signal output messages[maxMatches][decodedLen];
    messages <== decodedClaims; 
}
