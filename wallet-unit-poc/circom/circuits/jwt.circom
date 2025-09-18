pragma circom 2.1.6;

include "es256.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "@zk-email/circuits/lib/sha.circom";
include "claim-decoder.circom";
include "age-verifier.circom";
include "utils.circom";
include "payload_matcher.circom";
include "ec-extractor.circom";

// Prepare Circuit
template JWT(
    maxMessageLength,
    maxB64HeaderLength,
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

    component es256 = ES256(maxMessageLength);
    es256.message <== message;
    es256.messageLength <== messageLength;
    es256.sig_r <== sig_r;
    es256.sig_s_inverse <== sig_s_inverse;
    es256.pubKeyX <== pubKeyX;
    es256.pubKeyY <== pubKeyY;

    component extractor = HeaderPayloadExtractor(maxMessageLength,maxB64HeaderLength, maxB64PayloadLength);
    extractor.message <== message;
    extractor.messageLength <== messageLength;
    extractor.periodIndex <== periodIndex;    


    signal payloadHash <== PayloadSubstringMatcher(maxPayloadLength, maxMatches, maxSubstringLength)(
        extractor.payload,
        matchesCount,
        matchSubstring,
        matchLength,
        matchIndex
    );

    signal xValueStart <== matchIndex[0] + matchLength[0];
    signal yValueStart <== matchIndex[1] + matchLength[1];

    // 32-byte coordinate -> ceil(32 * 4 / 3) = 43 base64url chars
    signal xValueEnd <== xValueStart + 43;
    signal yValueEnd <== yValueStart + 43; 

    component ecExtractor = ECPublicKeyExtractor(maxPayloadLength, maxClaimsLength, 43, 32);
    ecExtractor.payload <== extractor.payload;
    ecExtractor.xStartIndex <== xValueStart;
    ecExtractor.yStartIndex <== yValueStart;

    signal output KeyBindingX <== ecExtractor.pubKeyX;
    signal output KeyBindingY <== ecExtractor.pubKeyY;
}
