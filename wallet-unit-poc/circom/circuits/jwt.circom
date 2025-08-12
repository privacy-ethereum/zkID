pragma circom 2.1.6;

include "es256.circom";
include "jwt_tx_builder/header-payload-extractor.circom";
include "jwt_tx_builder/array.circom";
include "keyless_zk_proofs/arrays.circom";
include "@zk-email/circuits/lib/sha.circom";
include "claim-decoder.circom";
include "age-verifier.circom";
include "utils.circom";

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

    component claimDecoder = ClaimDecoder(maxMatches, maxClaimsLength);
    claimDecoder.claims <== claims;
    claimDecoder.claimLengths <== claimLengths;
    claimDecoder.decodeFlags <== decodeFlags;


    component claimHasher = ClaimHasher(maxMatches, maxClaimsLength);
    claimHasher.claims <== claims;
           
    ClaimComparator(maxMatches, maxSubstringLength)(claimHasher.claimHashes ,claimLengths, matchSubstring, matchLength);

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

    component enableMacher[maxMatches];
    component matcher[maxMatches];
    var       maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    for (var i=0;i<maxMatches;i++) {
        enableMacher[i] = LessThan(8);
        enableMacher[i].in[0] <== i;
        enableMacher[i].in[1] <== matchesCount;

        matcher[i] = CheckSubstrInclusionPoly(maxPayloadLength,maxSubstringLength);
        matcher[i].str <== extractor.payload;
        matcher[i].str_hash <== 81283812381238128;
        matcher[i].substr <== matchSubstring[i];
        matcher[i].substr_len <== matchLength[i];
        matcher[i].start_index <== matchIndex[i];
        matcher[i].enabled <== enableMacher[i].out;
    }

    signal output jwtClaims[maxMatches][decodedLen];
    jwtClaims <==  claimDecoder.decodedClaims;
}