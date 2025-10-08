pragma circom 2.2.2;

include "jwt_tx_builder/header-payload-extractor.circom";
include "jwt_tx_builder/array.circom";

template PayloadSubstringMatcher(maxPayloadLength, maxMatches, maxSubstringLength) {

    signal input payload[maxPayloadLength];
    signal input matchesCount;
    signal input matchSubstring[maxMatches][maxSubstringLength];
    signal input matchLength[maxMatches];
    signal input matchIndex[maxMatches];

    signal output payloadHash;

    component payloadHasher = HashBytesToFieldWithLen(maxPayloadLength);
    payloadHasher.in <== payload;
    payloadHasher.len <== maxPayloadLength;
    payloadHash <== payloadHasher.hash;

    component enableMatcher[maxMatches];
    component matcher[maxMatches];

    for (var i = 0; i < maxMatches; i++) {
        enableMatcher[i] = LessThan(log2Ceil(maxMatches));
        enableMatcher[i].in[0] <== i;
        enableMatcher[i].in[1] <== matchesCount;

        matcher[i] = CheckSubstrInclusionPoly(maxPayloadLength, maxSubstringLength);
        matcher[i].str <== payload;
        matcher[i].str_hash <== payloadHash;
        matcher[i].substr <== matchSubstring[i];
        matcher[i].substr_len <== matchLength[i];
        matcher[i].start_index <== matchIndex[i];
        matcher[i].enabled <== enableMatcher[i].out;
    }
}
