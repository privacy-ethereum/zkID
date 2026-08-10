pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";
include "../utils/utils.circom";

/// @title ClaimValueExtractor
/// @notice Extracts the value (3rd element) from a [salt, key, value] JSON tuple
/// @notice A claim is encoded as: ["<salt>","<key>","<value>"]
/// @param decodedLen: maximum length of decoded claim
/// @input claim: array of decoded claim bytes (from ClaimDecoder output)
/// @output value: array of value bytes extracted from the tuple
/// @output valueLength: length of extracted value
template ClaimValueExtractor(decodedLen) {
    signal input claim[decodedLen];
    signal input isActive; // 1 = enforce extraction constraints; 0 = output zeros without constraint
    signal output value[decodedLen];
    signal output valueLength;

    // Step 1: Count quotes in ["salt","key","value"]
    component isQuoteCmp[decodedLen];
    signal isQuote[decodedLen];
    signal quoteCount[decodedLen];

    for (var i = 0; i < decodedLen; i++) {
        isQuoteCmp[i] = IsEqual();
        isQuoteCmp[i].in[0] <== claim[i];
        isQuoteCmp[i].in[1] <== 34;
        isQuote[i] <== isQuoteCmp[i].out;
        quoteCount[i] <== (i == 0 ? 0 : quoteCount[i - 1]) + isQuote[i];
    }

    // We expect exactly 6 quotes in ["salt","key","value"] (only enforced for active slots)
    isActive * (quoteCount[decodedLen - 1] - 6) === 0;

    // Forbid backslash bytes so every counted quote is a real JSON string
    // delimiter, never the raw 0x22 byte inside an escaped \" sequence -
    // otherwise an escaped quote in one field shifts which bytes this
    // extractor treats as another field's boundaries.
    component isBackslashCmp[decodedLen];
    signal isBackslash[decodedLen];
    signal backslashCount[decodedLen];

    for (var i = 0; i < decodedLen; i++) {
        isBackslashCmp[i] = IsEqual();
        isBackslashCmp[i].in[0] <== claim[i];
        isBackslashCmp[i].in[1] <== 92;
        isBackslash[i] <== isBackslashCmp[i].out;
        backslashCount[i] <== (i == 0 ? 0 : backslashCount[i - 1]) + isBackslash[i];
    }
    isActive * backslashCount[decodedLen - 1] === 0;

    // Step 2: Locate 5th quote (value open) and 6th quote (value close)
    component isFifthQuote[decodedLen];
    component isSixthQuote[decodedLen];
    signal atFifth[decodedLen];
    signal atSixth[decodedLen];
    signal fifthPosAcc[decodedLen];
    signal sixthPosAcc[decodedLen];

    for (var i = 0; i < decodedLen; i++) {
        isFifthQuote[i] = IsEqual();
        isFifthQuote[i].in[0] <== quoteCount[i];
        isFifthQuote[i].in[1] <== 5;

        isSixthQuote[i] = IsEqual();
        isSixthQuote[i].in[0] <== quoteCount[i];
        isSixthQuote[i].in[1] <== 6;

        atFifth[i] <== isFifthQuote[i].out * isQuote[i];
        atSixth[i] <== isSixthQuote[i].out * isQuote[i];

        fifthPosAcc[i] <== (i == 0 ? 0 : fifthPosAcc[i - 1]) + atFifth[i] * i;
        sixthPosAcc[i] <== (i == 0 ? 0 : sixthPosAcc[i - 1]) + atSixth[i] * i;
    }

    signal startPos <== fifthPosAcc[decodedLen - 1] + 1;
    signal endPos <== sixthPosAcc[decodedLen - 1];
    signal rawLength <== endPos - startPos;
    // Gate through isActive: inactive slots get valueLength=0, which zeroes all value outputs.
    valueLength <== isActive * rawLength;

    // Step 3: Shift so value begins at index 0, then mask after valueLength
    component shifter = VarShiftLeft(decodedLen, decodedLen);
    shifter.in <== claim;
    shifter.shift <== startPos;

    component lengthGt[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        lengthGt[i] = GreaterThan(log2Ceil(decodedLen + 1));
        lengthGt[i].in[0] <== valueLength;
        lengthGt[i].in[1] <== i;
        value[i] <== lengthGt[i].out * shifter.out[i];
    }
}

