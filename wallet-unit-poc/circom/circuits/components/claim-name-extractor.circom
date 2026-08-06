pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";
include "../utils/utils.circom";

/// @title ClaimNameExtractor
/// @notice Extracts the name (2nd element) from a [salt, name, value] JSON tuple.
/// @notice A claim is encoded as: ["<salt>","<name>","<value>"], so the name is
///         the bytes between the 3rd quote (name open) and the 4th quote (name
///         close). This mirrors ClaimValueExtractor, which targets quotes 5/6.
/// @dev Kept as a sibling of ClaimValueExtractor rather than a shared
///      parameterized template so the working value-extraction path is untouched.
/// @param decodedLen: maximum length of decoded claim
/// @input claim: array of decoded claim bytes (from ClaimDecoder output)
/// @input isActive: 1 = enforce extraction constraints; 0 = output zeros
/// @output name: array of name bytes extracted from the tuple
/// @output nameLength: length of extracted name
template ClaimNameExtractor(decodedLen) {
    signal input claim[decodedLen];
    signal input isActive;
    signal output name[decodedLen];
    signal output nameLength;

    // Step 1: running quote count over ["salt","name","value"].
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

    // Exactly 6 quotes in ["salt","name","value"] (only enforced for active slots).
    isActive * (quoteCount[decodedLen - 1] - 6) === 0;

    // Step 2: locate the 3rd quote (name open) and 4th quote (name close).
    component isThirdQuote[decodedLen];
    component isFourthQuote[decodedLen];
    signal atThird[decodedLen];
    signal atFourth[decodedLen];
    signal thirdPosAcc[decodedLen];
    signal fourthPosAcc[decodedLen];

    for (var i = 0; i < decodedLen; i++) {
        isThirdQuote[i] = IsEqual();
        isThirdQuote[i].in[0] <== quoteCount[i];
        isThirdQuote[i].in[1] <== 3;

        isFourthQuote[i] = IsEqual();
        isFourthQuote[i].in[0] <== quoteCount[i];
        isFourthQuote[i].in[1] <== 4;

        atThird[i] <== isThirdQuote[i].out * isQuote[i];
        atFourth[i] <== isFourthQuote[i].out * isQuote[i];

        thirdPosAcc[i] <== (i == 0 ? 0 : thirdPosAcc[i - 1]) + atThird[i] * i;
        fourthPosAcc[i] <== (i == 0 ? 0 : fourthPosAcc[i - 1]) + atFourth[i] * i;
    }

    signal startPos <== thirdPosAcc[decodedLen - 1] + 1;
    signal endPos <== fourthPosAcc[decodedLen - 1];
    signal rawLength <== endPos - startPos;
    // Inactive slots get nameLength=0, which zeroes all name outputs.
    nameLength <== isActive * rawLength;

    // Step 3: shift the name to index 0, then mask past nameLength.
    component shifter = VarShiftLeft(decodedLen, decodedLen);
    shifter.in <== claim;
    shifter.shift <== startPos;

    component lengthGt[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        lengthGt[i] = GreaterThan(log2Ceil(decodedLen + 1));
        lengthGt[i].in[0] <== nameLength;
        lengthGt[i].in[1] <== i;
        name[i] <== lengthGt[i].out * shifter.out[i];
    }
}
