pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "../utils/utils.circom";

/// @title ClaimValueNormalizer
/// @notice Converts extracted claim value bytes to a canonical integer.
/// @param valueLen: maximum length of value bytes
/// @input value: array of extracted value bytes (ASCII)
/// @input valueLength: actual number of meaningful bytes
/// @input format: 0=bool, 1=uint, 2=iso_date (YYYY-MM-DD), 3=roc_date (YYYMMDD), 4=string (big-endian byte pack)
/// @output normalizedValue: single integer representation suitable for numeric comparison
template ClaimValueNormalizer(valueLen) {
    signal input value[valueLen];
    signal input valueLength;
    signal input format;

    signal output normalizedValue;

    // ===== Format selectors =====
    component formatEq[5];
    signal isBoolFormat;
    signal isUintFormat;
    signal isIsoDateFormat;
    signal isRocDateFormat;

    for (var i = 0; i < 5; i++) {
        formatEq[i] = IsEqual();
        formatEq[i].in[0] <== format;
        formatEq[i].in[1] <== i;
    }

    isBoolFormat    <== formatEq[0].out;
    isUintFormat    <== formatEq[1].out;
    isIsoDateFormat <== formatEq[2].out;
    isRocDateFormat <== formatEq[3].out;
    signal isStringFormat <== formatEq[4].out;

    // Require exactly one supported format (0..4) to be selected, so an
    // out-of-range format is rejected rather than normalized to 0.
    signal formatSelectorSum <== isBoolFormat + isUintFormat + isIsoDateFormat + isRocDateFormat + isStringFormat;
    formatSelectorSum === 1;

    // ===== Format 0: Boolean — "1" or "true" → 1, else → 0 =====
    component valLenEq1 = IsEqual();
    valLenEq1.in[0] <== valueLength;
    valLenEq1.in[1] <== 1;

    component valLenEq4 = IsEqual();
    valLenEq4.in[0] <== valueLength;
    valLenEq4.in[1] <== 4;

    component v0is1 = IsEqual();
    v0is1.in[0] <== value[0];
    v0is1.in[1] <== 49; // '1'

    component vt = IsEqual(); vt.in[0] <== value[0]; vt.in[1] <== 116; // 't'
    component vr = IsEqual(); vr.in[0] <== value[1]; vr.in[1] <== 114; // 'r'
    component vu = IsEqual(); vu.in[0] <== value[2]; vu.in[1] <== 117; // 'u'
    component ve = IsEqual(); ve.in[0] <== value[3]; ve.in[1] <== 101; // 'e'

    signal valueTrueWordLeft  <== vt.out * vr.out;
    signal valueTrueWordRight <== vu.out * ve.out;
    signal valueTrueWord      <== valueTrueWordLeft * valueTrueWordRight;

    signal boolValueFromOne  <== valLenEq1.out * v0is1.out;
    signal boolValueFromWord <== valLenEq4.out * valueTrueWord;
    signal boolValue <== boolValueFromOne + boolValueFromWord;

    // ===== Format 1: Unsigned Integer — decimal ASCII → integer =====
    signal uintAccum[valueLen + 1];
    uintAccum[0] <== 0;

    // Scale by 10 only within valueLength; past the value the multiplier is 1
    // so trailing padding does not inflate the result.
    component valueLenGt[valueLen];
    signal uintScaled[valueLen];
    for (var i = 0; i < valueLen; i++) {
        valueLenGt[i] = GreaterThan(log2Ceil(valueLen + 1));
        valueLenGt[i].in[0] <== valueLength;
        valueLenGt[i].in[1] <== i;

        uintScaled[i] <== uintAccum[i] * (9 * valueLenGt[i].out + 1);
        uintAccum[i + 1] <== uintScaled[i] + (value[i] - 48) * valueLenGt[i].out;
    }
    signal uintValue <== uintAccum[valueLen];

    // ===== Format 2: ISO Date (YYYY-MM-DD) → YYYYMMDD integer =====
    signal isoDateValue <==
        ((value[0] - 48) * 1000 + (value[1] - 48) * 100 + (value[2] - 48) * 10 + (value[3] - 48)) * 10000
        + ((value[5] - 48) * 10 + (value[6] - 48)) * 100
        + ((value[8] - 48) * 10 + (value[9] - 48));

    // ===== Format 3: ROC Date (YYYMMDD) → integer =====
    signal rocDateValue <==
        ((value[0] - 48) * 100 + (value[1] - 48) * 10 + (value[2] - 48)) * 10000
        + ((value[3] - 48) * 10 + (value[4] - 48)) * 100
        + ((value[5] - 48) * 10 + (value[6] - 48));

    // ===== Select based on format =====
    // Format 4: String — pack ASCII bytes big-endian into a single field element.
    // "TW" → 84*256 + 87 = 21591. For compatibility with VALUE_BITS=64 comparisons,
    // string values are constrained to <= 8 bytes.
    // Verifier supplies the same packed integer as compareValue; EvalPredicate uses op==.
    signal strAccum[valueLen + 1];
    strAccum[0] <== 0;

    component strLenLe8 = LessEqThan(log2Ceil(valueLen + 1));
    strLenLe8.in[0] <== valueLength;
    strLenLe8.in[1] <== 8;
    isStringFormat * (1 - strLenLe8.out) === 0;

    // Scale by 256 only within valueLength; past the value the multiplier is 1
    // so trailing padding does not inflate the packed integer.
    component strLenGt[valueLen];
    signal strScaled[valueLen];
    for (var i = 0; i < valueLen; i++) {
        strLenGt[i] = GreaterThan(log2Ceil(valueLen + 1));
        strLenGt[i].in[0] <== valueLength;
        strLenGt[i].in[1] <== i;

        strScaled[i] <== strAccum[i] * (255 * strLenGt[i].out + 1);
        strAccum[i + 1] <== strScaled[i] + value[i] * strLenGt[i].out;
    }
    signal strValue <== strAccum[valueLen];

    signal normBool <== isBoolFormat    * boolValue;
    signal normUint <== isUintFormat    * uintValue;
    signal normIso  <== isIsoDateFormat * isoDateValue;
    signal normRoc  <== isRocDateFormat * rocDateValue;
    signal normStr  <== isStringFormat  * strValue;

    normalizedValue <== normBool + normUint + normIso + normRoc + normStr;
}
