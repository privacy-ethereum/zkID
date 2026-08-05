pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/lib/sha.circom";
include "../keyless_zk_proofs/arrays.circom";

template MdocValueExtractor(maxPreimageLen, maxValueLen) {
    signal input preimage[maxPreimageLen];
    signal input preimageHashPoseidon;
    signal input preimageLength;
    signal input elementValueLabelPos;
    signal input valueStart;
    signal input valueEnd;
    signal input valueType;
    signal input isActive;

    signal output normalizedValue;

    // isActive is already constrained boolean by the caller.
    // valueType is constrained to {0,1,2,3} by the formatSum gate below,
    // which uses the IsEqual outputs we need anyway.

    // CBOR text(12) "elementValue"
    var LABEL_LEN = 13;
    signal elementValueLabel[LABEL_LEN];
    elementValueLabel[0]  <== 0x6c;
    elementValueLabel[1]  <== 0x65;
    elementValueLabel[2]  <== 0x6c;
    elementValueLabel[3]  <== 0x65;
    elementValueLabel[4]  <== 0x6d;
    elementValueLabel[5]  <== 0x65;
    elementValueLabel[6]  <== 0x6e;
    elementValueLabel[7]  <== 0x74;
    elementValueLabel[8]  <== 0x56;
    elementValueLabel[9]  <== 0x61;
    elementValueLabel[10] <== 0x6c;
    elementValueLabel[11] <== 0x75;
    elementValueLabel[12] <== 0x65;

    CheckSubstrInclusionPoly(maxPreimageLen, LABEL_LEN)(
        preimage,
        preimageHashPoseidon,
        elementValueLabel,
        LABEL_LEN,
        elementValueLabelPos,
        isActive
    );

    // Offset between label and value: 13 (label itself) to 18 (label + up to
    // 5 B of CBOR header for tagged dates).
    signal offset <== valueStart - elementValueLabelPos;
    var OFFSET_BITS = log2Ceil(maxPreimageLen + 1);

    // Range-check offset so a valueStart < labelPos underflow can't wrap past LessEqThan.
    component offsetBits = Num2Bits(OFFSET_BITS);
    offsetBits.in <== offset;

    component offsetGe13 = GreaterEqThan(OFFSET_BITS);
    offsetGe13.in[0] <== offset;
    offsetGe13.in[1] <== LABEL_LEN;
    (1 - offsetGe13.out) * isActive === 0;

    component offsetLe18 = LessEqThan(OFFSET_BITS);
    offsetLe18.in[0] <== offset;
    offsetLe18.in[1] <== LABEL_LEN + 5;
    (1 - offsetLe18.out) * isActive === 0;

    signal dataLen <== valueEnd - valueStart;

    component dataLenBits = Num2Bits(OFFSET_BITS);
    dataLenBits.in <== dataLen;

    component dataLenLe = LessEqThan(OFFSET_BITS);
    dataLenLe.in[0] <== dataLen;
    dataLenLe.in[1] <== maxValueLen;
    (1 - dataLenLe.out) * isActive === 0;

    // valueEnd inside the preimage; otherwise the extractor reads SHA padding
    // or wraps via VarShiftLeft.
    component valueEndBits = Num2Bits(OFFSET_BITS);
    valueEndBits.in <== valueEnd;

    component valueEndLe = LessEqThan(OFFSET_BITS);
    valueEndLe.in[0] <== valueEnd;
    valueEndLe.in[1] <== preimageLength;
    (1 - valueEndLe.out) * isActive === 0;

    // Bind dataLen to the signed CBOR header; a free valueEnd lets a holder
    // prove a predicate over a prefix of the signed value. preimage[valueStart-1]
    // is the text-string header for every form we accept, bare or tag-wrapped,
    // so this covers all four branches.
    // Gated on isActive: padding slots have valueStart = 0 and would underflow.
    signal hdrShift <== isActive * (valueStart - 2);
    component hdrShifter = VarShiftLeft(maxPreimageLen, 2);
    hdrShifter.in <== preimage;
    hdrShifter.shift <== hdrShift;
    signal hdrB2 <== hdrShifter.out[0];   // preimage[valueStart - 2]
    signal hdrB1 <== hdrShifter.out[1];   // preimage[valueStart - 1]

    component cborLenLt24 = LessThan(OFFSET_BITS);
    cborLenLt24.in[0] <== dataLen;
    cborLenLt24.in[1] <== 24;

    // text(n), n < 24: single byte 0x60 | n
    component shortHdrOk = IsZero();
    shortHdrOk.in <== hdrB1 - 0x60 - dataLen;

    // text(n), 24 <= n <= 255: 0x78 then the length byte
    component longPfxOk = IsZero();
    longPfxOk.in <== hdrB2 - 0x78;
    component longLenOk = IsZero();
    longLenOk.in <== hdrB1 - dataLen;
    signal longHdrOk <== longPfxOk.out * longLenOk.out;

    signal caseShort <== cborLenLt24.out * shortHdrOk.out;
    signal caseLong <== (1 - cborLenLt24.out) * longHdrOk;

    // Unrecognised header forms must reject, not fall through to a free dataLen.
    isActive * (1 - caseShort - caseLong) === 0;

    component formatEq[4];
    for (var i = 0; i < 4; i++) {
        formatEq[i] = IsEqual();
        formatEq[i].in[0] <== valueType;
        formatEq[i].in[1] <== i;
    }

    // Exactly one format must match when the claim is active. This also
    // sound-checks valueType without LessThan's field-wrap pitfall.
    signal formatSum <== formatEq[0].out + formatEq[1].out + formatEq[2].out + formatEq[3].out;
    (1 - formatSum) * isActive === 0;

    component shifter = VarShiftLeft(maxPreimageLen, maxValueLen);
    shifter.in <== preimage;
    shifter.shift <== valueStart;

    signal value[maxValueLen];
    for (var i = 0; i < maxValueLen; i++) {
        value[i] <== shifter.out[i];
    }

    signal dateYear  <== (value[0] - 48) * 1000 + (value[1] - 48) * 100 + (value[2] - 48) * 10 + (value[3] - 48);
    signal dateMonth <== (value[5] - 48) * 10 + (value[6] - 48);
    signal dateDay   <== (value[8] - 48) * 10 + (value[9] - 48);
    signal dateValue <== dateYear * 10000 + dateMonth * 100 + dateDay;

    // Same reasoning as the uint branch below, for the fixed date positions.
    // A signed value shorter than "YYYY-MM-DD" leaves value[dataLen..9] reading
    // whatever CBOR follows, and any byte below '0' makes (value[i] - 48) wrap
    // to a huge residue that satisfies LessEqThan(64) against any comparison
    // value. Pin the width to the CBOR-bound dataLen and the alphabet to digits.
    signal isDateActive <== formatEq[0].out * isActive;
    isDateActive * (dataLen - 10) === 0;

    var DATE_DIGIT_POS[8] = [0, 1, 2, 3, 5, 6, 8, 9];
    component dateGe48[8];
    component dateLe57[8];
    for (var i = 0; i < 8; i++) {
        dateGe48[i] = GreaterEqThan(9);
        dateGe48[i].in[0] <== value[DATE_DIGIT_POS[i]];
        dateGe48[i].in[1] <== 48;

        dateLe57[i] = LessEqThan(9);
        dateLe57[i].in[0] <== value[DATE_DIGIT_POS[i]];
        dateLe57[i].in[1] <== 57;

        isDateActive * (1 - dateGe48[i].out) === 0;
        isDateActive * (1 - dateLe57[i].out) === 0;
    }

    signal strAccum[maxValueLen + 1];
    strAccum[maxValueLen] <== 0;

    component strLenGt[maxValueLen];
    signal strShifted[maxValueLen];
    signal strBranch[maxValueLen];
    for (var i = maxValueLen - 1; i >= 0; i--) {
        strLenGt[i] = GreaterThan(log2Ceil(maxValueLen + 1));
        strLenGt[i].in[0] <== dataLen;
        strLenGt[i].in[1] <== i;

        strShifted[i] <== strAccum[i + 1] * 256 + value[i];
        strBranch[i] <== strLenGt[i].out * (strShifted[i] - strAccum[i + 1]);
        strAccum[i] <== strAccum[i + 1] + strBranch[i];
    }
    signal strValue <== strAccum[0];

    signal uintAccum[maxValueLen + 1];
    uintAccum[0] <== 0;

    component uintLenGt[maxValueLen];
    signal uintScaled[maxValueLen];
    for (var i = 0; i < maxValueLen; i++) {
        uintLenGt[i] = GreaterThan(log2Ceil(maxValueLen + 1));
        uintLenGt[i].in[0] <== dataLen;
        uintLenGt[i].in[1] <== i;

        // Scale by 10 only within dataLen; past the value the multiplier is 1
        // so trailing padding does not inflate the result by 10^(maxValueLen - dataLen).
        uintScaled[i] <== uintAccum[i] * (9 * uintLenGt[i].out + 1);
        uintAccum[i + 1] <== uintScaled[i] + (value[i] - 48) * uintLenGt[i].out;
    }
    signal uintValue <== uintAccum[maxValueLen];

    // Same field-wrap reasoning as ClaimValueNormalizer: bound the digit count
    // so no partial product can exceed 10^19 - 1 < 2^64 < q, and constrain
    // each active byte to be an ASCII digit so no term aliases mod q.
    var maxUintDigits = maxValueLen < 19 ? maxValueLen : 19;
    signal isUintActive <== formatEq[2].out * isActive;

    component uintLenLe = LessEqThan(OFFSET_BITS);
    uintLenLe.in[0] <== dataLen;
    uintLenLe.in[1] <== maxUintDigits;
    isUintActive * (1 - uintLenLe.out) === 0;

    component digitGe48[maxUintDigits];
    component digitLe57[maxUintDigits];
    signal digitActive[maxUintDigits];
    for (var i = 0; i < maxUintDigits; i++) {
        digitActive[i] <== isUintActive * uintLenGt[i].out;

        digitGe48[i] = GreaterEqThan(9);
        digitGe48[i].in[0] <== value[i];
        digitGe48[i].in[1] <== 48;

        digitLe57[i] = LessEqThan(9);
        digitLe57[i].in[0] <== value[i];
        digitLe57[i].in[1] <== 57;

        digitActive[i] * (1 - digitGe48[i].out) === 0;
        digitActive[i] * (1 - digitLe57[i].out) === 0;
    }

    // The string branch packs bytes at base 256, so 32+ bytes wrap the 254-bit
    // field and two distinct signed values can share a residue under `==`.
    signal isStrActive <== formatEq[1].out * isActive;
    component strLenLe31 = LessEqThan(OFFSET_BITS);
    strLenLe31.in[0] <== dataLen;
    strLenLe31.in[1] <== 31;
    isStrActive * (1 - strLenLe31.out) === 0;

    // Inactive claims feed a dummy padded-zero input to Sha256Bytes.
    signal input digestInputPadded[maxValueLen];
    signal input digestInputPaddedLen;

    // Pin every byte of the SHA input: message bytes to value[i], then the 0x80
    // marker, zeros, and the big-endian bit length. Free padding would let the
    // holder vary the length field and prove a suffix-extension of the slice.
    // Single-block layout only -- a longer input moves the length field.
    assert(maxValueLen == 64);

    signal isDigestActive <== formatEq[3].out * isActive;

    // 55 message bytes + 0x80 + 8-byte length = one 64 B block
    component digestLenLe55 = LessEqThan(OFFSET_BITS);
    digestLenLe55.in[0] <== dataLen;
    digestLenLe55.in[1] <== 55;
    isDigestActive * (1 - digestLenLe55.out) === 0;
    isDigestActive * (digestInputPaddedLen - 64) === 0;

    // (dataLen > i) is monotone decreasing, so (dataLen == i) is the drop
    // between neighbours -- no IsEqual components needed.
    signal prevLenGt[56];
    prevLenGt[0] <== 1;                       // (dataLen > -1) is always true
    for (var i = 1; i < 56; i++) {
        prevLenGt[i] <== uintLenGt[i - 1].out;
    }

    signal msgByte[56];
    signal expectedByte[56];
    for (var i = 0; i < 56; i++) {
        msgByte[i] <== uintLenGt[i].out * value[i];
        expectedByte[i] <== msgByte[i] + (prevLenGt[i] - uintLenGt[i].out) * 128;
        isDigestActive * (digestInputPadded[i] - expectedByte[i]) === 0;
    }

    // dataLen <= 55 so the bit length fits the low two bytes; Sha256Bytes
    // range-checks each byte, making the split unique.
    for (var i = 56; i < 62; i++) {
        isDigestActive * digestInputPadded[i] === 0;
    }
    isDigestActive * (digestInputPadded[62] * 256 + digestInputPadded[63] - dataLen * 8) === 0;

    signal digestSha[256] <== Sha256Bytes(maxValueLen)(digestInputPadded, digestInputPaddedLen);

    component digestToField = Bits2Num(248);
    for (var i = 0; i < 248; i++) {
        digestToField.in[i] <== digestSha[i];
    }
    signal digestValue <== digestToField.out;

    signal normDate   <== formatEq[0].out * dateValue;
    signal normStr    <== formatEq[1].out * strValue;
    signal normUint   <== formatEq[2].out * uintValue;
    signal normDigest <== formatEq[3].out * digestValue;

    signal rawValue <== normDate + normStr + normUint + normDigest;
    normalizedValue <== rawValue * isActive;
}
