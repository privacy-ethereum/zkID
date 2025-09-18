pragma circom 2.1.6;
include "jwt_tx_builder/array.circom";
include "keyless_zk_proofs/arrays.circom";
include "@zk-email/circuits/lib/base64.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/gates.circom";


template Selector() {
    signal input condition;
    signal input in[2];
    signal output out;

    out <== condition * (in[0] - in[1]) + in[1];
}


template DecodeSD(maxSdLen, byteLength) {
    var charLength = 4 * ((byteLength + 2) \ 3);

    signal input sdBytes[maxSdLen];
    signal input sdLen;

    signal stdB64[charLength];
    component inRange[charLength];
    component isDash[charLength];
    component isUnder[charLength];
    component dashSel[charLength];
    component underSel[charLength];
    component rangeSel[charLength];

    for (var i = 0; i < charLength; i++) {

        inRange[i] = LessThan(8);
        inRange[i].in[0] <== i;
        inRange[i].in[1] <== sdLen;

        isDash[i]  = IsEqual();
        isDash[i].in[0] <== sdBytes[i]; 
        isDash[i].in[1] <== 45;
        
        isUnder[i] = IsEqual();
        isUnder[i].in[0] <== sdBytes[i];
        isUnder[i].in[1] <== 95;

        dashSel[i] = Selector();
        dashSel[i].condition <== isDash[i].out;
        dashSel[i].in[0] <== 43;  // '+'
        dashSel[i].in[1] <== sdBytes[i];

        underSel[i] = Selector();
        underSel[i].condition <== isUnder[i].out;
        underSel[i].in[0] <== 47;  // '/'
        underSel[i].in[1] <== dashSel[i].out;

        rangeSel[i] = Selector();
        rangeSel[i].condition <== inRange[i].out;
        rangeSel[i].in[0] <== underSel[i].out;
        rangeSel[i].in[1] <== 61;   // '='

        stdB64[i] <== rangeSel[i].out;
    }


    signal output base64Out[byteLength];
    
    component base64 = Base64Decode(byteLength);
    base64.in <== stdB64;
    base64Out <== base64.out;
}

template AssertBase64UrlChar() {
    signal input char;
    signal input enabled;

    component isUpperGt = GreaterThan(9);
    isUpperGt.in[0] <== char;
    isUpperGt.in[1] <== 64;

    component isUpperLt = LessThan(9);
    isUpperLt.in[0] <== char;
    isUpperLt.in[1] <== 91;

    signal isUpper <== isUpperGt.out * isUpperLt.out;

    component isLowerGt = GreaterThan(9);
    isLowerGt.in[0] <== char;
    isLowerGt.in[1] <== 96;

    component isLowerLt = LessThan(9);
    isLowerLt.in[0] <== char;
    isLowerLt.in[1] <== 123;

    signal isLower <== isLowerGt.out * isLowerLt.out;

    component isDigitGt = GreaterThan(9);
    isDigitGt.in[0] <== char;
    isDigitGt.in[1] <== 47;

    component isDigitLt = LessThan(9);
    isDigitLt.in[0] <== char;
    isDigitLt.in[1] <== 58;

    signal isDigit <== isDigitGt.out * isDigitLt.out;

    component isDash = IsZero();
    isDash.in <== char - 45;   // '-'

    component isUnder = IsZero();
    isUnder.in <== char - 95;  // '_'

    component isPlus = IsZero();
    isPlus.in <== char - 43;   // '+'

    component isSlash = IsZero();
    isSlash.in <== char - 47;  // '/'

    component isPad = IsZero();
    isPad.in <== char - 61;    // '='

    component upperOrLower = OR();
    upperOrLower.a <== isUpper;
    upperOrLower.b <== isLower;

    component alphaOrDigit = OR();
    alphaOrDigit.a <== upperOrLower.out;
    alphaOrDigit.b <== isDigit;

    component dashOrAlphaNum = OR();
    dashOrAlphaNum.a <== alphaOrDigit.out;
    dashOrAlphaNum.b <== isDash.out;

    component plusOrSlash = OR();
    plusOrSlash.a <== isPlus.out;
    plusOrSlash.b <== isSlash.out;

    component dashPlusSlash = OR();
    dashPlusSlash.a <== dashOrAlphaNum.out;
    dashPlusSlash.b <== plusOrSlash.out;

    component underOrPad = OR();
    underOrPad.a <== isUnder.out;
    underOrPad.b <== isPad.out;

    component allowed = OR();
    allowed.a <== dashPlusSlash.out;
    allowed.b <== underOrPad.out;

    (1 - allowed.out) * enabled === 0;
}

template BytesToNumberBE(numBytes) {
    signal input in[numBytes];
    signal output out;

    signal acc[numBytes + 1];
    acc[0] <== 0;

    for (var i = 0; i < numBytes; i++) {
        acc[i + 1] <== acc[i] * 256 + in[i];
    }

    out <== acc[numBytes];
}

// reduce a 256-bit hash modulo the secp256r1 scalar field order
template HashModScalarField() {
    signal input hash[256];  
    signal output out;       
    
    component hashNum = Bits2Num(256);
    for (var i = 0; i < 256; i++) {
        hashNum.in[i] <== hash[255 - i];
    }
    
    var q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    var qlo = q & ((2 ** 128) - 1);
    var qhi = q >> 128;
    
    // 128 bit each
    signal hashLo <-- hashNum.out & (2 ** (128) - 1);
    signal hashHi <-- hashNum.out >> 128;
    
    component verifyLo = Num2Bits(128);
    verifyLo.in <== hashLo;
    component verifyHi = Num2Bits(128);
    verifyHi.in <== hashHi;
    
    // hash >= q
    component alpha = GreaterThan(129);
    alpha.in[0] <== hashHi;
    alpha.in[1] <== qhi;
    
    component beta = IsEqual();
    beta.in[0] <== hashHi;
    beta.in[1] <== qhi;
    
    component gamma = GreaterEqThan(129);
    gamma.in[0] <== hashLo;
    gamma.in[1] <== qlo;
    
    // hashhi == qhi && ashlo >= qlo
    component betaANDgamma = AND();
    betaANDgamma.a <== beta.out;
    betaANDgamma.b <== gamma.out;
    
    component isHashGteQ = OR();
    isHashGteQ.a <== betaANDgamma.out;
    isHashGteQ.b <== alpha.out;
    
    // If hash >= q, hash - q; else hash
    signal resultLo <== hashLo - isHashGteQ.out * qlo;
    signal resultHi <== hashHi - isHashGteQ.out * qhi;
    
    out <== resultLo + resultHi * (2 ** 128);
}

template ExtractBase64UrlValue(maxPayloadLength, maxValueChars, expectedLength) {
    signal input payload[maxPayloadLength];
    signal input startIndex;
    signal output value[maxValueChars];
    signal output valueLength;

    signal found[maxValueChars + 1];
    found[0] <== 0;

    signal lengthAcc[maxValueChars + 1];
    lengthAcc[0] <== 0;

    signal currentIndex[maxValueChars];
    signal currentChar[maxValueChars];
    signal notFound[maxValueChars];
    signal includeChar[maxValueChars];

    component isQuote[maxValueChars];
    component base64Check[maxValueChars];

    for (var i = 0; i < maxValueChars; i++) {
        currentIndex[i] <== startIndex + i;
        currentChar[i] <== SelectArrayValue(maxPayloadLength)(payload, currentIndex[i], 1);

        isQuote[i] = IsEqual();
        isQuote[i].in[0] <== currentChar[i];
        isQuote[i].in[1] <== 34;

        notFound[i] <== 1 - found[i];
        includeChar[i] <== notFound[i] - notFound[i] * isQuote[i].out;

        base64Check[i] = AssertBase64UrlChar();
        base64Check[i].char <== currentChar[i];
        base64Check[i].enabled <== includeChar[i];

        value[i] <== includeChar[i] * currentChar[i];

        lengthAcc[i + 1] <== lengthAcc[i] + includeChar[i];
        found[i + 1] <== found[i] + isQuote[i].out - found[i] * isQuote[i].out;
    }

    found[maxValueChars] === 1;
    valueLength <== lengthAcc[maxValueChars];

    component lengthCheckExact = IsEqual();
    lengthCheckExact.in[0] <== valueLength;
    lengthCheckExact.in[1] <== expectedLength;

    component lengthCheckOneLess = IsEqual();
    lengthCheckOneLess.in[0] <== valueLength;
    lengthCheckOneLess.in[1] <== expectedLength - 1;

    component lengthOk = OR();
    lengthOk.a <== lengthCheckExact.out;
    lengthOk.b <== lengthCheckOneLess.out;
    lengthOk.out === 1;

    signal closingIndex <== startIndex + valueLength;
    signal closingChar <== SelectArrayValue(maxPayloadLength)(payload, closingIndex, 1);
    closingChar === 34;
}
