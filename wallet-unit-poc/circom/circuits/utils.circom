pragma circom 2.1.6;
include "jwt_tx_builder/array.circom";
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
