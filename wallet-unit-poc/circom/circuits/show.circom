pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";

template Show(maxNonceLength) {
    signal input deviceKeyX;
    signal input deviceKeyY;
    signal input messageHash;
    signal input sig_r;
    signal input sig_s_inverse;
    
    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== messageHash;
    ecdsa.pubKeyX <== deviceKeyX;
    ecdsa.pubKeyY <== deviceKeyY;
    // TODO; we need to output the message[][] which is decodedClaim from prepare circuit ? 
}


