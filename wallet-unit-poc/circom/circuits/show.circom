pragma circom 2.2.3;

include "utils/es256.circom";

template Show(maxNonceLength) {
    signal input deviceKeyX;
    signal input deviceKeyY;
    signal input nonce[maxNonceLength];
    signal input nonceLength;
    signal input sig_r;
    signal input sig_s_inverse;
    
    ES256(maxNonceLength)(nonce, nonceLength, sig_r, sig_s_inverse, deviceKeyX, deviceKeyY);
}


