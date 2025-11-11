pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "components/age-verifier.circom";

template Show(maxClaimsLength) {
    var decodedLen = (maxClaimsLength * 3) / 4;

    signal input deviceKeyX;
    signal input deviceKeyY;
    signal input messageHash;
    signal input sig_r;
    signal input sig_s_inverse;

    signal input claim[decodedLen];
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal output ageAbove18;

    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== messageHash;
    ecdsa.pubKeyX <== deviceKeyX;
    ecdsa.pubKeyY <== deviceKeyY;

    component ageVerifier = AgeVerifier(decodedLen);
    ageVerifier.claim <== claim;
    ageVerifier.currentYear <== currentYear;
    ageVerifier.currentMonth <== currentMonth;
    ageVerifier.currentDay <== currentDay;
    ageAbove18 <== ageVerifier.ageAbove18;
}


