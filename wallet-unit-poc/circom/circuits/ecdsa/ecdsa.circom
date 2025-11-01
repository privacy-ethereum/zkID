pragma circom 2.2.3;

include "./p256/mul.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";


/**
 *  ECDSA
 *  ====================
 *  
 *  Implements ECDSA verification. Each Secp256r1Mul takes 3k constraints, however adding checked wrong field multiplication
 *  costs 4k constraints and so instead of doing the s_inverse * m and s_inverse * r mod n where n is the order of the secp256r1
 *  we just do scalar mults which use the native field of secp256r1.
 *
 *  From https://github.com/aleph-v/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/regular_ecdsa.circom
 */
template ECDSA() {
    signal input s_inverse;
    signal input r;
    signal input m;
    signal input pubKeyX;
    signal input pubKeyY;

    // TODO - Do we want more checks on s_inverse? (I think s_inv != 0 suffices)
    component check0 = IsZero();
    check0.in <== s_inverse;
    check0.out === 0;

    // TODO - Its shocking that this is more efficient than big number multiply, perhaps we should double check

    // s^-1 x Q_a computation
    component siPub = Secp256r1Mul();
    siPub.scalar <== s_inverse;
    siPub.xP <== pubKeyX;
    siPub.yP <== pubKeyY;

    // r x (s^-1 x Q_a) computation
    component rSiPub = Secp256r1Mul();
    rSiPub.scalar <== r;
    rSiPub.xP <== siPub.outX;
    rSiPub.yP <== siPub.outY;

    // s^-1 x G computation
    component siG = Secp256r1Mul();
    siG.scalar <== s_inverse;
    siG.xP <== 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
    siG.yP <== 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;

    // m x (s^-1 x G) computation
    component mSiG = Secp256r1Mul();
    mSiG.scalar <== m;
    mSiG.xP <== siG.outX;
    mSiG.yP <== siG.outY;

    // R = r s^-1 x Q_a + m s^-1 x G
    component R = Secp256r1AddComplete();
    R.xP <== rSiPub.outX;
    R.yP <== rSiPub.outY;
    R.xQ <== mSiG.outX;
    R.yQ <== mSiG.outY;

    // In ECDSA we have that the R's x coordinate should be the r from the signature's verification result
    r === R.outX;
}
