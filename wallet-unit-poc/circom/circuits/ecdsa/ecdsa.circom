pragma circom 2.2.3;

include "./p256/mul.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";


/**
 *  PointOnP256
 *  ===========
 *
 *  Asserts (x, y) satisfies P-256's curve equation y^2 = x^3 - 3x + b mod p
 *  (native-field check, no bigint limbs needed since circuit arithmetic is
 *  already done in P-256's base field). secp256r1 has prime order, so no
 *  affine point has y = 0 - this also rejects the (0,0) infinity sentinel
 *  and any (+-1, 0) degenerate point, without a separate check.
 */
template PointOnP256() {
    signal input x;
    signal input y;
    var b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    signal xSq <== x * x;
    signal xCu <== xSq * x;
    signal ySq <== y * y;
    ySq === xCu - 3 * x + b;
}

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

    // r == 0 must be unreachable regardless of the lambdaB accident at
    // Secp256r1AddComplete (see PointOnP256 above) - r is a public input the
    // prover fully controls, so this needs an explicit constraint.
    component checkR = IsZero();
    checkR.in <== r;
    checkR.out === 0;

    // Reject any off-curve pubkey. Without this, the incomplete/complete
    // addition formulas in Secp256r1Mul are valid group-law arithmetic on
    // *any* point sharing P-256's `a` coefficient regardless of `b`, so an
    // attacker can pick Q off-curve and still satisfy r === R.outX for an
    // arbitrary message.
    component pubKeyOnCurve = PointOnP256();
    pubKeyOnCurve.x <== pubKeyX;
    pubKeyOnCurve.y <== pubKeyY;

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
