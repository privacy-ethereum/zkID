pragma circom 2.1.2;

/**
 *  Secp256r1Double
 *  ===============
 *
 *  Double a specific point (xP, yP) on the secp256r1 curve. Should work for any 
 *  short Weierstrass curve (Pasta, P-256).
 *
 *  Modified from https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/secp256k1/double.circom
 */
template Secp256r1Double() {
    signal input xP; 
    signal input yP;

    signal output outX;
    signal output outY;

    signal lambda;
    signal xPSquared;

    xPSquared <== xP * xP;

    lambda <-- (3 * xPSquared - 3) / (2 * yP);
    lambda * 2 * yP === 3 * xPSquared - 3;

    outX <== lambda * lambda - (2 * xP);
    outY <== lambda * (xP - outX) - yP;
}
