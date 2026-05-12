pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/array.circom";
include "components/smtNonmembership.circom";
include "utils/utils.circom";

/// @title Bits2Limbs
/// @notice Convert a bit array to k limbs of n bits each (little-endian limb order)
/// @param totalBits Total number of input bits
/// @param n Number of bits per limb
/// @param k Number of limbs
/// @input in The input bit array
/// @output out Array of k limbs
template Bits2Limbs(totalBits, n, k) {
    signal input in[totalBits];
    signal output out[k];

    component b2n[k];
    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitIdx = i * n + j;
            if (bitIdx < totalBits) {
                b2n[i].in[j] <== in[bitIdx];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

/// @title CertRSA256Verify
/// @notice Verifies an X.509 certificate RSA-SHA256 signature
/// @param maxMessageLength Maximum TBS certificate bytes
/// @param n RSA chunk bits (121)
/// @param k RSA chunks (17 for 2048-bit)
template CertRSA256Verify(maxMessageLength, n, k) {
    // === Inputs ===
    signal input message[maxMessageLength];    // TBS certificate bytes
    signal input messageLength;                // actual TBS length
    signal input rsaModulus[k];                // issuer's RSA public key
    signal input rsaSignature[k];              // certificate signature

    // === Step 1: Assert zero padding ===
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // === Step 2: SHA-256 of TBS certificate ===
    signal sha[256] <== Sha256Bytes(maxMessageLength)(message, messageLength);

    // === Step 3: Convert SHA-256 to RSA limbs ===
    signal shaReversed[256];
    for (var i = 0; i < 256; i++) {
        shaReversed[i] <== sha[255 - i];
    }

    component hashToLimbs = Bits2Limbs(256, n, k);
    hashToLimbs.in <== shaReversed;

    // === Step 4: RSA Verify ===
    RSAVerifier65537(n, k)(hashToLimbs.out, rsaSignature, rsaModulus);
}

