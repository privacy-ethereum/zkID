pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/array.circom";


template VerifyTBSinCert(MAX_CERT_LEN, MAX_TBS_LEN) {
    var TBS_OFFSET = 4;

    signal input user_cert[MAX_CERT_LEN];
    signal input tbs[MAX_TBS_LEN];
    signal input issuer_tbs_length;          // actual length, runtime

    component isLt[MAX_TBS_LEN];
    signal diff[MAX_TBS_LEN];

    for (var i = 0; i < MAX_TBS_LEN - TBS_OFFSET; i++) {
        isLt[i] = LessThan(12);
        isLt[i].in[0] <== i;
        isLt[i].in[1] <== issuer_tbs_length;

        // only enforce if i < issuer_tbs_length
        // (user_cert[4+i] - tbs[i]) * isLt[i].out === 0
        diff[i] <== user_cert[TBS_OFFSET + i] - tbs[i];
        diff[i] * isLt[i].out === 0;
    }
}

/// Extracts cert[subject_dn_offset .. +length] and asserts it equals subject_dn.
template VerifySubjectDN(MAX_CERT_LEN, MAX_SUBJECT_LEN) {
    signal input cert[MAX_CERT_LEN];
    signal input subject_dn[MAX_SUBJECT_LEN];
    signal input subject_dn_offset;
    signal input length;

    component extracted = SelectSubArray(MAX_CERT_LEN, MAX_SUBJECT_LEN);
    extracted.in <== cert;
    extracted.startIndex <== subject_dn_offset;
    extracted.length <== length;

    for (var i = 0; i < MAX_SUBJECT_LEN; i++) {
        extracted.out[i] === subject_dn[i];
    }
}

/// Validates ASN.1 INTEGER tag+length, extracts serial bytes, and reconstructs
/// a big-endian integer to assert it equals `target`.
template VerifySerialNumber(MAX_CERT_LEN, MAX_SERIAL_LEN) {
    signal input cert[MAX_CERT_LEN];
    signal input offset;
    signal input target;  // single big-endian integer

    // -----------------------------------------------------------------------
    // Step 0: Extract tag byte at (offset-2) and length byte at (offset-1)
    // -----------------------------------------------------------------------
    component tagSel = ItemAtIndex(MAX_CERT_LEN);
    tagSel.in <== cert;
    tagSel.index <== offset - 2;

    // Enforce ASN.1 INTEGER tag == 0x02
    component tagCheck = IsEqual();
    tagCheck.in[0] <== tagSel.out;
    tagCheck.in[1] <== 2;
    tagCheck.out === 1;

    component lenSel = ItemAtIndex(MAX_CERT_LEN);
    lenSel.in <== cert;
    lenSel.index <== offset - 1;

    signal actual_len;
    actual_len <== lenSel.out;

    component lenGtZero = GreaterThan(8);
    lenGtZero.in[0] <== actual_len;
    lenGtZero.in[1] <== 0;
    lenGtZero.out === 1;

    component lenInRange = LessEqThan(8);
    lenInRange.in[0] <== actual_len;
    lenInRange.in[1] <== MAX_SERIAL_LEN;
    lenInRange.out === 1;

    // -----------------------------------------------------------------------
    // Step 1: Extract serial bytes using SelectSubArray (log-depth shift)
    // -----------------------------------------------------------------------
    component serialSel = SelectSubArray(MAX_CERT_LEN, MAX_SERIAL_LEN);
    serialSel.in <== cert;
    serialSel.startIndex <== offset;
    serialSel.length <== actual_len;

    // -----------------------------------------------------------------------
    // Step 2: Reconstruct big-endian integer using actual_len-relative powers
    // -----------------------------------------------------------------------

    var pow256[MAX_SERIAL_LEN + 1];
    pow256[0] = 1;
    for (var k = 1; k <= MAX_SERIAL_LEN; k++) {
        pow256[k] = pow256[k-1] * 256;
    }

    component powEq[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 1];
    signal powSelected[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 1];
    signal powSum[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 2];
    signal byte_weight[MAX_SERIAL_LEN];

    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        powSum[i][0] <== 0;
        for (var k = 0; k <= MAX_SERIAL_LEN; k++) {
            powEq[i][k] = IsEqual();
            powEq[i][k].in[0] <== actual_len;
            powEq[i][k].in[1] <== k + 1 + i;
            powSelected[i][k] <== pow256[k] * powEq[i][k].out;
            powSum[i][k+1] <== powSum[i][k] + powSelected[i][k];
        }
        byte_weight[i] <== powSum[i][MAX_SERIAL_LEN + 1];
    }

    signal weighted[MAX_SERIAL_LEN];
    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        weighted[i] <== serialSel.out[i] * byte_weight[i];
    }

    signal reconSum[MAX_SERIAL_LEN + 1];
    reconSum[0] <== 0;
    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        reconSum[i+1] <== reconSum[i] + weighted[i];
    }

    reconSum[MAX_SERIAL_LEN] === target;
}

/// @title ExtractModulus
/// @notice Extracts an RSA public key modulus from a DER-encoded certificate
/// @dev    SubjectPublicKeyInfo layout:
///           SEQUENCE {
///             SEQUENCE { OID rsaEncryption  NULL }
///             BIT STRING {
///               SEQUENCE {
///                 INTEGER  ← modulus value bytes start at modulusOffset
///                 INTEGER  ← exponent (65537)
///               }
///             }
///           }
///         Prover supplies modulusTagOffset pointing to the 0x02 INTEGER tag
///         and modulusOffset pointing to the first actual modulus byte
///         (after tag + length field + optional 0x00 sign byte).
///         Circuit validates the INTEGER tag at modulusTagOffset.
///         DER is big-endian; limbs are packed LSB-first for RSAVerifier65537.
///         For non-byte-aligned limb sizes (e.g. n=121), bits beyond
///         modulusBits in the top limb are zero-padded.
/// @param maxLen        Maximum certificate DER byte length
/// @param n             Bits per RSA limb (e.g. 121)
/// @param k             Number of RSA limbs (e.g. 17 for RSA-2048)
/// @param modulusBits   Actual RSA key size in bits (e.g. 2048) — must be
///                      divisible by 8. Separate from n*k (e.g. 121*17=2057).
/// @input in                Certificate DER bytes, zero-padded to maxLen
/// @input modulusOffset     Byte offset of first modulus value byte in `in`
///                          (points past tag + length field + sign byte)
/// @input modulusTagOffset  Byte offset of the INTEGER tag (0x02) in `in`
///                          Circuit asserts in[modulusTagOffset] == 2
/// @output out              Modulus as k limbs of n bits, LSB limb first
///                          Compatible with RSAVerifier65537(n, k)
template ExtractModulus(maxLen, n, k, modulusBits) {
    var modulusBytes = modulusBits \ 8;  // 2048\8 = 256 bytes

    signal input in[maxLen];
    signal input modulusOffset;
    signal input modulusTagOffset;
    signal output out[k];

    // ── Step 1: Validate INTEGER tag (0x02) at modulusTagOffset ──────────
    // Prevents prover from pointing at arbitrary bytes as the modulus
    component tagSel = Multiplexer(1, maxLen);
    for (var i = 0; i < maxLen; i++) {
        tagSel.inp[i][0] <== in[i];
    }
    tagSel.sel <== modulusTagOffset;
    tagSel.out[0] === 2;  // 0x02 = INTEGER tag

    // ── Step 2: Extract modulusBytes bytes starting at modulusOffset ──────
    // Uses clamped selector to avoid Multiplexer out-of-bounds assert
    component bytesel[modulusBytes];
    component ltn[modulusBytes];
    signal modBytes[modulusBytes];

    for (var i = 0; i < modulusBytes; i++) {
        // Check modulusOffset + i is within maxLen
        ltn[i] = LessThan(12);
        ltn[i].in[0] <== modulusOffset + i;
        ltn[i].in[1] <== maxLen;

        bytesel[i] = Multiplexer(1, maxLen);
        for (var j = 0; j < maxLen; j++) {
            bytesel[i].inp[j][0] <== in[j];
        }
        // Clamp selector: use modulusOffset+i if in bounds, else 0
        bytesel[i].sel <== ltn[i].out * (modulusOffset + i) +
                           (1 - ltn[i].out) * 0;

        // Zero out if out of bounds
        modBytes[i] <== bytesel[i].out[0] * ltn[i].out;
    }

    // ── Step 3: Bytes → flat bit array (MSB first) ────────────────────────
    // modBytes[0] is the most significant byte (big-endian DER)
    // bits[0] = MSB of modBytes[0], bits[modulusBits-1] = LSB of last byte
    component byte2bits[modulusBytes];
    signal bits[modulusBytes * 8];  // = modulusBits bits

    for (var i = 0; i < modulusBytes; i++) {
        byte2bits[i] = Num2Bits(8);
        byte2bits[i].in <== modBytes[i];
        for (var j = 0; j < 8; j++) {
            bits[i * 8 + j] <== byte2bits[i].out[7 - j];  // MSB first
        }
    }

    // ── Step 4: Pack bits → k limbs of n bits, LSB limb first ────────────
    // bits[0]          = MSB of modulus
    // bits[modulusBits-1] = LSB of modulus
    //
    // limb[0] = least significant n bits of modulus
    // limb[k-1] = most significant n bits of modulus
    //
    // For i-th limb, j-th bit:
    //   bitPos = i*n + j  (position from LSB end)
    //   maps to bits[modulusBits - 1 - bitPos]
    //
    // If bitPos >= modulusBits (top limb overflow when n*k > modulusBits),
    //   zero-pad those bits
    component b2n[k];

    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitPos = i * n + j;
            if (bitPos < modulusBits) {
                b2n[i].in[j] <== bits[modulusBits - 1 - bitPos];
            } else {
                // Zero-pad top limb bits that exceed modulusBits
                // e.g. n=121, k=17: n*k=2057 but modulusBits=2048
                // limb[16] bits 2048..2056 are zero
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

template PackBytes(N_BYTES, TBS_LENGTH) {
    // packs N_BYTES into ceil(N_BYTES/31) field elements
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[TBS_LENGTH];
    signal output out[N_FIELDS];

    for (var f = 0; f < N_FIELDS; f++) {
        var acc = 0;
        var shift = 1;
        for (var i = 0; i < BYTES_PER_FIELD; i++) {
            var idx = f * BYTES_PER_FIELD + i;
            if (idx < N_BYTES) {
                acc = acc + in[idx] * shift;
            }
            shift = shift * 256;
        }
        out[f] <== acc;
    }
}

template PoseidonBytes(N_BYTES) {
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[N_BYTES];
    signal output out;

    // step 1: pack bytes → field elements
    component packer = PackBytes(N_BYTES, N_BYTES);
    for (var i = 0; i < N_BYTES; i++) {
        packer.in[i] <== in[i];
    }

    // step 2: hash packed field elements
    component hasher = Poseidon(N_FIELDS);
    for (var f = 0; f < N_FIELDS; f++) {
        hasher.inputs[f] <== packer.out[f];
    }

    out <== hasher.out;
}

/// Like PoseidonBytes but appends one extra field element before hashing.
/// Used to bind a byte array to an application-specific domain value.
template PoseidonBytesWithField(N_BYTES) {
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[N_BYTES];
    signal input extra;
    signal output out;

    component packer = PackBytes(N_BYTES, N_BYTES);
    for (var i = 0; i < N_BYTES; i++) {
        packer.in[i] <== in[i];
    }

    component hasher = Poseidon(N_FIELDS + 1);
    for (var f = 0; f < N_FIELDS; f++) {
        hasher.inputs[f] <== packer.out[f];
    }
    hasher.inputs[N_FIELDS] <== extra;

    out <== hasher.out;
}
