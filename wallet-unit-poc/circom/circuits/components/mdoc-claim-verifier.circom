pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";
include "../keyless_zk_proofs/arrays.circom";
include "../keyless_zk_proofs/hashtofield.circom";

template MdocClaimVerifier(maxCredLen, maxPreimageLen, maxIdentifierLen) {
    signal input message[maxCredLen];
    signal input messageHash;
    signal input messageLength;
    signal input preimage[maxPreimageLen];
    signal input preimageLength;
    signal input preimageHashPoseidon;
    signal input identifierCbor[maxIdentifierLen];
    signal input identifierLength;
    signal input identifierPos;
    signal input digestId;
    signal input encodedDigestPos;
    signal input isActive;

    signal preimageHash[32];

    // isActive must be 0 or 1; a fractional value would bypass the gated checks below.
    isActive * (1 - isActive) === 0;

    CheckSubstrInclusionPoly(maxPreimageLen, maxIdentifierLen)(
        preimage,
        preimageHashPoseidon,
        identifierCbor,
        identifierLength,
        identifierPos,
        isActive
    );

    // Range-check the length first so a huge prover-supplied value can't wrap
    // the position arithmetic below.
    var ID_POS_BITS = log2Ceil(maxPreimageLen + 1);
    component idLenLe = LessEqThan(log2Ceil(maxIdentifierLen + 1));
    idLenLe.in[0] <== identifierLength;
    idLenLe.in[1] <== maxIdentifierLen;
    (1 - idLenLe.out) * isActive === 0;

    // Bound the identifier to the SHA-authenticated preimage region. The
    // substring match above runs over the full maxPreimageLen array, but only
    // the first preimageLength bytes are covered by the SHA-256 digest the
    // issuer signed (checked below). Without this bound a prover could plant a
    // favourable identifier in the un-hashed tail and have it "match", forging
    // the claim identity that Show now binds predicates to (Item 7).
    component idEndLe = LessEqThan(ID_POS_BITS);
    idEndLe.in[0] <== identifierPos + identifierLength;
    idEndLe.in[1] <== preimageLength;
    (1 - idEndLe.out) * isActive === 0;

    signal sha[256] <== Sha256Bytes(maxPreimageLen)(preimage, preimageLength);

    component bits2byte[32];
    for (var i = 0; i < 32; i++) {
        bits2byte[i] = Bits2Num(8);
        for (var k = 0; k < 8; k++) {
            bits2byte[i].in[7 - k] <== sha[i * 8 + k];
        }
        preimageHash[i] <== bits2byte[i].out;
    }

    // Encoded digest layout: [digestId, 0x58, 0x20, <32-byte hash>].
    // Caller contract: digestId < 24 so its CBOR encoding is a single byte;
    // larger ids use multi-byte CBOR and won't match the eqDigestId check below.
    var ENCODED_DIGEST_LEN = 35;
    var DIGEST_POS_BITS = log2Ceil(maxCredLen + 1);

    // Keep the digest window inside messageLength so VarShiftLeft's circular
    // wrap cannot read tail/head bytes outside the signed region.
    component digestEndLe = LessEqThan(DIGEST_POS_BITS);
    digestEndLe.in[0] <== encodedDigestPos + ENCODED_DIGEST_LEN;
    digestEndLe.in[1] <== messageLength;
    (1 - digestEndLe.out) * isActive === 0;

    component digestShifter = VarShiftLeft(maxCredLen, ENCODED_DIGEST_LEN);
    digestShifter.in <== message;
    digestShifter.shift <== encodedDigestPos;

    signal extracted[ENCODED_DIGEST_LEN];
    for (var i = 0; i < ENCODED_DIGEST_LEN; i++) {
        extracted[i] <== digestShifter.out[i];
    }

    component eqDigestId = IsEqual();
    eqDigestId.in[0] <== extracted[0];
    eqDigestId.in[1] <== digestId;
    (1 - eqDigestId.out) * isActive === 0;

    component eq58 = IsEqual();
    eq58.in[0] <== extracted[1];
    eq58.in[1] <== 0x58;
    (1 - eq58.out) * isActive === 0;

    component eq20 = IsEqual();
    eq20.in[0] <== extracted[2];
    eq20.in[1] <== 0x20;
    (1 - eq20.out) * isActive === 0;

    component eqHash[32];
    for (var i = 0; i < 32; i++) {
        eqHash[i] = IsEqual();
        eqHash[i].in[0] <== extracted[3 + i];
        eqHash[i].in[1] <== preimageHash[i];
        (1 - eqHash[i].out) * isActive === 0;
    }
}
