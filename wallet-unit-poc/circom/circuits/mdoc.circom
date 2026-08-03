pragma circom 2.2.3;

include "utils/es256.circom";
include "utils/utils.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "components/mdoc-validity.circom";
include "components/mdoc-claim-verifier.circom";
include "components/mdoc-value-extractor.circom";
include "components/mdoc-device-key.circom";

template MDOC(
    maxCredLen,
    maxPreimageLen,
    maxClaims,
    maxIdentifierLen,
    maxValueLen,
    maxDeviceKeyPrefixLen
) {
    signal input message[maxCredLen];
    signal input messageLength;

    // Issuer public key the ES256 check runs against. Declared public on the main
    // component, so it appears in the proof's public IO and a verifier can compare
    // it against the issuers it trusts.
    signal input pubKeyX;
    signal input pubKeyY;

    signal input sig_r;
    signal input sig_s_inverse;

    signal input validUntilPrefixPos;

    signal input deviceKeyPrefix[maxDeviceKeyPrefixLen];
    signal input deviceKeyPrefixLen;
    signal input deviceKeyPrefixPos;
    signal input yPrefixLen;

    signal input preimages[maxClaims][maxPreimageLen];
    signal input preimageLengths[maxClaims];
    signal input identifierCbor[maxClaims][maxIdentifierLen];
    signal input identifierLengths[maxClaims];
    signal input identifierPositions[maxClaims];
    signal input digestIds[maxClaims];
    signal input encodedDigestPositions[maxClaims];
    signal input elementValueLabelPositions[maxClaims];
    signal input valueStarts[maxClaims];
    signal input valueEnds[maxClaims];
    // valueTypes and claimFlags decide how each value in normalizedClaimValues was
    // produced, so they are public inputs of the main component: a verifier reading
    // those values needs them to know what the values mean. A slot with claimFlags 0
    // holds 0 rather than the claim, and a slot extracted under one value type is not
    // comparable to a literal in another.
    signal input valueTypes[maxClaims];    // 0=date, 1=string, 2=integer, 3=reveal_digest
    signal input claimFlags[maxClaims];

    signal input digestInputsPadded[maxClaims][maxValueLen];
    signal input digestInputsPaddedLen[maxClaims];

    signal output validUntilDate;
    signal output normalizedClaimValues[maxClaims];

    signal output deviceKeyX;
    signal output deviceKeyY;

    // CHECK 1: ECDSA-P256 signature
    ES256(maxCredLen)(message, messageLength, sig_r, sig_s_inverse, pubKeyX, pubKeyY);

    signal messageHash <== HashBytesToFieldWithLen(maxCredLen)(message, messageLength);

    // CHECK 2: validUntil
    validUntilDate <== MdocValidUntil(maxCredLen)(message, messageHash, messageLength, validUntilPrefixPos);

    // CHECK 3: per-claim preimage authenticity + value extraction
    signal preimageHashesPoseidon[maxClaims];

    for (var i = 0; i < maxClaims; i++) {
        // claimFlags[i] must be 0 or 1; fractional values bypass gated assertions.
        claimFlags[i] * (1 - claimFlags[i]) === 0;

        preimageHashesPoseidon[i] <== HashBytesToFieldWithLen(maxPreimageLen)(preimages[i], preimageLengths[i]);

        MdocClaimVerifier(maxCredLen, maxPreimageLen, maxIdentifierLen)(
            message,
            messageHash,
            messageLength,
            preimages[i],
            preimageLengths[i],
            preimageHashesPoseidon[i],
            identifierCbor[i],
            identifierLengths[i],
            identifierPositions[i],
            digestIds[i],
            encodedDigestPositions[i],
            claimFlags[i]
        );

        normalizedClaimValues[i] <== MdocValueExtractor(maxPreimageLen, maxValueLen)(
            preimages[i],
            preimageHashesPoseidon[i],
            preimageLengths[i],
            elementValueLabelPositions[i],
            valueStarts[i],
            valueEnds[i],
            valueTypes[i],
            claimFlags[i],
            digestInputsPadded[i],
            digestInputsPaddedLen[i]
        );
    }

    // CHECK 4: device key extraction
    (deviceKeyX, deviceKeyY) <== MdocDeviceKeyExtractor(maxCredLen, maxDeviceKeyPrefixLen)(
        message,
        messageHash,
        messageLength,
        deviceKeyPrefix,
        deviceKeyPrefixLen,
        deviceKeyPrefixPos,
        yPrefixLen
    );
}
