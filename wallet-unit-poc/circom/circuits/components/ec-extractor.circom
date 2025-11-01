pragma circom 2.1.6;

include "../keyless_zk_proofs/arrays.circom";
include "circomlib/circuits/comparators.circom";
include "../utils/utils.circom";

template ECPublicKeyExtractor(maxPayloadLength, valueCharLen, expectedB64Len, coordinateByteLen) {
    signal input payload[maxPayloadLength];
    signal input xStartIndex;
    signal input yStartIndex;

    signal output pubKeyX;
    signal output pubKeyY;

    signal xValueEnd <== xStartIndex + expectedB64Len;
    signal yValueEnd <== yStartIndex + expectedB64Len;

    component xWithinBounds = LessThan(log2Ceil(maxPayloadLength));
    xWithinBounds.in[0] <== xValueEnd;
    xWithinBounds.in[1] <== maxPayloadLength;
    xWithinBounds.out === 1;

    component yWithinBounds = LessThan(log2Ceil(maxPayloadLength));
    yWithinBounds.in[0] <== yValueEnd;
    yWithinBounds.in[1] <== maxPayloadLength;
    yWithinBounds.out === 1;

    component xExtractor = ExtractBase64UrlValue(maxPayloadLength, valueCharLen, expectedB64Len);
    xExtractor.payload <== payload;
    xExtractor.startIndex <== xStartIndex;

    component yExtractor = ExtractBase64UrlValue(maxPayloadLength, valueCharLen, expectedB64Len);
    yExtractor.payload <== payload;
    yExtractor.startIndex <== yStartIndex;

    component decodeX = DecodeSD(valueCharLen, coordinateByteLen);
    decodeX.sdBytes <== xExtractor.value;
    decodeX.sdLen <== xExtractor.valueLength;

    component decodeY = DecodeSD(valueCharLen, coordinateByteLen);
    decodeY.sdBytes <== yExtractor.value;
    decodeY.sdLen <== yExtractor.valueLength;

    component xToNumber = BytesToNumberBE(coordinateByteLen);
    xToNumber.in <== decodeX.base64Out;

    component yToNumber = BytesToNumberBE(coordinateByteLen);
    yToNumber.in <== decodeY.base64Out;

    pubKeyX <== xToNumber.out;
    pubKeyY <== yToNumber.out;
}

template ECPublicKeyExtractor_Optimized(maxPayloadLength, coordinateByteLen) {
    signal input payload[maxPayloadLength];
    signal input xStartIndex;
    signal input yStartIndex;

    signal output pubKeyX;
    signal output pubKeyY;

    component xExtractor = VarShiftLeft(maxPayloadLength, 44);
    xExtractor.in <== payload;
    xExtractor.shift <== xStartIndex;

    component yExtractor = VarShiftLeft(maxPayloadLength, 44);
    yExtractor.in <== payload;
    yExtractor.shift <== yStartIndex;

    signal xBase64[44] <== xExtractor.out;
    signal yBase64[44] <== yExtractor.out;

    component decodeX = DecodeSD(44, coordinateByteLen);
    decodeX.sdBytes <== xBase64;
    decodeX.sdLen <== 43;

    component decodeY = DecodeSD(44, coordinateByteLen);
    decodeY.sdBytes <== yBase64;
    decodeY.sdLen <== 43;

    component xToNumber = BytesToNumberBE(coordinateByteLen);
    xToNumber.in <== decodeX.base64Out;

    component yToNumber = BytesToNumberBE(coordinateByteLen);
    yToNumber.in <== decodeY.base64Out;

    pubKeyX <== xToNumber.out;
    pubKeyY <== yToNumber.out;
}