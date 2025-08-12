pragma circom 2.1.6;

include "@zk-email/circuits/utils/array.circom";

/// @title SelectSubArrayBase64
/// @notice Select sub array from an array and pad with 'A' for Base64
/// @notice This is similar to `SelectSubArray` but pads with 'A' (ASCII 65) instead of zero
/// @notice Useful for preparing Base64 encoded data for decoding
/// @param maxArrayLen: the maximum number of bytes in the input array
/// @param maxSubArrayLen: the maximum number of integers in the output array
/// @input in: the input array
/// @input startIndex: the start index of the sub array; assumes a valid index
/// @input length: the length of the sub array; assumes to fit in `ceil(log2(maxArrayLen))` bits
/// @output out: array of `maxSubArrayLen` size, items starting from `startIndex`, and items after `length` set to 'A' (ASCII 65)
template SelectSubArrayBase64(maxArrayLen, maxSubArrayLen) {
    assert(maxSubArrayLen <= maxArrayLen);

    signal input in[maxArrayLen];
    signal input startIndex;
    signal input length;

    signal output out[maxSubArrayLen];

    component shifter = VarShiftLeft(maxArrayLen, maxSubArrayLen);
    shifter.in <== in;
    shifter.shift <== startIndex;

    component gts[maxSubArrayLen];
    for (var i = 0; i < maxSubArrayLen; i++) {
        gts[i] = GreaterThan(log2Ceil(maxSubArrayLen));
        gts[i].in[0] <== length;
        gts[i].in[1] <== i;

        // Pad with 'A' (ASCII 65) instead of zero
        out[i] <== gts[i].out * shifter.out[i] + (1 - gts[i].out) * 65;
    }
}