pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "../utils/utils.circom";

// Extracts the device-binding key from the signed COSE_Key EC2 map.
//
// The map always encodes the coordinates as `-2: bytes(32) x` and
// `-3: bytes(32) y`, i.e. the byte runs 0x21 0x58 0x20 and 0x22 0x58 0x20
// immediately precede x and y. Those six bytes are the anchor: deviceKeyPos
// only says where to look, and every byte that gives the window its meaning is
// a circuit constant. Without them a prover picks two arbitrary 32-byte windows
// of the signed message -- including the SHA-padding zero run, which yields
// deviceKeyX = deviceKeyY = 0 and bypasses device binding outright.
//
// Same anchoring discipline as MdocValidUntil: the prefix is never an input.
template MdocDeviceKeyExtractor(maxCredLen) {
    signal input message[maxCredLen];
    signal input messageLength;
    // Index of the 0x21 marker, i.e. 3 bytes before the x coordinate.
    signal input deviceKeyPos;

    signal output deviceKeyX;
    signal output deviceKeyY;

    // 0x21 0x58 0x20 || x[32] || 0x22 0x58 0x20 || y[32]
    var X_HDR = 0;
    var X_OFF = 3;
    var Y_HDR = 35;
    var Y_OFF = 38;
    var WINDOW = 70;

    var POS_BITS = log2Ceil(maxCredLen + 1);

    // Range-check the position so the sum below cannot wrap the field, then
    // keep the whole window inside the signed region -- VarShiftLeft reads
    // circularly, so an out-of-range window would splice head bytes onto tail.
    component posBits = Num2Bits(POS_BITS);
    posBits.in <== deviceKeyPos;

    component endLe = LessEqThan(POS_BITS + 1);
    endLe.in[0] <== deviceKeyPos + WINDOW;
    endLe.in[1] <== messageLength;
    endLe.out === 1;

    component shifter = VarShiftLeft(maxCredLen, WINDOW);
    shifter.in <== message;
    shifter.shift <== deviceKeyPos;

    signal win[WINDOW];
    for (var i = 0; i < WINDOW; i++) {
        win[i] <== shifter.out[i];
    }

    // COSE label -2, bytes(32).
    win[X_HDR]     === 0x21;
    win[X_HDR + 1] === 0x58;
    win[X_HDR + 2] === 0x20;

    // COSE label -3, bytes(32). Fixed at x + 32, so the y window is no longer
    // reachable independently of the x window.
    win[Y_HDR]     === 0x22;
    win[Y_HDR + 1] === 0x58;
    win[Y_HDR + 2] === 0x20;

    signal xBytes[32];
    signal yBytes[32];
    for (var i = 0; i < 32; i++) {
        xBytes[i] <== win[X_OFF + i];
        yBytes[i] <== win[Y_OFF + i];
    }

    // The anchor bytes above pin where the coordinates are read from, but not
    // that they are the canonical <P encoding; without this, x and x+P are two
    // different signed device keys that collapse to the same field element.
    CheckBytesInRangeP256(32)(xBytes);
    CheckBytesInRangeP256(32)(yBytes);

    deviceKeyX <== BytesToNumberBE(32)(xBytes);
    deviceKeyY <== BytesToNumberBE(32)(yBytes);
}
