pragma circom 2.1.6;
include "../jwt_tx_builder/array.circom";
include "@zk-email/circuits/lib/base64.circom";
include "@zk-email/circuits/lib/sha.circom";
include "../utils/utils.circom";

/// @title ClaimDecoder
/// @notice Decodes multiple Base64 input claims that might be padded with zeros
/// @param maxClaims: the maximum number of claims to process
/// @param maxClaimsLength: the maximum number of characters in each Base64 input array
/// @input claims: array of raw Base64 input arrays, each padded with zeros
/// @input claimLengths: array containing the actual length of each Base64 claim
/// @output decodedClaims: array of decoded outputs
template ClaimDecoder(maxMatches, maxClaimsLength) {
    var decodedLen = (maxClaimsLength * 3) / 4;

    signal input claims[maxMatches][maxClaimsLength];
    signal input claimLengths[maxMatches];
    signal input decodeFlags[maxMatches];

    signal output decodedClaims[maxMatches][decodedLen];

    component paddedClaims[maxMatches];
    signal paddedOrConst[maxMatches][maxClaimsLength];
    component claimDecoders[maxMatches];

    for (var i = 0; i < maxMatches; i++) {
        paddedClaims[i] = SelectSubArrayBase64(maxClaimsLength,maxClaimsLength);
        paddedClaims[i].in <== claims[i];
        paddedClaims[i].startIndex <== 0;
        paddedClaims[i].length <== claimLengths[i];

        for (var j = 0; j < maxClaimsLength; j++) {
            paddedOrConst[i][j] <== paddedClaims[i].out[j] * decodeFlags[i] + 65 * (1 - decodeFlags[i]);
        }

        claimDecoders[i] = Base64Decode(decodedLen);
        claimDecoders[i].in <== paddedOrConst[i];

        decodeFlags[i] * decodeFlags[i] === decodeFlags[i];

        for (var j = 0; j < decodedLen; j++) {
            decodedClaims[i][j] <== claimDecoders[i].out[j] * decodeFlags[i];
        }
    }
}   

template ClaimComparator(maxMatches , maxSubstringLength){
    signal input claimHashes[maxMatches][32]; // hashed claims from rawclaims
    signal input claimLengths[maxMatches];
    
    signal input matchSubstring[maxMatches][maxSubstringLength]; // hashed claims in base64url encoded
    signal input matchLength[maxMatches];

    component isZero[maxMatches];
    signal useClaim[maxMatches];
    for (var i = 0; i < maxMatches; i++) {
        isZero[i] = IsEqual();
        isZero[i].in[0] <== claimLengths[i];
        isZero[i].in[1] <== 0;
        useClaim[i] <== 1 - isZero[i].out;
        useClaim[i] * (1 - useClaim[i]) === 0;
    }

    // Only decode match entries that correspond to real claims; 
    // otherwise feed padded 'A's so DecodeSD never parses the helper patterns like "x":" or "y":".

    signal sanitizedSubstring[maxMatches][maxSubstringLength];
    signal effectiveLen[maxMatches];
    component sdDecoders[maxMatches];
    for (var i = 0; i < maxMatches; i++) {
        for (var j = 0; j < maxSubstringLength; j++) {
            sanitizedSubstring[i][j] <== matchSubstring[i][j] * useClaim[i] + 65 * (1 - useClaim[i]);
        }

        effectiveLen[i] <== matchLength[i] * useClaim[i];

        sdDecoders[i] = DecodeSD(maxSubstringLength, 32);
        sdDecoders[i].sdBytes <== sanitizedSubstring[i];
        sdDecoders[i].sdLen   <== effectiveLen[i];
    }

    component eq[maxMatches][32];
    for (var i = 0; i < maxMatches; i++) {
        for (var j = 0; j < 32; j++) {
            eq[i][j] = IsEqual();
            eq[i][j].in[0] <== claimHashes[i][j];
            eq[i][j].in[1] <== sdDecoders[i].base64Out[j];
            eq[i][j].out * useClaim[i] === useClaim[i];
        }
    }
}

template ClaimHasher(maxMatches, maxClaimsLength){
    signal input claims[maxMatches][maxClaimsLength];

    component claimHasher[maxMatches];
    component hashByteConvert[maxMatches][32];
    signal output claimHashes[maxMatches][32]; 

    for (var i = 0; i < maxMatches; i++) {
        claimHasher[i] = Sha256Bytes(maxClaimsLength);
        claimHasher[i].paddedIn <== claims[i];
        claimHasher[i].paddedInLength <== maxClaimsLength;

         for (var j = 0; j < 32; j++) {
            hashByteConvert[i][j] = Bits2Num(8);
            for (var k = 0; k < 8; k++) {
                    hashByteConvert[i][j].in[7-k] <== claimHasher[i].out[j * 8 + k];
                 }
        claimHashes[i][j] <== hashByteConvert[i][j].out;
        }
    }
}
