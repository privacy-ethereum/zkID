pragma circom 2.1.3;

include "./arrays.circom";
include "./hashtofield.circom";
include "./packing.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/bitify.circom";

// Checks if character 'char' is a whitespace character. Returns 1 if so, 0 otherwise
// Assumes char is a valid ascii character. Does not check for non-ascii unicode whitespace chars.
template isWhitespace() {
   signal input char;  
                       
   signal is_tab <== IsEqual()([char, 9]); // character is a tab space

   signal is_line_break_part_1 <== GreaterEqThan(8)([char, 10]); // ASCII bytes values between 10 ...
   signal is_line_break_part_2 <== LessEqThan(8)([char, 13]); //    ... and 13 inclusive are line break characters
   signal is_line_break <== is_line_break_part_1 * is_line_break_part_2;

   signal is_space <== IsEqual()([char, 32]); // ' '
                       
   signal output is_whitespace <== is_tab + is_line_break + is_space;
}

/*
// https://github.com/TheFrozenFire/snark-jwt-verify/blob/master/circuits/calculate_total.circom
// This circuit returns the sum of the inputs in `num`
// `n` must be greater than 0.
template CalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for (var i=1; i < n; i++) {
        sums[i] <== sums[i - 1] + nums[i];
    }

    sum <== sums[n - 1];
}
*/

// Given input `in`, enforces that `in[0] === in[1]` if `bool` is 1
template AssertEqualIfTrue() {
    signal input in[2];
    signal input bool;

    (in[0]-in[1]) * bool === 0;
}

// Given an input `brackets_depth_map`, which must be an output of `BracketsDepthMap` and
// corresponds to the nested brackets depth of the original JWT, and a `start_index` and `field_len`
// corresponding to the first index and length of a full field in the JWT, fails if the given field
// contains any indices inside nested brackets in the original JWT, and succeeds otherwise
template EnforceNotNested(len) {
    signal input start_index;
    signal input field_len;
    signal input brackets_depth_map[len];
    signal input enabled;

    signal brackets_selector[len] <== ArraySelector(len)(start_index, start_index+field_len, enabled);
    signal is_nested <== EscalarProduct(len)(brackets_depth_map, brackets_selector);
    is_nested === 0;
}

// Enforce that if uid name is "email", the email verified field is either true or "true"
template EmailVerifiedCheck(maxEVNameLen, maxEVValueLen, maxUIDNameLen) {
    signal input ev_name[maxEVNameLen];
    signal input ev_value[maxEVValueLen];
    signal input ev_value_len;
    signal input uid_name[maxUIDNameLen];
    signal input uid_name_len;
    signal output uid_is_email;

    var email[5] = [101, 109, 97, 105, 108]; // email

    var uid_starts_with_email_0 = IsEqual()([email[0], uid_name[0]]);
    var uid_starts_with_email_1 = IsEqual()([email[1], uid_name[1]]);
    var uid_starts_with_email_2 = IsEqual()([email[2], uid_name[2]]);
    var uid_starts_with_email_3 = IsEqual()([email[3], uid_name[3]]);
    var uid_starts_with_email_4 = IsEqual()([email[4], uid_name[4]]);

    var uid_starts_with_email = MultiAND(5)([uid_starts_with_email_0, uid_starts_with_email_1, uid_starts_with_email_2, uid_starts_with_email_3, uid_starts_with_email_4]);


    signal uid_name_len_is_5 <== IsEqual()([uid_name_len, 5]);
    uid_is_email <== AND()(uid_starts_with_email, uid_name_len_is_5); // '1' if uid_name is "email" with length 5. This guarantees uid_name is in fact "email" (with quotes) combined with the logic in `JWTFieldCheck`

    var required_ev_name[14] = [101, 109, 97, 105, 108, 95, 118, 101, 114, 105, 102, 105, 101, 100];    // email_verified

    // If uid name is "email", enforce ev_name is "email_verified"
    for (var i = 0; i < 14; i++) {
        AssertEqualIfTrue()([ev_name[i], required_ev_name[i]], uid_is_email);
    }

    signal ev_val_len_is_4 <== IsEqual()([ev_value_len, 4]);
    signal ev_val_len_is_6 <== IsEqual()([ev_value_len, 6]);
    var ev_val_len_is_correct = OR()(ev_val_len_is_4, ev_val_len_is_6);

    signal not_uid_is_email <== NOT()(uid_is_email);
    signal is_ok <== OR()(not_uid_is_email, ev_val_len_is_correct);
    is_ok === 1;
    
    var required_ev_val_len_4[4] = [116, 114, 117, 101]; // true
    signal check_ev_val_bool <== AND()(ev_val_len_is_4, uid_is_email);
    for (var i = 0; i < 4; i ++) {
        AssertEqualIfTrue()([required_ev_val_len_4[i], ev_value[i]], check_ev_val_bool);
    }

    var required_ev_val_len_6[6] = [34, 116, 114, 117, 101, 34]; // "true"
    signal check_ev_val_str <== AND()(ev_val_len_is_6, uid_is_email);
    for (var i = 0; i < 6; i++) {
        AssertEqualIfTrue()([required_ev_val_len_6[i], ev_value[i]], check_ev_val_str);
    }
}

// Given an array of ascii characters representing a JSON object, output a binary array demarquing
// the spaces in between quotes, so that the indices in between quotes in `in` are given the value
// `1` in `out`, and are 0 otherwise. Escaped quotes are not considered quotes in this subcircuit
// input =  { asdfsdf "as\"df" }
// output = 00000000000111111000
template StringBodies(len) {
  signal input in[len];
  signal output out[len];


  signal quotes[len];
  signal quote_parity[len];
  signal quote_parity_1[len];
  signal quote_parity_2[len];

  signal backslashes[len];
  signal adjacent_backslash_parity[len];

  quotes[0] <== IsEqual()([in[0], 34]); 
  quote_parity[0] <== IsEqual()([in[0], 34]); 

  backslashes[0] <== IsEqual()([in[0], 92]);
  adjacent_backslash_parity[0] <== IsEqual()([in[0], 92]);

  for (var i = 1; i < len; i++) {
    backslashes[i] <== IsEqual()([in[i], 92]);
    adjacent_backslash_parity[i] <== backslashes[i] * (1 - adjacent_backslash_parity[i-1]);
  }

  for (var i = 1; i < len; i++) {
    var is_quote = IsEqual()([in[i], 34]); 
    var prev_is_odd_backslash = adjacent_backslash_parity[i-1];
    quotes[i] <== is_quote * (1 - prev_is_odd_backslash); // 1 iff there is a non-escaped quote at this position
    quote_parity[i] <== XOR()(quotes[i], quote_parity[i-1]);
  }
  // input =               { asdfsdf "asdf" }
  // intermediate output = 000000000011111000
  // i.e., still has offset-by-one error

  out[0] <== 0;

  for (var i = 1; i < len; i++) {
    out[i] <== AND()(quote_parity[i-1], quote_parity[i]); // remove offset error
  }
}

// Given an array of ASCII characters `arr`, returns an array `brackets` with
// a 1 in the position of each open bracket `{`, a -1 in the position of each closed bracket `}`
// and 0 everywhere else.
//
// See an example below. The real string is `arr` but we re-display it with "fake" spaces in `align_arr` 
// to more easily showcase which character in `arr` corresponds to the `-1` in `brackets`.
// arr:       {he{llo{}world!}}
// align_arr: {he{llo{ }world! } }
// brackets:  10010001-1000000-1-1
//
// where `arr` is represented by its ASCII encoding, i.e. `{` = 123
template BracketsMap(len) {
    signal input arr[len];
    signal output brackets[len];

    for (var i = 0; i < len; i++) {
        var is_open_bracket = IsEqual()([arr[i], 123]); // 123 = `{`
        var is_closed_bracket = IsEqual()([arr[i], 125]); // 125 = '}'
        brackets[i] <== is_open_bracket + (0-is_closed_bracket);
    }
}

// Given an input array `arr` of length `len` containing `1`s corresponding to open
// brackets `{`, `-1`s corresponding to closed brackets `}`, and 0s everywhere else, outputs an array
// containing a positive integer in each index between nested brackets which indicates the depth
// of the brackets nesting at that index, and 0 everywhere else. The outermost open and
// closed bracket are both ignored. The open and closed brackets are not considered to be inside
// their bracketed area. It is assumed that the input will contain an equal
// number of closed and open brackets, and that a closed bracket will not appear while there are no unclosed open brackets
// The basic algorithm is:
// 1. Compute an intermediate array where each index is a running sum of all previous indices in the input
// 2. Subtract 1 from each index in the result of step 1 to get a new array. This corresponds to ignoring the single pair of outermost brackets in the running sum from step 1
// 3. For each negative value in the result of step 2, change that value to 0
// 4. For each value greater than 1 compared to the previous value in the result of step 3, decrement that value by 1. This is to fix an off-by-1 error with step 1 in computing nested brackets depth, so that each depth excludes its open bracket. I.e.
// step 4 in:  001112233332100
// step 4 out: 000111223332100
// Example input/output for the entire subcircuit, plus intermediate values
// To preserve alignment, we use * to represent -1:
// str:           a{aaa{a{aaa}aa}aaaa}
// arr:           01000101000*00*0000*
// prelim_out1:   01111223333222111110   full depth map incorrectly including open brackets inside bracket depth counts
// prelim_out2:   *000011222211100000*   removes outermost brackets from depth map
// prelim_out3:   00000112222111000000   replaces negative values with 0s
// out:           00000011222111000000   correctly represents open brackets as being outside of bracket nesting
// out: 0000001122 11 0000 0
template BracketsDepthMap(len) {
    signal input arr[len];
    signal output out[len];

    signal prelim_out1[len];
    signal prelim_out2[len];
    signal prelim_out3[len];
    prelim_out1[0] <== arr[0];
    for (var i = 1; i < len; i++) {
        prelim_out1[i] <== prelim_out1[i-1] + arr[i];
    }

    // Subtracting 1 here from every index amounts to ignoring the outermost
    // open and closed brackets, which is what we want
    for (var i = 0; i < len; i++) {
        prelim_out2[i] <== prelim_out1[i]-1;
    }
    // Remove all negative numbers from the array and set their indices to 0
    for (var i = 0; i < len; i++) {
        var is_neg = LessThan(20)([prelim_out2[i], 0]);
        prelim_out3[i] <== prelim_out2[i] * (1-is_neg);
    }
    // Decrement the positions of open brackets by 1 to remove offset
    for (var i = 1; i < len; i++) {
        var is_inc = IsEqual()([prelim_out3[i], prelim_out3[i-1]+1]);
        out[i] <== prelim_out3[i] - is_inc;
    }
}

// Given a base64-encoded array `in`, max length `maxN`, and actual unpadded length `n`, returns
// the actual length of the decoded string
template Base64DecodedLength(maxN) {
    var max_q = (3 * maxN) \ 4;
    //signal input in[maxN];
    signal input n; // actual lenght
    signal output decoded_len;
    signal q <-- 3*n \ 4;
    signal r <-- 3*n % 4;

    3*n - 4*q - r === 0;
    signal r_correct_reminder <== LessThan(2)([r, 4]);
    r_correct_reminder === 1;

    // use log function to compute log(max_q)
    signal q_correct_quotient <== LessThan(252)([q, max_q]);
    q_correct_quotient === 1;

    // var eq = 61;
    // assumes valid encoding (if last != "=" then second to last is also
    // != "=")
    // TODO: We don't seem to need this, as the jwt spec removes b64 padding
    // see https://datatracker.ietf.org/doc/html/rfc7515#page-54
    //signal l <== SelectArrayValue(maxN)(in, n - 1);
    //signal s2l <== SelectArrayValue(maxN)(in, n - 2);
    //signal s_l <== IsEqual()([l, eq]);
    //signal s_s2l <== IsEqual()([s2l, eq]);
    //signal reducer <== -1*s_l -1*s_s2l;
    //decoded_len <== q + reducer;
    //log("decoded_len", decoded_len);
}