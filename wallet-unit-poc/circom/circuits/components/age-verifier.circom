pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

template AgeExtractor() {
    signal input YYMMDD[7];
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal output age;

    signal birthROCYear <== YYMMDD[0]*100 + YYMMDD[1]*10 + YYMMDD[2];
    signal birthYear    <== birthROCYear + 1911;
    signal birthMonth   <== YYMMDD[3]*10 + YYMMDD[4];
    signal birthDay     <== YYMMDD[5]*10 + YYMMDD[6];

    // raw year difference
    signal rawAge <== currentYear - birthYear;

    // month > birthMonth?
    component mGt = GreaterThan(4);
    mGt.in[0] <== currentMonth;
    mGt.in[1] <== birthMonth;

    // month == birthMonth?
    component mEq = IsEqual();
    mEq.in[0] <== currentMonth;
    mEq.in[1] <== birthMonth;

    // currentDay ≥ birthDay?
    component dGe = GreaterEqThan(5);
    dGe.in[0] <== currentDay;
    dGe.in[1] <== birthDay;

    // had birthday this year?
    signal hadBirthday;
    hadBirthday <== mGt.out + mEq.out * dGe.out;

    // final age = rawAge - 1 + hadBirthday
    age <== rawAge - 1 + hadBirthday;
}

template AgeVerifier(decodedLen) {
    signal input claim[decodedLen];  // ASCII codes of decoded base64: ["…","roc_birthday","0750101"]
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal output ageAbove18;


    component isQuoteCmp[decodedLen];
    signal    isQuote[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
        isQuoteCmp[i] = IsEqual();
        isQuoteCmp[i].in[0] <== claim[i];
        isQuoteCmp[i].in[1] <== 34;
        isQuote[i]    <== isQuoteCmp[i].out;
    }

    signal quoteCount[decodedLen];
    quoteCount[0] <== isQuote[0];
    for (var i = 1; i < decodedLen; i++) {
        quoteCount[i] <== quoteCount[i-1] + isQuote[i];
    }
    quoteCount[decodedLen-1] === 6;

    component isThirdQuoteChar[decodedLen];
    signal   isThird[decodedLen];
    for (var i = 0; i < decodedLen; i++) {
    isThirdQuoteChar[i] = IsEqual();
    isThirdQuoteChar[i].in[0] <== quoteCount[i];
    isThirdQuoteChar[i].in[1] <== 5;
    isThird[i] <== isThirdQuoteChar[i].out;
    }
   
    
  signal thirdCount[decodedLen];
  thirdCount[0] <== isThird[0];
  for (var i = 1; i < decodedLen; i++) {
    thirdCount[i] <== thirdCount[i-1] + isThird[i];
  }
  thirdCount[decodedLen - 1] === 8;// one opening-quote + seven digits YYMMDD + one closing-quote


    component digitEq[7][decodedLen];
    signal   matchDigit[7][decodedLen];
    signal   digitAcc[7][decodedLen];
    signal   birthDigits[7];

    for (var j = 0; j < 7; j++) {
      for (var i = 0; i < decodedLen; i++) {
        digitEq[j][i] = IsEqual();
        digitEq[j][i].in[0] <== thirdCount[i];
        digitEq[j][i].in[1] <== j + 2;

        matchDigit[j][i] <== digitEq[j][i].out * isThird[i];

        if (i == 0) {
          digitAcc[j][0] <== matchDigit[j][0] * (claim[0] - 48);
        } else {
          digitAcc[j][i] <== digitAcc[j][i-1]
                         + matchDigit[j][i] * (claim[i] - 48);
        }
      }
      birthDigits[j] <== digitAcc[j][decodedLen - 1];
    }


    component ageExtractor = AgeExtractor();
    ageExtractor.YYMMDD <== birthDigits;
    ageExtractor.currentYear <== currentYear;
    ageExtractor.currentMonth <== currentMonth;
    ageExtractor.currentDay <== currentDay;

    component ageAbove18Checker = GreaterThan(8);
    ageAbove18Checker.in[0] <== ageExtractor.age;
    ageAbove18Checker.in[1] <== 18;
    ageAbove18 <== ageAbove18Checker.out;
}

