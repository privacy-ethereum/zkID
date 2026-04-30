pragma circom 2.2.3;

include "rs256.circom";
include "components/pk_commit.circom";

/// @title CertChainRSA256
/// @notice Circuit A of the CertChain + DeviceSig pair. Proves: "I hold a
///         non-revoked, MOICA-issued cert whose RSA public key hashes (with
///         pk_blind) to pk_commit." Issuer RSA params are separate from user
///         params so MOICA-G3's 4096-bit CA can certify a 2048-bit user key.
///         pk_commit is computed over k_user limbs so it byte-matches
///         DeviceSigRSA256's; the verifier checks `pk_commit_A == pk_commit_B`
///         to prevent proof-mixing.
///
/// @param maxMessageLength    Max TBS / cert byte length (1536)
/// @param n                   RSA limb bits (e.g. 121)
/// @param k_issuer            Issuer RSA limb count (17 for G2, 34 for G3)
/// @param modulusBitsIssuer   Issuer RSA key bits (2048 for G2, 4096 for G3)
/// @param k_user              User RSA limb count (always 17 — MOICA user keys are 2048-bit)
/// @param modulusBitsUser     User RSA key bits (always 2048)
/// @param maxSubjectDNLength  Max subject DN bytes (e.g. 128)
/// @param smtDepth            SMT non-membership proof depth (e.g. 128)
/// @param maxSerialNumberLength  Max cert serial bytes (e.g. 16)
template CertChainRSA256(
    maxMessageLength,
    n,
    k_issuer,
    modulusBitsIssuer,
    k_user,
    modulusBitsUser,
    maxSubjectDNLength,
    smtDepth,
    maxSerialNumberLength
) {
    // === User cert ===
    signal input user_cert_zero_padded[maxMessageLength];
    signal input actual_user_cert_length;
    signal input user_modulus_offset;
    signal input user_modulus_tag_offset;

    // === Subject DN extraction ===
    signal input subject_dn[maxSubjectDNLength];
    signal input subject_dn_offset;
    signal input subject_dn_length;

    // === Serial extraction ===
    signal input serial_number_offset;

    // === Issuer (cert chain) — sized to k_issuer ===
    signal input issuer_tbs[maxMessageLength];
    signal input issuer_tbs_length;
    signal input actual_issuer_tbs_length;
    signal input issuer_rsa_modulus[k_issuer];
    signal input issuer_rsa_signature[k_issuer];

    // === Revocation (SMT non-membership) ===
    signal input smtRoot;
    signal input serialNumber;
    signal input smtSiblings[smtDepth];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // === Linking (private; same value used in DeviceSigRSA256) ===
    signal input pk_blind;

    // === Outputs ===
    signal output pk_commit;

    VerifyTBSinCert(maxMessageLength, maxMessageLength)(
        user_cert_zero_padded,
        issuer_tbs,
        actual_issuer_tbs_length
    );

    VerifySubjectDN(maxMessageLength, maxSubjectDNLength)(
        user_cert_zero_padded,
        subject_dn,
        subject_dn_offset,
        subject_dn_length
    );

    VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
        user_cert_zero_padded,
        serial_number_offset,
        serialNumber
    );

    signal user_rsa_extracted_modulus[k_user];
    ExtractModulus(maxMessageLength, n, k_user, modulusBitsUser)(
        in               <== user_cert_zero_padded,
        modulusOffset    <== user_modulus_offset,
        modulusTagOffset <== user_modulus_tag_offset
    ) ==> user_rsa_extracted_modulus;

    CertRSA256Verify(maxMessageLength, n, k_issuer)(
        issuer_tbs,
        issuer_tbs_length,
        issuer_rsa_modulus,
        issuer_rsa_signature
    );

    SMTNonMembershipVerifier(smtDepth)(
        smtRoot,
        serialNumber,
        smtSiblings,
        smtOldKey,
        smtOldValue,
        smtIsOld0
    );

    // Sized to k_user so pk_commit byte-matches DeviceSigRSA256's output.
    component pkCommit = ChunkedPoseidonP256(k_user + 1);
    for (var i = 0; i < k_user; i++) {
        pkCommit.inputs[i] <== user_rsa_extracted_modulus[i];
    }
    pkCommit.inputs[k_user] <== pk_blind;
    pk_commit <== pkCommit.out;
}
