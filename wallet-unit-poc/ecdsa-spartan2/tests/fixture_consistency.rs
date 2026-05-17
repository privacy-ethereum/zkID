//! Asserts the bundled fixture's signature is a valid PKCS#1 v1.5 signature
//! over `SHA-256(DEFAULT_TBS)`.

use ecdsa_spartan2::DEFAULT_TBS;

#[test]
fn fixture_signature_matches_default_tbs() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
        signature::Verifier,
        RsaPublicKey,
    };
    use sha2::Sha256;
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
    };

    let response_str = std::fs::read_to_string("tests/testdata/response_sign_test.json")
        .expect("response_sign_test.json not found — run `cargo run --example generate_fixtures` first");
    let response: serde_json::Value = serde_json::from_str(&response_str)
        .expect("invalid JSON in response_sign_test.json");

    let cert_der = B64
        .decode(response["certb64"].as_str().expect("missing certb64 field"))
        .expect("certb64 base64 decode failed");
    let sig_bytes = B64
        .decode(response["signature"].as_str().expect("missing signature field"))
        .expect("signature base64 decode failed");

    let cert = Certificate::from_der(&cert_der).expect("cert DER parse failed");
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("SPKI encode failed");
    let pub_key =
        RsaPublicKey::from_public_key_der(&spki_der).expect("RSA pub key decode failed");

    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    let signature =
        Signature::try_from(sig_bytes.as_slice()).expect("signature format invalid");

    verifying_key.verify(DEFAULT_TBS, &signature).expect(
        "Fixture signature does not match SHA-256(DEFAULT_TBS). \
         Regenerate with: cargo run --example generate_fixtures",
    );
}

#[test]
fn fixture_rs4096_signature_matches_default_tbs() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
        signature::Verifier,
        RsaPublicKey,
    };
    use sha2::Sha256;
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
    };

    let response_str = std::fs::read_to_string("tests/testdata/rs4096_response_sign.json")
        .expect("rs4096_response_sign.json not found — run `cargo run --example generate_fixtures` first");
    let response: serde_json::Value =
        serde_json::from_str(&response_str).expect("invalid JSON in rs4096_response_sign.json");

    let cert_b64 = response["result"]["cert"].as_str().expect("missing result.cert");
    let sig_b64 = response["result"]["signed_response"].as_str().expect("missing result.signed_response");

    let cert_der = B64.decode(cert_b64).expect("cert base64 decode failed");
    let sig_bytes = B64.decode(sig_b64).expect("signature base64 decode failed");

    let cert = Certificate::from_der(&cert_der).expect("cert DER parse failed");
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("SPKI encode failed");
    let pub_key =
        RsaPublicKey::from_public_key_der(&spki_der).expect("RSA pub key decode failed");

    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    let signature =
        Signature::try_from(sig_bytes.as_slice()).expect("signature format invalid");

    verifying_key.verify(DEFAULT_TBS, &signature).expect(
        "RS4096 fixture signature does not match SHA-256(DEFAULT_TBS). \
         Regenerate with: cargo run --example generate_fixtures",
    );
}

#[test]
fn fixture_user_sig_input_is_valid_json() {
    let input_str = std::fs::read_to_string("../circom/inputs/user_sig_rs2048/input.json")
        .expect("user_sig_rs2048/input.json not found");
    let input: serde_json::Value =
        serde_json::from_str(&input_str).expect("invalid JSON in user_sig input");

    for key in [
        "tbs",
        "userPkLimbs",
        "userRsaSignature",
        "pkBlind",
    ] {
        assert!(
            input.get(key).is_some(),
            "user_sig input missing key: {key}"
        );
    }

    assert_eq!(
        input["tbs"].as_array().unwrap().len(),
        1536,
        "tbs array must have maxMessageLength=1536 elements"
    );
    assert_eq!(
        input["userPkLimbs"].as_array().unwrap().len(),
        17,
        "userPkLimbs must have k=17 limbs for RSA-2048"
    );
    assert_eq!(
        input["userRsaSignature"].as_array().unwrap().len(),
        17,
        "userRsaSignature must have k=17 limbs for RSA-2048"
    );
}

#[test]
fn fixture_pk_blind_matches_across_inputs() {
    let cc_str = std::fs::read_to_string("../circom/inputs/cert_chain_rs2048/input.json")
        .expect("cert_chain_rs2048/input.json not found");
    let ds_str = std::fs::read_to_string("../circom/inputs/user_sig_rs2048/input.json")
        .expect("user_sig_rs2048/input.json not found");

    let cc: serde_json::Value = serde_json::from_str(&cc_str).unwrap();
    let ds: serde_json::Value = serde_json::from_str(&ds_str).unwrap();

    let cc_blind = cc["pkBlind"]
        .as_str()
        .expect("cert_chain pkBlind not a string");
    let ds_blind = ds["pkBlind"]
        .as_str()
        .expect("user_sig pkBlind not a string");

    assert_eq!(
        cc_blind, ds_blind,
        "pkBlind must match between cert_chain_rs2048 and user_sig_rs2048 fixtures"
    );
}
