//! Certificate DER parsing and extraction helpers.

use crate::types::Pkcs11InfoResponse;
use base64::Engine as _;
use der::{Decode, Encode};
use x509_cert::Certificate;

/// DER byte offsets for in-circuit modulus extraction.
#[derive(Debug)]
pub struct CertOffsets {
    pub modulus_offset: usize,     // first real modulus byte (after sign byte)
    pub modulus_tag_offset: usize, // where 0x02 INTEGER tag is
}

/// Strip leading zero bytes from a DER INTEGER before hex-encoding.
pub fn serial_bytes_to_hex_trimmed(serial_bytes: &[u8]) -> String {
    let first_nonzero = serial_bytes.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(i) => hex::encode(&serial_bytes[i..]),
        None => hex::encode(serial_bytes),
    }
}

/// Find the RSA modulus byte offsets in a DER-encoded certificate.
pub fn parse_cert_offsets(der: &[u8]) -> Result<CertOffsets, Box<dyn std::error::Error>> {
    let (modulus_offset, modulus_tag_offset) = find_modulus_offset(der)?;

    if der[modulus_tag_offset] != 0x02 {
        return Err(format!(
            "Modulus INTEGER tag wrong at {}: got 0x{:02x}",
            modulus_tag_offset, der[modulus_tag_offset]
        )
        .into());
    }

    Ok(CertOffsets {
        modulus_offset,
        modulus_tag_offset,
    })
}

fn find_modulus_offset(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let cert = Certificate::from_der(der)?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;

    let spki_abs = find_subslice(der, &spki_der).ok_or("SPKI not found in cert DER")?;

    let mut pos = 0usize;

    // Skip outer SPKI SEQUENCE tag + length
    pos += 1;
    let (_, lb) = read_der_len(&spki_der, pos);
    pos += lb;

    // Skip AlgorithmIdentifier SEQUENCE tag + length + content
    pos += 1;
    let (alg_len, alb) = read_der_len(&spki_der, pos);
    pos += alb + alg_len;

    // Skip BIT STRING tag + length + unused-bits byte (0x00)
    pos += 1;
    let (_, blb) = read_der_len(&spki_der, pos);
    pos += blb;
    pos += 1; // unused bits byte

    // Skip RSAPublicKey SEQUENCE tag + length
    pos += 1;
    let (_, slb) = read_der_len(&spki_der, pos);
    pos += slb;

    // Now at INTEGER tag for modulus
    if spki_der[pos] != 0x02 {
        return Err(format!(
            "Expected INTEGER tag at spki pos {}, got 0x{:02x}",
            pos, spki_der[pos]
        )
        .into());
    }
    let tag_pos = pos;
    pos += 1;

    // Skip length field
    let (_mod_len, mlb) = read_der_len(&spki_der, pos);
    pos += mlb;

    // Skip leading 0x00 sign byte if present
    if spki_der[pos] == 0x00 {
        pos += 1;
    }

    Ok((spki_abs + pos, spki_abs + tag_pos))
}

fn read_der_len(der: &[u8], pos: usize) -> (usize, usize) {
    if der[pos] & 0x80 == 0 {
        (der[pos] as usize, 1)
    } else {
        let num_len_bytes = (der[pos] & 0x7f) as usize;
        let value =
            (0..num_len_bytes).fold(0usize, |acc, i| (acc << 8) | der[pos + 1 + i] as usize);
        (value, 1 + num_len_bytes)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Pull the "CA Cert"-labelled issuer certificate from the first slot's token.
pub fn extract_issuer_cert(
    pkcs11info: &Pkcs11InfoResponse,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let certs = pkcs11info
        .slots
        .first()
        .and_then(|s| s.token.as_ref())
        .map(|t| &t.certs)
        .ok_or("No token found in pkcs11info response")?;

    let ca_entry = certs
        .iter()
        .find(|c| c.label == "CA Cert")
        .ok_or("No cert with label 'CA Cert' found in pkcs11info response")?;

    let der = base64::engine::general_purpose::STANDARD.decode(&ca_entry.certb64)?;
    Ok(Certificate::from_der(&der)?)
}

pub fn fetch_cert_from_file(path: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    Ok(Certificate::from_der(&std::fs::read(path)?)?)
}

pub fn generate_user_cert_from_certb64(
    certb64: &str,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let der = base64::engine::general_purpose::STANDARD.decode(certb64)?;
    Ok(Certificate::from_der(&der)?)
}
