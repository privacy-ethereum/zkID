use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use bellpepper_core::SynthesisError;
use rust_witness::BigInt;
use serde_json::Value;
use std::{collections::HashMap, ops::Range, str::FromStr};

use crate::Scalar;

#[derive(Clone, Copy)]
pub enum FieldParser {
    BigIntScalar,
    U64Scalar,
    BigIntArray,
    U64Array,
    BigInt2DArray,
}

/// Generic function to parse input fields from JSON based on field definitions
pub fn parse_inputs(
    json_value: &Value,
    field_defs: &[(&str, FieldParser)],
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let mut inputs = HashMap::new();

    for (field_name, parser) in field_defs {
        let value = match parser {
            FieldParser::BigIntScalar => {
                vec![parse_bigint_scalar(json_value, field_name)
                    .map_err(|_| SynthesisError::AssignmentMissing)?]
            }
            FieldParser::U64Scalar => {
                vec![parse_u64_scalar(json_value, field_name)
                    .map_err(|_| SynthesisError::AssignmentMissing)?]
            }
            FieldParser::BigIntArray => parse_bigint_string_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
            FieldParser::U64Array => parse_u64_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
            FieldParser::BigInt2DArray => parse_2d_bigint_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        };
        inputs.insert(field_name.to_string(), value);
    }

    Ok(inputs)
}

// Circuit-specific input parsers
/// Parse JWT circuit inputs from JSON
pub fn parse_jwt_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        // BigInt scalar fields (wrapped in vec)
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("pubKeyX", FieldParser::BigIntScalar),
        ("pubKeyY", FieldParser::BigIntScalar),
        // U64 scalar fields (wrapped in vec)
        ("messageLength", FieldParser::U64Scalar),
        ("periodIndex", FieldParser::U64Scalar),
        ("matchesCount", FieldParser::U64Scalar),
        // Array fields
        ("message", FieldParser::BigIntArray),
        ("matchIndex", FieldParser::U64Array),
        ("matchLength", FieldParser::U64Array),
        ("claimLengths", FieldParser::BigIntArray),
        ("decodeFlags", FieldParser::U64Array),
        // 2D array fields (flattened)
        ("matchSubstring", FieldParser::BigInt2DArray),
        ("claims", FieldParser::BigInt2DArray),
        ("ageClaimIndex", FieldParser::U64Scalar),
    ];

    parse_inputs(json_value, field_defs)
}

/// Parse Show circuit inputs from JSON
pub fn parse_show_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        // BigInt scalar fields (wrapped in vec)
        ("deviceKeyX", FieldParser::BigIntScalar),
        ("deviceKeyY", FieldParser::BigIntScalar),
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("messageHash", FieldParser::BigIntScalar),
        ("claim", FieldParser::BigIntArray),
        ("currentYear", FieldParser::BigIntScalar),
        ("currentMonth", FieldParser::BigIntScalar),
        ("currentDay", FieldParser::BigIntScalar),
    ];

    parse_inputs(json_value, field_defs)
}

/// Convert a single BigInt to Scalar
pub fn bigint_to_scalar(bigint_val: BigInt) -> Result<Scalar, SynthesisError> {
    let bytes = bigint_val.to_bytes_le().1;

    // Validate size before padding
    if bytes.len() > 32 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);

    Scalar::from_bytes(&padded)
        .into_option()
        .ok_or(SynthesisError::Unsatisfiable)
}

pub fn convert_bigint_to_scalar(
    bigint_witness: Vec<BigInt>,
) -> Result<Vec<Scalar>, SynthesisError> {
    bigint_witness.into_iter().map(bigint_to_scalar).collect()
}

#[derive(Debug, Clone)]
pub struct PrepareSharedScalars {
    pub keybinding_x: Scalar,
    pub keybinding_y: Scalar,
    pub claim_scalars: Vec<Scalar>,
}

pub fn compute_prepare_shared_scalars(
    root_json: &Value,
) -> Result<PrepareSharedScalars, SynthesisError> {
    let message_length = root_json
        .get("messageLength")
        .and_then(|value| value.as_u64())
        .ok_or(SynthesisError::AssignmentMissing)? as usize;

    let message_values = root_json
        .get("message")
        .and_then(|value| value.as_array())
        .ok_or(SynthesisError::AssignmentMissing)?;

    let mut truncated_message = Vec::with_capacity(message_length);
    for value in message_values.iter().take(message_length) {
        truncated_message.push(parse_byte(value)?);
    }

    let jwt_ascii: Vec<u8> = truncated_message
        .iter()
        .take_while(|byte| **byte != 0)
        .filter(|byte| byte.is_ascii())
        .copied()
        .collect();

    let jwt_string = String::from_utf8(jwt_ascii).map_err(|_| SynthesisError::AssignmentMissing)?;

    let jwt_parts: Vec<&str> = jwt_string.split('.').collect();
    if jwt_parts.len() < 2 {
        return Err(SynthesisError::AssignmentMissing);
    }
    let payload_b64 = jwt_parts[1];

    let payload_bytes = decode_base64(payload_b64)?;
    let payload_json: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| SynthesisError::AssignmentMissing)?;

    extract_prepare_shared_data(&payload_json, root_json)
}

pub fn extract_prepare_shared_data(
    payload_json: &Value,
    root_json: &Value,
) -> Result<PrepareSharedScalars, SynthesisError> {
    let jwk = payload_json
        .get("cnf")
        .and_then(|value| value.get("jwk"))
        .ok_or(SynthesisError::AssignmentMissing)?;

    let keybinding_x_b64 = jwk
        .get("x")
        .and_then(|value| value.as_str())
        .ok_or(SynthesisError::AssignmentMissing)?;

    let keybinding_y_b64 = jwk
        .get("y")
        .and_then(|value| value.as_str())
        .ok_or(SynthesisError::AssignmentMissing)?;

    let keybinding_x_bigint = bytes_to_bigint(&decode_base64(keybinding_x_b64)?);
    let keybinding_y_bigint = bytes_to_bigint(&decode_base64(keybinding_y_b64)?);

    let age_claim_index = root_json
        .get("ageClaimIndex")
        .and_then(|value| value.as_u64())
        .ok_or(SynthesisError::AssignmentMissing)? as usize;

    let claims = root_json
        .get("claims")
        .and_then(|value| value.as_array())
        .ok_or(SynthesisError::AssignmentMissing)?;

    let claim_values = claims
        .get(age_claim_index)
        .and_then(|value| value.as_array())
        .ok_or(SynthesisError::AssignmentMissing)?;

    let claim_bytes = claim_values
        .iter()
        .map(parse_byte)
        .collect::<Result<Vec<_>, _>>()?;

    let max_claim_length = claim_values.len();
    if max_claim_length == 0 {
        return Err(SynthesisError::AssignmentMissing);
    }

    let claim_lengths = root_json
        .get("claimLengths")
        .and_then(|value| value.as_array())
        .ok_or(SynthesisError::AssignmentMissing)?;

    let encoded_claim_len_value = claim_lengths
        .get(age_claim_index)
        .ok_or(SynthesisError::AssignmentMissing)?;

    let encoded_claim_len = match encoded_claim_len_value {
        Value::String(s) => s
            .parse::<usize>()
            .map_err(|_| SynthesisError::AssignmentMissing)?,
        Value::Number(n) => n
            .as_u64()
            .map(|value| value as usize)
            .ok_or(SynthesisError::AssignmentMissing)?,
        _ => return Err(SynthesisError::AssignmentMissing),
    };

    if encoded_claim_len > claim_bytes.len() {
        return Err(SynthesisError::AssignmentMissing);
    }

    let encoded_claim = String::from_utf8(claim_bytes[..encoded_claim_len].to_vec())
        .map_err(|_| SynthesisError::AssignmentMissing)?;

    let decoded_claim_bytes = decode_base64(&encoded_claim)?;
    let decoded_len = (max_claim_length * 3) / 4;

    if decoded_claim_bytes.len() > decoded_len {
        return Err(SynthesisError::AssignmentMissing);
    }

    let mut claim_scalars: Vec<Scalar> = decoded_claim_bytes
        .into_iter()
        .map(|byte| Scalar::from(byte as u64))
        .collect();

    while claim_scalars.len() < decoded_len {
        claim_scalars.push(Scalar::from(0u64));
    }

    let keybinding_x = bigint_to_scalar(keybinding_x_bigint)?;
    let keybinding_y = bigint_to_scalar(keybinding_y_bigint)?;

    Ok(PrepareSharedScalars {
        keybinding_x,
        keybinding_y,
        claim_scalars,
    })
}

pub fn parse_byte(value: &Value) -> Result<u8, SynthesisError> {
    if let Some(as_str) = value.as_str() {
        let parsed = as_str
            .parse::<u16>()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        return u8::try_from(parsed).map_err(|_| SynthesisError::AssignmentMissing);
    }

    if let Some(as_u64) = value.as_u64() {
        return u8::try_from(as_u64).map_err(|_| SynthesisError::AssignmentMissing);
    }

    Err(SynthesisError::AssignmentMissing)
}

pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, SynthesisError> {
    if encoded.len() % 4 == 1 {
        return Err(SynthesisError::AssignmentMissing);
    }

    let mut candidates = vec![encoded.to_string()];

    let mut padded = encoded.to_string();
    match encoded.len() % 4 {
        0 => {}
        2 => padded.push_str("=="),
        3 => padded.push('='),
        _ => {}
    }

    if padded != encoded {
        candidates.push(padded);
    }

    for candidate in candidates {
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = URL_SAFE.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
    }

    Err(SynthesisError::AssignmentMissing)
}

// JSON Parsing Helpers
/// Parse a single BigInt from a string field
fn parse_bigint_scalar(json: &Value, key: &str) -> Result<BigInt, String> {
    let s = json
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or("Field must be a string")?;
    BigInt::from_str(s).map_err(|_| "Failed to parse as BigInt".to_string())
}

/// Parse a single u64 from a number field and convert to BigInt
fn parse_u64_scalar(json: &Value, key: &str) -> Result<BigInt, String> {
    json.get(key)
        .and_then(|v| v.as_u64())
        .map(BigInt::from)
        .ok_or("Field must be a number".to_string())
}

/// Parse an array of BigInt strings
fn parse_bigint_string_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    let array = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?;

    array
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or("Array element must be a string")?;
            BigInt::from_str(s).map_err(|_| "Failed to parse array element as BigInt".to_string())
        })
        .collect()
}

/// Parse an array of u64 numbers and convert to BigInt
fn parse_u64_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    json.get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?
        .iter()
        .map(|v| {
            v.as_u64()
                .map(BigInt::from)
                .ok_or("Array element must be a number".to_string())
        })
        .collect()
}

/// Parse a 2D array of BigInt strings and flatten into 1D vector
fn parse_2d_bigint_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    let outer_array = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?;

    // Pre-calculate total capacity
    let total_capacity: usize = outer_array
        .iter()
        .filter_map(|v| v.as_array())
        .map(|arr| arr.len())
        .sum();

    let mut result = Vec::with_capacity(total_capacity);

    for inner_value in outer_array.iter() {
        let inner_array = inner_value
            .as_array()
            .ok_or("Outer array element must be an array")?;

        for v in inner_array.iter() {
            let s = v.as_str().ok_or("Inner array element must be a string")?;
            let bigint =
                BigInt::from_str(s).map_err(|_| "Failed to parse inner array element as BigInt")?;
            result.push(bigint);
        }
    }

    Ok(result)
}

fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    let mut acc = BigInt::from(0u8);
    for &byte in bytes {
        acc = (acc << 8) + BigInt::from(byte);
    }
    acc
}

/// Layout information for the JWT circuit outputs within the witness vector.
#[derive(Debug, Clone, Copy)]
pub struct JwtOutputLayout {
    pub age_claim_start: usize,
    pub age_claim_len: usize,
    pub keybinding_x_index: usize,
    pub keybinding_y_index: usize,
}

impl JwtOutputLayout {
    pub fn age_claim_range(&self) -> Range<usize> {
        self.age_claim_start..self.age_claim_start + self.age_claim_len
    }
}

/// Calculate output signal indices for JWT circuit based on circuit parameters.
///
/// JWT circuit outputs (in order):
/// 1. `ageClaim[decodedLen]` where `decodedLen = (maxClaimsLength * 3) / 4`
/// 2. `KeyBindingX`
/// 3. `KeyBindingY`
///
/// Parameters: `[maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength]`
pub fn calculate_jwt_output_indices(
    _max_matches: usize,
    max_claims_length: usize,
) -> JwtOutputLayout {
    let decoded_len = (max_claims_length * 3) / 4;
    let age_claim_start = 1; // Index 0 is reserved for the constant signal in Circom witness
    let keybinding_x_index = age_claim_start + decoded_len;
    let keybinding_y_index = keybinding_x_index + 1;

    JwtOutputLayout {
        age_claim_start,
        age_claim_len: decoded_len,
        keybinding_x_index,
        keybinding_y_index,
    }
}
