use bellpepper_core::SynthesisError;
use rust_witness::BigInt;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr};

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

/// Calculate output signal indices for JWT circuit based on circuit parameters
/// This avoids parsing the large .sym file by calculating indices from known circuit structure.
///
/// JWT circuit outputs:
/// 1. messages[maxMatches][decodedLen] where decodedLen = (maxClaimsLength * 3) / 4
/// 2. KeyBindingX (single scalar)
/// 3. KeyBindingY (single scalar)
///
/// Parameters: [maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength]
/// Example: [2048, 2000, 4, 50, 128]
pub fn calculate_jwt_output_indices(
    max_matches: usize,
    max_claims_length: usize,
) -> (usize, usize) {
    // decodedLen = (maxClaimsLength * 3) / 4
    let decoded_len = (max_claims_length * 3) / 4;

    // messages array size: maxMatches * decodedLen
    let messages_size = max_matches * decoded_len;

    // In Circom, outputs are placed after all intermediate signals
    // The messages output starts at index 1 (after constant 1 at index 0)
    // KeyBindingX comes after messages, KeyBindingY after KeyBindingX
    let keybinding_x_index = 1 + messages_size; // After messages array
    let keybinding_y_index = keybinding_x_index + 1; // After KeyBindingX

    (keybinding_x_index, keybinding_y_index)
}
