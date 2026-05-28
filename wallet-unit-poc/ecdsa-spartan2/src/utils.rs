use bellpepper_core::SynthesisError;
use num_bigint::BigInt;
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
/// Parse JWT circuit inputs from JSON.
///
/// Matches the current `JWT(...)` template in `circom/circuits/jwt.circom`:
/// `claimFormats[]` is required, `ageClaimIndex` was removed when
/// the circuit switched to per-slot claim normalization.
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
        ("claimFormats", FieldParser::BigIntArray),
        // 2D array fields (flattened)
        ("matchSubstring", FieldParser::BigInt2DArray),
        ("claims", FieldParser::BigInt2DArray),
    ];

    parse_inputs(json_value, field_defs)
}

/// Parse Show circuit inputs from JSON.
///
/// Matches the current `Show(nClaims, maxPredicates, maxLogicTokens, valueBits)`
/// template: predicates + RPN logic expression replaced the old
/// `claim/currentYear/currentMonth/currentDay` interface.
///
/// Predicate RHS encoding uses a single `predicateRhsValues[]` array:
/// - when `predicateRhsIsRef[i] = 0`, `predicateRhsValues[i]` is a literal value
/// - when `predicateRhsIsRef[i] = 1`, `predicateRhsValues[i]` is a claim index
///
/// This supports both attribute-to-literal and attribute-to-attribute comparisons.
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
        ("predicateLen", FieldParser::BigIntScalar),
        ("exprLen", FieldParser::BigIntScalar),
        // Array fields
        ("claimValues", FieldParser::BigIntArray),
        ("predicateClaimRefs", FieldParser::BigIntArray),
        ("predicateOps", FieldParser::BigIntArray),
        ("predicateRhsIsRef", FieldParser::BigIntArray),
        ("predicateRhsValues", FieldParser::BigIntArray),
        ("tokenTypes", FieldParser::BigIntArray),
        ("tokenValues", FieldParser::BigIntArray),
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

/// Parses the Circom witness binary format (.wtns) directly to Scalar vector
pub fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<Scalar>, SynthesisError> {
    let mut pos = 0;

    // Validate .wtns header (4 bytes magic)
    if witness_bytes.len() < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 4;

    // Skip version (4 bytes)
    pos += 4;

    // Read number of sections (4 bytes)
    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;

    // Number of bytes per field element (from section 1)
    let mut n8 = 0;

    // Iterate through sections to find witness data (section_id = 2)
    for _ in 0..n_sections {
        if pos + 12 > witness_bytes.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let section_id = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let section_length =
            u64::from_le_bytes(witness_bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        match section_id {
            // Section 1: Header metadata
            // Contains n8 (4 bytes), field q (32 bytes), n_witness_values (4 bytes)
            1 => {
                if pos + 4 > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                pos += section_length; // Skip entire section
            }

            // Section 2: Witness data
            // Contains witness elements (n8 bytes each)
            2 => {
                if n8 == 0 {
                    return Err(SynthesisError::Unsatisfiable);
                }

                if pos + section_length > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                // Parse witness elements directly to Scalar
                let witness_data = &witness_bytes[pos..pos + section_length];
                let num_elements = section_length / n8;

                let mut scalars = Vec::with_capacity(num_elements);

                for chunk in witness_data.chunks(n8) {
                    // Pad to 32 bytes if needed (n8 might be less than 32)
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);

                    // Convert to Scalar
                    let scalar = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(scalar);
                }

                return Ok(scalars);
            }

            // Skip any other section
            _ => {
                pos += section_length;
            }
        }
    }

    Err(SynthesisError::Unsatisfiable)
}

/// Convert HashMap<String, Vec<BigInt>> to JSON string for witnesscalc_adapter.
/// Reconstructs 2D arrays for fields that were flattened during parsing.
pub fn hashmap_to_json_string(
    inputs: &HashMap<String, Vec<BigInt>>,
    max_matches: usize,
    max_substring_length: usize,
    max_claims_length: usize,
) -> Result<String, SynthesisError> {
    use serde_json::json;

    let mut json_map = serde_json::Map::new();

    // Define 2D array fields and their dimensions (rows, cols).
    // `claims` is sized `maxClaims = maxMatches - 2` because the first two
    // match slots are reserved for the device-binding key extraction.
    let max_claims = max_matches.saturating_sub(2);
    let two_d_fields: HashMap<&str, (usize, usize)> = [
        ("claims", (max_claims, max_claims_length)),
        ("matchSubstring", (max_matches, max_substring_length)),
    ]
    .iter()
    .cloned()
    .collect();

    for (key, values) in inputs.iter() {
        // Check if this is a 2D array field
        if let Some(&(rows, cols)) = two_d_fields.get(key.as_str()) {
            // Reconstruct 2D array from flattened 1D array
            let mut array_2d = Vec::with_capacity(rows);
            for i in 0..rows {
                let start = i * cols;
                let end = start + cols;
                if end <= values.len() {
                    let row: Vec<String> = values[start..end]
                        .iter()
                        .map(|bigint| bigint.to_string())
                        .collect();
                    array_2d.push(json!(row));
                } else {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            json_map.insert(key.clone(), json!(array_2d));
        } else {
            // Regular 1D array
            let string_array: Vec<String> =
                values.iter().map(|bigint| bigint.to_string()).collect();
            json_map.insert(key.clone(), json!(string_array));
        }
    }

    serde_json::to_string(&json_map).map_err(|_| SynthesisError::Unsatisfiable)
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

/// Layout of the JWT (Prepare) circuit's public outputs within the witness vector.
///
/// JWT circuit outputs (in order, derived from `circom/circuits/jwt.circom`):
/// 1. `normalizedClaimValues[n_claims]` where `n_claims = maxMatches - 2`
/// 2. `KeyBindingX`
/// 3. `KeyBindingY`
///
/// Verified against `build/jwt_1k/jwt_1k.sym`:
///   witness[1] = main.normalizedClaimValues[0]
///   witness[2] = main.normalizedClaimValues[1]
///   witness[3] = main.KeyBindingX
///   witness[4] = main.KeyBindingY
#[derive(Debug, Clone, Copy)]
pub struct JwtOutputLayout {
    /// Witness index of `normalizedClaimValues[0]`. Always `1` (index 0 is the
    /// constant-1 signal that every Circom witness reserves).
    pub claim_values_start: usize,
    /// Number of normalized claim values, equal to `maxMatches - 2`.
    pub claim_values_len: usize,
    pub keybinding_x_index: usize,
    pub keybinding_y_index: usize,
}

impl JwtOutputLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }

    /// Total number of public outputs (`normalizedClaimValues + KeyBindingX + KeyBindingY`).
    pub fn num_public(&self) -> usize {
        self.claim_values_len + 2
    }
}

/// Calculate JWT circuit witness layout from the circuit's template parameters.
pub fn calculate_jwt_output_indices(
    max_matches: usize,
    _max_claims_length: usize,
) -> JwtOutputLayout {
    let claim_values_len = max_matches.saturating_sub(2);
    let claim_values_start = 1;
    let keybinding_x_index = claim_values_start + claim_values_len;
    let keybinding_y_index = keybinding_x_index + 1;

    JwtOutputLayout {
        claim_values_start,
        claim_values_len,
        keybinding_x_index,
        keybinding_y_index,
    }
}

/// Layout of the Show circuit's witness vector.
///
/// Verified against `build/show/show.sym` (`Show(2, 2, 8, 64)`):
///   witness[1] = main.expressionResult (output)
///   witness[2] = main.deviceKeyX       (public input)
///   witness[3] = main.deviceKeyY       (public input)
///   witness[4] = main.sig_r            (private)
///   witness[5] = main.sig_s_inverse    (private)
///   witness[6] = main.predicateLen     (private)
///   witness[7..7+n_claims] = main.claimValues[..]
///
/// Note: `main.messageHash` shows `witness_idx = -1` in show.sym, so it does
/// not occupy a slot in the witness vector and is not counted in this layout.
#[derive(Debug, Clone, Copy)]
pub struct ShowWitnessLayout {
    pub expression_result_index: usize,
    pub device_key_x_index: usize,
    pub device_key_y_index: usize,
    pub claim_values_start: usize,
    pub claim_values_len: usize,
}

impl ShowWitnessLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }
}

/// Calculate Show circuit witness layout for the given `n_claims` template parameter.
///
/// `n_claims` must equal the JWT circuit's `maxMatches - 2` (see [`CircuitSize::n_claims`]).
pub fn calculate_show_witness_indices(n_claims: usize) -> ShowWitnessLayout {
    ShowWitnessLayout {
        expression_result_index: 1,
        device_key_x_index: 2,
        device_key_y_index: 3,
        claim_values_start: 7,
        claim_values_len: n_claims,
    }
}

/// Layout of the MDOC circuit's public outputs within the witness vector.
///
/// MDOC circuit outputs (in order, derived from `circom/circuits/mdoc.circom`):
/// 1. `validUntilDate`
/// 2. `normalizedClaimValues[maxClaims]`
/// 3. `deviceKeyX`
/// 4. `deviceKeyY`
#[derive(Debug, Clone, Copy)]
pub struct MdocOutputLayout {
    pub valid_until_index: usize,
    pub claim_values_start: usize,
    pub claim_values_len: usize,
    pub device_key_x_index: usize,
    pub device_key_y_index: usize,
}

impl MdocOutputLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }

    /// Total number of public outputs (`validUntilDate + claims + deviceKeyX + deviceKeyY`).
    pub fn num_public(&self) -> usize {
        1 + self.claim_values_len + 2
    }
}

/// Calculate MDOC circuit witness layout from `maxClaims`.
pub fn calculate_mdoc_output_indices(max_claims: usize) -> MdocOutputLayout {
    let valid_until_index = 1;
    let claim_values_start = valid_until_index + 1;
    let device_key_x_index = claim_values_start + max_claims;
    let device_key_y_index = device_key_x_index + 1;

    MdocOutputLayout {
        valid_until_index,
        claim_values_start,
        claim_values_len: max_claims,
        device_key_x_index,
        device_key_y_index,
    }
}

/// Parse MDOC circuit inputs from JSON.
///
/// Matches `MDOC(maxCredLen, maxPreimageLen, maxClaims, maxIdentifierLen, maxValueLen, maxDeviceKeyPrefixLen)`
/// in `circom/circuits/mdoc.circom`.
pub fn parse_mdoc_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        ("pubKeyX", FieldParser::BigIntScalar),
        ("pubKeyY", FieldParser::BigIntScalar),
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("messageLength", FieldParser::BigIntScalar),
        ("validUntilPrefixPos", FieldParser::BigIntScalar),
        ("deviceKeyPrefixLen", FieldParser::BigIntScalar),
        ("deviceKeyPrefixPos", FieldParser::BigIntScalar),
        ("yPrefixLen", FieldParser::BigIntScalar),
        ("message", FieldParser::BigIntArray),
        ("deviceKeyPrefix", FieldParser::BigIntArray),
        ("preimageLengths", FieldParser::BigIntArray),
        ("identifierLengths", FieldParser::BigIntArray),
        ("identifierPositions", FieldParser::BigIntArray),
        ("digestIds", FieldParser::BigIntArray),
        ("encodedDigestPositions", FieldParser::BigIntArray),
        ("elementValueLabelPositions", FieldParser::BigIntArray),
        ("valueStarts", FieldParser::BigIntArray),
        ("valueEnds", FieldParser::BigIntArray),
        ("valueTypes", FieldParser::BigIntArray),
        ("claimFlags", FieldParser::BigIntArray),
        ("digestInputsPaddedLen", FieldParser::BigIntArray),
        ("preimages", FieldParser::BigInt2DArray),
        ("identifierCbor", FieldParser::BigInt2DArray),
        ("digestInputsPadded", FieldParser::BigInt2DArray),
    ];

    parse_inputs(json_value, field_defs)
}

/// Convert HashMap<String, Vec<BigInt>> to JSON string for witnesscalc_adapter (MDOC).
/// Reconstructs the three MDOC 2D arrays using their declared dimensions.
pub fn mdoc_hashmap_to_json_string(
    inputs: &HashMap<String, Vec<BigInt>>,
    max_claims: usize,
    max_preimage_len: usize,
    max_identifier_len: usize,
    max_value_len: usize,
) -> Result<String, SynthesisError> {
    use serde_json::json;

    let mut json_map = serde_json::Map::new();

    let two_d_fields: HashMap<&str, (usize, usize)> = [
        ("preimages", (max_claims, max_preimage_len)),
        ("identifierCbor", (max_claims, max_identifier_len)),
        ("digestInputsPadded", (max_claims, max_value_len)),
    ]
    .iter()
    .cloned()
    .collect();

    for (key, values) in inputs.iter() {
        if let Some(&(rows, cols)) = two_d_fields.get(key.as_str()) {
            let mut array_2d = Vec::with_capacity(rows);
            for i in 0..rows {
                let start = i * cols;
                let end = start + cols;
                if end <= values.len() {
                    let row: Vec<String> = values[start..end]
                        .iter()
                        .map(|bigint| bigint.to_string())
                        .collect();
                    array_2d.push(json!(row));
                } else {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            json_map.insert(key.clone(), json!(array_2d));
        } else {
            let string_array: Vec<String> =
                values.iter().map(|bigint| bigint.to_string()).collect();
            json_map.insert(key.clone(), json!(string_array));
        }
    }

    serde_json::to_string(&json_map).map_err(|_| SynthesisError::Unsatisfiable)
}

#[cfg(test)]
mod show_witness_indices_tests {
    use super::*;

    /// Catches witness-layout drift between show.sym and calculate_show_witness_indices,
    /// which would silently break the Prepare<->Show commitment binding.
    #[test]
    fn witness_indices_match_show_sym() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let sym_path = std::path::Path::new(manifest_dir)
            .join("../circom/build/show/show.sym");
        if !sym_path.exists() {
            eprintln!(
                "show.sym not found at {}; skipping (run `bash ../circom/scripts/compile.sh show`).",
                sym_path.display()
            );
            return;
        }

        let contents = std::fs::read_to_string(&sym_path).expect("read show.sym");
        let idx_of = |name: &str| -> Option<usize> {
            for line in contents.lines() {
                let mut parts = line.split(',');
                let _ = parts.next();
                let witness_idx = parts.next()?;
                let _ = parts.next();
                let signal = parts.next()?.trim();
                if signal == name {
                    let parsed: i64 = witness_idx.parse().ok()?;
                    if parsed < 0 {
                        return None;
                    }
                    return Some(parsed as usize);
                }
            }
            None
        };

        let expression_result = idx_of("main.expressionResult")
            .expect("main.expressionResult missing from show.sym");
        let device_key_x =
            idx_of("main.deviceKeyX").expect("main.deviceKeyX missing from show.sym");
        let device_key_y =
            idx_of("main.deviceKeyY").expect("main.deviceKeyY missing from show.sym");
        let claim0 =
            idx_of("main.claimValues[0]").expect("main.claimValues[0] missing from show.sym");

        let layout = calculate_show_witness_indices(2);
        assert_eq!(
            layout.expression_result_index, expression_result,
            "expressionResult witness index mismatch with show.sym"
        );
        assert_eq!(
            layout.device_key_x_index, device_key_x,
            "deviceKeyX witness index mismatch with show.sym (recompile show and update utils.rs)"
        );
        assert_eq!(
            layout.device_key_y_index, device_key_y,
            "deviceKeyY witness index mismatch with show.sym (recompile show and update utils.rs)"
        );
        assert_eq!(
            layout.claim_values_start, claim0,
            "claimValues[0] witness index mismatch with show.sym"
        );
    }
}
