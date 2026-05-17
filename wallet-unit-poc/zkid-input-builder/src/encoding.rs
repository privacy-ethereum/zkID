//! Wire-encoding helpers for Circom circuit inputs.

use crate::types::SmtCircuitInputs;
use num_bigint::BigUint;

/// SMT JSON fields: either cloned from a fetched proof or deterministic defaults.
pub(crate) fn smt_fields_from_option(
    smt_inputs: Option<&SmtCircuitInputs>,
    serial_decimal: String,
    sibling_depth: usize,
) -> (
    String,
    String,
    Vec<String>,
    String,
    String,
    String,
) {
    match smt_inputs {
        Some(smt) => (
            smt.smt_root.clone(),
            smt.serial_number.clone(),
            smt.smt_siblings.clone(),
            smt.smt_old_key.clone(),
            smt.smt_old_value.clone(),
            smt.smt_is_old0.clone(),
        ),
        None => {
            let zeros = vec!["0".to_string(); sibling_depth];
            (
                "0".to_string(),
                serial_decimal,
                zeros,
                "0".to_string(),
                "0".to_string(),
                "1".to_string(),
            )
        }
    }
}

pub(crate) fn bigint_to_chunks(n: &BigUint, count: usize, chunk_bits: usize) -> Vec<String> {
    let mask = (BigUint::from(1u64) << chunk_bits) - BigUint::from(1u64);
    let mut chunks = Vec::new();
    let mut val = n.clone();
    for _ in 0..count {
        let chunk = &val & &mask;
        chunks.push(chunk.to_string());
        val >>= chunk_bits;
    }
    chunks
}

pub(crate) fn sha256_pad(msg: &[u8], max_len: usize) -> Vec<u8> {
    let bit_len = (msg.len() as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    padded.resize(max_len, 0);
    padded
}

pub(crate) fn sha256_padded_length(original_len: usize) -> usize {
    let mut len = original_len + 1;
    while len % 64 != 56 {
        len += 1;
    }
    len + 8
}
